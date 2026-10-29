/**
 * Reporting.
 *
 * Four formats, because four different things read them: a terminal, a script,
 * a human writing up an engagement, and a code-scanning dashboard. The
 * content is the same and the shape is not, and the one invariant across all
 * of them is that redaction is applied on the way out -- a report is the
 * artefact most likely to be pasted into a ticket.
 *
 * SARIF gets particular care because it is the format most often emitted
 * wrongly. A file that omits a rule a result refers to, or a result with no
 * physical location, satisfies the schema and renders as an empty panel in
 * every viewer. Both are asserted in the test suite.
 */

import { PASSIVE_CHECKS } from '../scan/passive/index.js';
import { ACTIVE_CHECKS } from '../scan/active/checks.js';
import type { Exchange } from '../core/message.js';
import { serialiseRequest, serialiseResponse } from '../core/message.js';
import { redactHeaders, redactText, redactUrl, observedSecrets } from '../core/redact.js';
import { SEVERITY_ORDER, type Finding, type Severity, severityRank } from '../core/store.js';

export interface ReportOptions {
  readonly showSecrets?: boolean;
  /** Lowest severity to include. */
  readonly minSeverity?: Severity;
  /** Exchanges, so a report can quote evidence. */
  readonly exchanges?: ReadonlyMap<string, Exchange>;
  readonly toolVersion?: string;
  readonly projectName?: string;
  /** The authorisation the active checks ran under, cited in the report. */
  readonly authorisation?: string;
}

function filtered(findings: readonly Finding[], options: ReportOptions): Finding[] {
  const floor = options.minSeverity === undefined ? 'info' : options.minSeverity;
  return findings
    .filter((f) => severityRank(f.severity) <= severityRank(floor))
    .sort(
      (a, b) =>
        severityRank(a.severity) - severityRank(b.severity) ||
        a.check.localeCompare(b.check) ||
        a.url.localeCompare(b.url),
    );
}

function scrubFinding(finding: Finding, options: ReportOptions): Finding {
  if (options.showSecrets === true) return finding;
  // The literal values observed in the finding's own evidence, as well as the
  // credential-name patterns. A check's `detail` and `remediation` quote
  // captured bytes, and a credential does not always arrive with a
  // credential-shaped name in front of it -- which is the whole reason the
  // literal set exists. Scrubbing these two fields by pattern alone left a
  // value that had been seen in the request readable in the report.
  const extraValues = evidenceSecrets(finding, options);
  const scrub = (text: string): string => redactText(text, { extraValues });
  return {
    ...finding,
    url: redactUrl(finding.url, { extraValues }),
    detail: scrub(finding.detail),
    title: scrub(finding.title),
    // `remediation` is built from captured bytes by some checks -- cookies.ts
    // interpolates the cookie's own name -- and the AI prompt builder has
    // always redacted it. Two implementations of the same scrub, agreeing on
    // three fields and differing on the fourth, with no test across the seam.
    remediation: scrub(finding.remediation),
  };
}

/** Every credential value observed in the exchanges a finding cites. */
function evidenceSecrets(finding: Finding, options: ReportOptions): string[] {
  const exchanges = options.exchanges;
  if (exchanges === undefined) return [];
  const out: string[] = [];
  for (const id of finding.evidence) {
    const exchange = exchanges.get(id);
    if (exchange === undefined) continue;
    out.push(...observedSecrets(exchange.request.headers, exchange.request.url));
  }
  return out;
}

export function counts(findings: readonly Finding[]): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) out[f.severity] += 1;
  return out;
}

// ---- text -----------------------------------------------------------------

const BADGE: Record<Severity, string> = {
  critical: 'CRIT',
  high: 'HIGH',
  medium: 'MED ',
  low: 'LOW ',
  info: 'INFO',
};

export function renderText(findings: readonly Finding[], options: ReportOptions = {}): string {
  const list = filtered(findings, options).map((f) => scrubFinding(f, options));
  const lines: string[] = [];

  lines.push(`appsec-workbench${options.toolVersion === undefined ? '' : ` ${options.toolVersion}`}`);
  if (options.projectName !== undefined) lines.push(`  project: ${options.projectName}`);
  if (options.authorisation !== undefined) lines.push(`  authorised: ${options.authorisation}`);
  lines.push('');

  if (list.length === 0) {
    lines.push('  no findings at or above the chosen severity');
    lines.push('');
    return lines.join('\n');
  }

  const tally = counts(list);
  lines.push(
    `  ${list.length} finding${list.length === 1 ? '' : 's'}: ` +
      SEVERITY_ORDER.filter((s) => tally[s] > 0)
        .map((s) => `${tally[s]} ${s}`)
        .join(', '),
  );
  lines.push('');

  for (const finding of list) {
    lines.push(`  ${BADGE[finding.severity]}  ${finding.check}  ${finding.title}`);
    lines.push(`        ${finding.url}`);
    lines.push(
      `        confidence: ${finding.confidence}  evidence: ${summariseEvidence(finding.evidence)}`,
    );
    if (finding.aiAssessment !== undefined) {
      lines.push(
        `        model (${finding.aiAssessment.model}): ${finding.aiAssessment.verdict} -- ` +
          `${wrap(finding.aiAssessment.reasoning, 70, 10).trimStart()}`,
      );
    }
    lines.push('');
    lines.push(wrap(finding.detail, 76, 8));
    lines.push('');
    lines.push(`        fix: ${wrap(finding.remediation, 70, 13).trimStart()}`);
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Evidence ids, shortened for a terminal.
 *
 * A deduplicated finding can pool a dozen exchanges -- every fuzz request that
 * hit the same defect -- and a line of twelve hex ids is unreadable. The JSON
 * and SARIF reports carry the whole list.
 */
function summariseEvidence(evidence: readonly string[], shown = 3): string {
  if (evidence.length <= shown) return evidence.join(', ');
  return `${evidence.slice(0, shown).join(', ')} and ${evidence.length - shown} more`;
}

function wrap(text: string, width: number, indent: number): string {
  const pad = ' '.repeat(indent);
  const out: string[] = [];
  for (const paragraph of text.split('\n')) {
    if (paragraph.trim().length === 0) {
      out.push('');
      continue;
    }
    let line = '';
    for (const word of paragraph.split(/\s+/)) {
      if (line.length > 0 && line.length + 1 + word.length > width) {
        out.push(pad + line);
        line = word;
      } else {
        line = line.length === 0 ? word : `${line} ${word}`;
      }
    }
    if (line.length > 0) out.push(pad + line);
  }
  return out.join('\n');
}

// ---- json -----------------------------------------------------------------

export function renderJson(findings: readonly Finding[], options: ReportOptions = {}): string {
  const list = filtered(findings, options).map((f) => scrubFinding(f, options));
  return (
    JSON.stringify(
      {
        tool: 'appsec-workbench',
        version: options.toolVersion ?? '0.0.0',
        project: options.projectName,
        authorisation: options.authorisation,
        generatedAt: new Date(0).toISOString(),
        counts: counts(list),
        findings: list.map((f) => ({
          id: f.id,
          check: f.check,
          title: f.title,
          severity: f.severity,
          confidence: f.confidence,
          url: f.url,
          detail: f.detail,
          remediation: f.remediation,
          evidence: f.evidence,
          aiAssessment: f.aiAssessment,
        })),
      },
      replacer,
      2,
    ) + '\n'
  );
}

/** Keys sorted, so two runs over the same findings diff cleanly. */
function replacer(_key: string, value: unknown): unknown {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return value;
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    sorted[key] = (value as Record<string, unknown>)[key];
  }
  return sorted;
}

// ---- markdown -------------------------------------------------------------

export function renderMarkdown(findings: readonly Finding[], options: ReportOptions = {}): string {
  const list = filtered(findings, options).map((f) => scrubFinding(f, options));
  const out: string[] = [];

  out.push(`# Findings${options.projectName === undefined ? '' : ` — ${options.projectName}`}`);
  out.push('');
  if (options.authorisation !== undefined) {
    out.push(`Authorised under: ${options.authorisation}`);
    out.push('');
  }

  if (list.length === 0) {
    out.push('No findings at or above the chosen severity.');
    out.push('');
    return out.join('\n');
  }

  const tally = counts(list);
  out.push('| Severity | Count |');
  out.push('| --- | --- |');
  for (const severity of SEVERITY_ORDER) {
    if (tally[severity] > 0) out.push(`| ${severity} | ${tally[severity]} |`);
  }
  out.push('');

  out.push('| Severity | Check | Finding | Where |');
  out.push('| --- | --- | --- | --- |');
  for (const f of list) {
    out.push(
      `| ${f.severity} | ${f.check} | ${escapePipes(f.title)} | ${escapePipes(shortUrl(f.url))} |`,
    );
  }
  out.push('');

  for (const f of list) {
    out.push(`## ${f.check}: ${f.title}`);
    out.push('');
    out.push(`**Severity** ${f.severity} · **Confidence** ${f.confidence}`);
    out.push('');
    out.push(`**Where** \`${f.url}\``);
    out.push('');
    out.push(f.detail);
    out.push('');
    if (f.aiAssessment !== undefined) {
      out.push(
        `**Model assessment** (${f.aiAssessment.model}, not a substitute for verification): ` +
          `${f.aiAssessment.verdict}. ${f.aiAssessment.reasoning}`,
      );
      out.push('');
    }
    out.push(`**Remediation** ${f.remediation}`);
    out.push('');
    out.push(`**Evidence** ${f.evidence.map((id) => `\`${id}\``).join(', ')}`);
    out.push('');

    const quoted = quoteEvidence(f, options);
    if (quoted !== undefined) {
      out.push('<details><summary>The exchange</summary>');
      out.push('');
      out.push('```http');
      out.push(quoted);
      out.push('```');
      out.push('');
      out.push('</details>');
      out.push('');
    }
  }

  return out.join('\n');
}

function quoteEvidence(finding: Finding, options: ReportOptions): string | undefined {
  const map = options.exchanges;
  if (map === undefined) return undefined;
  const first = finding.evidence[0];
  if (first === undefined) return undefined;
  const exchange = map.get(first);
  if (exchange === undefined) return undefined;

  const show = options.showSecrets === true;
  const secrets = show ? [] : observedSecrets(exchange.request.headers, exchange.request.url);
  const request = serialiseRequest({
    ...exchange.request,
    headers: show ? exchange.request.headers : redactHeaders(exchange.request.headers),
  });
  const response =
    exchange.response === undefined
      ? `(no response: ${exchange.error ?? 'unknown'})`
      : serialiseResponse({
          ...exchange.response,
          headers: show ? exchange.response.headers : redactHeaders(exchange.response.headers),
          body: Buffer.from(
            trimBody(
              show
                ? exchange.response.body.toString('utf8')
                : redactText(exchange.response.body.toString('utf8'), { extraValues: secrets }),
            ),
            'utf8',
          ),
        });

  return `${trimBody(show ? request : redactText(request, { extraValues: secrets }))}\n\n${response}`;
}

function trimBody(text: string, limit = 2000): string {
  return text.length <= limit ? text : `${text.slice(0, limit)}\n[... truncated ...]`;
}

function escapePipes(text: string): string {
  return text.replace(/\|/g, '\\|');
}

function shortUrl(raw: string): string {
  try {
    const url = new URL(raw);
    return `${url.pathname}${url.search}` || '/';
  } catch {
    return raw;
  }
}

// ---- sarif ----------------------------------------------------------------

const SARIF_LEVEL: Record<Severity, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'warning',
  info: 'note',
};

/** SARIF's 0..10 scale, so a dashboard can sort by something finer than three levels. */
const SARIF_SCORE: Record<Severity, string> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '3.0',
  info: '1.0',
};

interface RuleDescriptor {
  readonly id: string;
  readonly title: string;
  readonly description: string;
}

function allRules(): Map<string, RuleDescriptor> {
  const out = new Map<string, RuleDescriptor>();
  for (const check of PASSIVE_CHECKS) {
    out.set(check.id, { id: check.id, title: check.title, description: check.description });
  }
  for (const check of ACTIVE_CHECKS) {
    out.set(check.id, { id: check.id, title: check.title, description: check.description });
  }
  return out;
}

/**
 * SARIF 2.1.0.
 *
 * Every rule a result references is declared in `driver.rules`, and every
 * result has a physical location. A viewer given a file missing either one
 * shows nothing and reports no error, which is the worst possible failure
 * mode for a security report.
 */
export function renderSarif(findings: readonly Finding[], options: ReportOptions = {}): string {
  const list = filtered(findings, options).map((f) => scrubFinding(f, options));
  const known = allRules();

  // Only the rules actually referenced, in a stable order.
  const referenced = [...new Set(list.map((f) => f.check))].sort();
  const rules = referenced.map((id) => {
    const rule = known.get(id);
    return {
      id,
      name: id.replace(/[^A-Za-z0-9]/g, ''),
      shortDescription: { text: rule?.title ?? id },
      fullDescription: { text: rule?.description ?? 'No description is registered for this check.' },
      help: {
        text:
          rule?.description ??
          'This check produced a result but is not in the registry; that is a defect in the tool.',
      },
      properties: { tags: ['security'] },
    };
  });

  const results = list.map((finding) => ({
    ruleId: finding.check,
    ruleIndex: referenced.indexOf(finding.check),
    level: SARIF_LEVEL[finding.severity],
    message: { text: `${finding.title}\n\n${finding.detail}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: locationUri(finding.url) },
          region: { startLine: 1, startColumn: 1 },
        },
      },
    ],
    partialFingerprints: { awbFindingId: finding.id },
    properties: {
      severity: finding.severity,
      confidence: finding.confidence,
      'security-severity': SARIF_SCORE[finding.severity],
      evidence: finding.evidence,
      remediation: finding.remediation,
      ...(finding.aiAssessment === undefined
        ? {}
        : {
            modelVerdict: finding.aiAssessment.verdict,
            modelName: finding.aiAssessment.model,
          }),
    },
  }));

  return (
    JSON.stringify(
      {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: {
                name: 'appsec-workbench',
                version: options.toolVersion ?? '0.0.0',
                informationUri: 'https://github.com/Young-Syre/appsec-workbench',
                rules,
              },
            },
            results,
            ...(options.authorisation === undefined
              ? {}
              : { properties: { authorisation: options.authorisation } }),
          },
        ],
      },
      null,
      2,
    ) + '\n'
  );
}

/**
 * SARIF wants a URI for an artifact, and a web finding has a URL rather than a
 * file. The URL is used as-is where it parses, because that is what a reviewer
 * needs to see, and query strings are kept -- they are frequently the finding.
 */
function locationUri(raw: string): string {
  try {
    return new URL(raw).toString();
  } catch {
    return raw;
  }
}

export type Format = 'text' | 'json' | 'markdown' | 'sarif';

export function render(
  format: Format,
  findings: readonly Finding[],
  options: ReportOptions = {},
): string {
  switch (format) {
    case 'text':
      return renderText(findings, options);
    case 'json':
      return renderJson(findings, options);
    case 'markdown':
      return renderMarkdown(findings, options);
    case 'sarif':
      return renderSarif(findings, options);
    default: {
      const exhaustive: never = format;
      return exhaustive;
    }
  }
}

export function parseFormat(text: string): Format {
  const lower = text.toLowerCase();
  if (lower === 'text' || lower === 'json' || lower === 'markdown' || lower === 'sarif') {
    return lower;
  }
  if (lower === 'md') return 'markdown';
  throw new Error(`unknown format ${JSON.stringify(text)}. Known: text, json, markdown, sarif.`);
}

export function parseSeverity(text: string): Severity {
  const lower = text.toLowerCase();
  if ((SEVERITY_ORDER as readonly string[]).includes(lower)) return lower as Severity;
  throw new Error(
    `unknown severity ${JSON.stringify(text)}. Known: ${SEVERITY_ORDER.join(', ')}.`,
  );
}
