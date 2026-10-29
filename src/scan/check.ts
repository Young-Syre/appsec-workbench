/**
 * What a check is, and the contract that keeps the output usable.
 *
 * Four rules, each of which exists because breaking it is how scanners get
 * their reputation.
 *
 * **A check reports evidence or it does not report.** Every finding names the
 * exchange it came from. No exchange, no finding. That rules out the entire
 * genre of output that says a header is missing without saying where.
 *
 * **A check states its own confidence.** `certain` means the response proves
 * it; `firm` means the response is strong evidence and a human should still
 * look; `tentative` means this is a lead. Writing that down per finding is
 * what lets a report be filtered honestly instead of uniformly distrusted.
 *
 * **Severity accounts for reachability.** A missing `X-Frame-Options` on an
 * API endpoint that returns JSON is not a medium, it is noise. The checks
 * here ask what the response actually is before grading it.
 *
 * **A passive check sends nothing.** It is a pure function of an exchange,
 * which is why it can run over a capture after the fact and why running it
 * costs the target nothing.
 */

import type { Exchange } from '../core/message.js';
import type { Confidence, Severity } from '../core/store.js';

export interface FindingDraft {
  readonly check: string;
  readonly title: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly detail: string;
  readonly remediation: string;
  /** Where it was found; defaults to the exchange's request URL. */
  readonly url?: string;
  /** Extra exchange ids beyond the one being scanned. */
  readonly alsoEvidence?: readonly string[];
}

export interface PassiveContext {
  /** Every exchange in the project, for checks that need corroboration. */
  readonly all?: readonly Exchange[];
  /** Hosts the operator declared in scope, for reachability judgements. */
  readonly inScopeHosts?: readonly string[];
}

export interface PassiveCheck {
  readonly id: string;
  readonly title: string;
  /** Why this matters, in a sentence a report can quote. */
  readonly description: string;
  run(exchange: Exchange, context: PassiveContext): FindingDraft[];
}

/**
 * Does this response look like a document a browser renders?
 *
 * Asked constantly, because almost every browser-protection header is
 * meaningless on a JSON API response and reporting it there is the single
 * biggest source of scanner noise.
 */
export function isHtmlDocument(exchange: Exchange): boolean {
  const response = exchange.response;
  if (response === undefined) return false;
  const ct = response.headers.find(([k]) => k.toLowerCase() === 'content-type')?.[1] ?? '';
  if (!/^text\/html/i.test(ct.trim())) return false;
  // A 204, a redirect or an empty body renders nothing.
  if (response.status === 204 || (response.status >= 300 && response.status < 400)) return false;
  return response.body.length > 0;
}

/** Was this request authenticated? The basis for every cache finding. */
export function isAuthenticated(exchange: Exchange): boolean {
  return exchange.request.headers.some(([k]) => {
    const lower = k.toLowerCase();
    return lower === 'authorization' || lower === 'cookie' || lower === 'x-api-key';
  });
}

/**
 * Cookie names that look like they carry a session.
 *
 * A heuristic, used to grade rather than to decide: a missing `HttpOnly` on
 * something called `session` is a real finding and the same on `theme` is
 * not, and a check that cannot tell them apart reports both at the same
 * severity and is ignored for it.
 */
const SESSION_NAME = /sess|sid$|^sid|auth|token|jwt|login|remember|csrf|xsrf|identity|account/i;

export function looksLikeSessionCookie(name: string): boolean {
  return SESSION_NAME.test(name);
}

export interface ParsedSetCookie {
  readonly name: string;
  readonly value: string;
  readonly attributes: ReadonlyMap<string, string>;
  readonly raw: string;
}

export function parseSetCookie(raw: string): ParsedSetCookie | undefined {
  const semi = raw.indexOf(';');
  const pair = semi < 0 ? raw : raw.slice(0, semi);
  const eq = pair.indexOf('=');
  if (eq < 0) return undefined;
  const attributes = new Map<string, string>();
  if (semi >= 0) {
    for (const part of raw.slice(semi + 1).split(';')) {
      const trimmed = part.trim();
      if (trimmed.length === 0) continue;
      const aeq = trimmed.indexOf('=');
      if (aeq < 0) attributes.set(trimmed.toLowerCase(), '');
      else attributes.set(trimmed.slice(0, aeq).toLowerCase(), trimmed.slice(aeq + 1));
    }
  }
  return {
    name: pair.slice(0, eq).trim(),
    value: pair.slice(eq + 1),
    attributes,
    raw,
  };
}

/** Run a set of checks over one exchange, collecting drafts. */
export function runPassive(
  checks: readonly PassiveCheck[],
  exchange: Exchange,
  context: PassiveContext = {},
): FindingDraft[] {
  const out: FindingDraft[] = [];
  for (const check of checks) {
    try {
      out.push(...check.run(exchange, context));
    } catch (err) {
      // A check that throws must not take the scan with it, and must not
      // disappear silently either: the failure is reported as a finding
      // against the tool rather than against the target.
      out.push({
        check: 'AWB-INTERNAL',
        title: `the ${check.id} check failed on this exchange`,
        severity: 'info',
        confidence: 'certain',
        detail:
          `${check.id} threw while examining this exchange: ${(err as Error).message}. ` +
          'This is a defect in appsec-workbench, not a finding about the target.',
        remediation: 'Report it at https://github.com/Young-Syre/appsec-workbench/issues',
      });
    }
  }
  return out;
}
