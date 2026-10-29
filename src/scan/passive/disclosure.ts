/**
 * What responses give away: errors, sources, secrets, internals.
 *
 * These are the checks most worth running over a capture you already have,
 * because they cost the target nothing and they find the things that are
 * hardest to find by poking: a stack trace on one unusual code path, a source
 * map left in a production bundle, a key in a JSON response that nobody
 * noticed because the page renders fine without reading it.
 *
 * The secret detection here has an entropy floor for the same reason a
 * credential scanner needs one: the shape of a key matches every example in
 * every piece of documentation, and a check that fires on `sk_test_example`
 * gets switched off within a day.
 */

import { get as getHeader } from '../../core/headers.js';
import { bodyText } from '../../core/encoding.js';
import { type FindingDraft, type PassiveCheck, isHtmlDocument } from '../check.js';

/**
 * Framework error signatures.
 *
 * Each is a string that appears in a stack trace or debug page and does not
 * appear in ordinary content. Matching a generic word like "error" would fire
 * on every validation message on the internet.
 */
const ERROR_SIGNATURES: readonly { readonly pattern: RegExp; readonly stack: string }[] = [
  { pattern: /Traceback \(most recent call last\)/, stack: 'Python' },
  { pattern: /\bat [\w$.]+\s*\([^)]*\.(?:js|ts|mjs|cjs):\d+:\d+\)/, stack: 'Node.js or a browser' },
  { pattern: /java\.(?:lang|util|io)\.[A-Za-z]+(?:Exception|Error)\b/, stack: 'Java' },
  { pattern: /\bat [\w.]+\(.*\.java:\d+\)/, stack: 'Java' },
  { pattern: /Fatal error: Uncaught \w+/, stack: 'PHP' },
  { pattern: /\bStack trace:\s*#0\s/, stack: 'PHP' },
  { pattern: /System\.(?:NullReference|InvalidOperation|Argument\w*)Exception/, stack: '.NET' },
  { pattern: /\bin [A-Za-z]:\\[^\s]+\.(?:cs|vb):line \d+/, stack: '.NET' },
  { pattern: /ActionController::RoutingError|ActiveRecord::\w+/, stack: 'Ruby on Rails' },
  { pattern: /\bfrom [^\s]+\.rb:\d+:in [`']/, stack: 'Ruby' },
  { pattern: /goroutine \d+ \[running\]:/, stack: 'Go' },
  { pattern: /thread '[^']*' panicked at/, stack: 'Rust' },
  { pattern: /Whitelabel Error Page|org\.springframework\.\w+/, stack: 'Spring' },
  { pattern: /Django Version:|DEBUG = True/, stack: 'Django with debug enabled' },
  { pattern: /Werkzeug Debugger|The debugger caught an exception/, stack: 'Flask with the debugger enabled' },
];

/**
 * Database error signatures.
 *
 * These carry more weight than the stack traces above. A database error that
 * reached the client means input influenced a statement and the failure was
 * not handled, which is the precondition injection testing is looking for --
 * so the finding says that rather than only reporting the disclosure.
 */
const DATABASE_SIGNATURES: readonly { readonly pattern: RegExp; readonly engine: string }[] = [
  { pattern: /SQLSTATE\[[0-9A-Z]{5}\]/, engine: 'a PDO-based stack' },
  { pattern: /You have an error in your SQL syntax/, engine: 'MySQL' },
  { pattern: /\bWarning: mysqli?_/, engine: 'MySQL' },
  { pattern: /PG::(?:Syntax|Undefined)\w*Error|PSQLException/, engine: 'PostgreSQL' },
  { pattern: /ORA-\d{5}/, engine: 'Oracle' },
  { pattern: /Microsoft (?:OLE DB|SQL Server)|Unclosed quotation mark/, engine: 'SQL Server' },
  { pattern: /SQLiteException|sqlite3\.\w+Error/, engine: 'SQLite' },
  { pattern: /MongoError|E11000 duplicate key/, engine: 'MongoDB' },
];

export const errorDisclosureCheck: PassiveCheck = {
  id: 'AWB-P030',
  title: 'Response discloses a stack trace or debug page',
  description:
    'A stack trace names files, line numbers, library versions and often the query that ' +
    'failed. It is the cheapest reconnaissance there is, and a debug page is usually also ' +
    'a signal that the environment is not the one that was hardened.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined || response.body.length === 0) return [];
    const text = bodyText(response.headers, response.body);
    const out: FindingDraft[] = [];

    for (const { pattern, stack } of ERROR_SIGNATURES) {
      const match = pattern.exec(text);
      if (match === null) continue;
      out.push({
        check: this.id,
        title: `Stack trace or debug output from ${stack}`,
        severity: /debug/i.test(stack) ? 'medium' : 'low',
        confidence: 'firm',
        detail:
          `The response body contains ${stack} diagnostic output. The matched text was ` +
          `${JSON.stringify(excerpt(text, match.index))}. Responses like this name internal ` +
          'paths, dependency versions and sometimes the failing statement.',
        remediation:
          'Return a generic error to the client and log the detail server-side. Where this is ' +
          'a framework debug mode, confirm which environment is serving this response.',
      });
      break; // One stack-trace finding per response is enough.
    }

    for (const { pattern, engine } of DATABASE_SIGNATURES) {
      const match = pattern.exec(text);
      if (match === null) continue;
      out.push({
        check: this.id,
        title: `Database error from ${engine} reached the response`,
        severity: 'medium',
        confidence: 'firm',
        detail:
          `The response contains a ${engine} error message: ` +
          `${JSON.stringify(excerpt(text, match.index))}. Beyond the disclosure, an error that ` +
          'reaches the client means input influenced a statement and the failure was not ' +
          'handled -- which is the condition injection testing looks for.',
        remediation:
          'Handle database errors without echoing them. Then establish whether the input that ' +
          'caused this is parameterised.',
      });
      break;
    }

    return out;
  },
};

export const sourceMapCheck: PassiveCheck = {
  id: 'AWB-P031',
  title: 'Source map exposed',
  description:
    'A source map hands back the original source of a bundle: the pre-minification ' +
    'names, the comments, and often files that were never meant to ship.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined) return [];
    const ct = (getHeader(response.headers, 'content-type') ?? '').toLowerCase();
    const isScript = /javascript|ecmascript/.test(ct) || /\.m?js(\?|$)/.test(exchange.request.url);

    const out: FindingDraft[] = [];

    // A map served directly.
    if (/\.m?js\.map(\?|$)/.test(exchange.request.url) && response.status === 200) {
      const text = bodyText(response.headers, response.body);
      const sources = /"sources"\s*:\s*\[([^\]]*)\]/.exec(text)?.[1] ?? '';
      const hasContent = /"sourcesContent"\s*:/.test(text);
      out.push({
        check: this.id,
        title: 'Source map is served and returns 200',
        severity: hasContent ? 'low' : 'info',
        confidence: 'certain',
        detail:
          'This URL returns a source map.' +
          (hasContent
            ? ' It includes sourcesContent, so the original source is in the response, not ' +
              'merely named by it.'
            : ' It lists source paths without their contents, which still discloses the ' +
              'project layout.') +
          (sources.length > 0 ? ` First paths: ${sources.slice(0, 200)}` : ''),
        remediation:
          'Stop deploying .map files, or restrict them to authenticated internal access. ' +
          'Removing the sourceMappingURL comment alone does not help: the map is still fetchable.',
      });
      return out;
    }

    if (!isScript || response.status !== 200) return out;
    const text = bodyText(response.headers, response.body);
    const ref = /\/[/*]#\s*sourceMappingURL=(\S+)/.exec(text);
    if (ref !== null) {
      const target = (ref[1] ?? '').replace(/\*\/$/, '');
      out.push({
        check: this.id,
        title: 'Script references a source map',
        severity: 'info',
        confidence: 'certain',
        detail:
          `This bundle ends with a sourceMappingURL pointing at ${target}. Whether that is a ` +
          'disclosure depends on whether the map is actually served -- fetch it and see. ' +
          'A data: URI here means the map is embedded in the bundle itself.',
        remediation:
          'Confirm the map is not reachable in production. If it is, remove it from the deploy ' +
          'rather than only removing the comment.',
      });
    }
    return out;
  },
};

/**
 * Credential-shaped values with an entropy floor.
 *
 * The floor is what makes this usable. Every one of these patterns matches
 * the example in the vendor's own documentation, and a check that reports
 * `AKIAIOSFODNN7EXAMPLE` is a check nobody leaves on.
 */
const SECRET_PATTERNS: readonly {
  readonly name: string;
  readonly pattern: RegExp;
  readonly minEntropy: number;
  readonly severity: 'critical' | 'high' | 'medium';
}[] = [
  { name: 'AWS access key id', pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, minEntropy: 3.0, severity: 'high' },
  {
    name: 'AWS secret access key',
    pattern: /\b(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    minEntropy: 4.4,
    severity: 'critical',
  },
  { name: 'GitHub token', pattern: /\bgh[pousr]_[A-Za-z0-9]{36}\b/g, minEntropy: 3.5, severity: 'critical' },
  { name: 'Slack token', pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g, minEntropy: 3.0, severity: 'high' },
  { name: 'Stripe secret key', pattern: /\bsk_live_[A-Za-z0-9]{16,}/g, minEntropy: 3.5, severity: 'critical' },
  { name: 'Google API key', pattern: /\bAIza[A-Za-z0-9_-]{35}\b/g, minEntropy: 3.5, severity: 'medium' },
  { name: 'private key block', pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, minEntropy: 0, severity: 'critical' },
  { name: 'Twilio API key', pattern: /\bSK[0-9a-fA-F]{32}\b/g, minEntropy: 3.2, severity: 'high' },
  { name: 'SendGrid key', pattern: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g, minEntropy: 3.5, severity: 'high' },
];

/** Shannon entropy in bits per character. */
export function entropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/** Values that are obviously documentation rather than credentials. */
function looksLikePlaceholder(value: string): boolean {
  return /example|sample|placeholder|dummy|replace|your[-_]?|xxxx|0000000000|1234567890|abcdef0123|redacted|changeme|test[-_]?key/i.test(
    value,
  );
}

export const secretInResponseCheck: PassiveCheck = {
  id: 'AWB-P032',
  title: 'Credential-shaped value in a response body',
  description:
    'A key served to the browser is a key the user has. Whether that matters depends ' +
    'entirely on which key it is, so the finding names the kind and leaves the value out.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined || response.body.length === 0) return [];
    // A response the client is meant to read as a credential -- a token
    // endpoint -- is not this finding. Those are identified by the request.
    if (/\/(?:oauth2?|token|login|signin|auth)(?:\/|$)/i.test(exchange.request.url)) return [];

    const text = bodyText(response.headers, response.body);
    const out: FindingDraft[] = [];
    const seen = new Set<string>();

    for (const { name, pattern, minEntropy, severity } of SECRET_PATTERNS) {
      const re = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = re.exec(text)) !== null) {
        const value = match[0];
        if (seen.has(name)) break;
        if (looksLikePlaceholder(value)) continue;
        if (entropy(value) < minEntropy) continue;
        seen.add(name);
        out.push({
          check: this.id,
          title: `${name} in a response body`,
          severity,
          confidence: 'firm',
          detail:
            `A value matching the shape of a ${name} appears in this response at offset ` +
            `${match.index}, with ${entropy(value).toFixed(2)} bits of entropy per character. ` +
            'The value itself is deliberately not reproduced here; read it from the stored ' +
            `exchange with \`awb show ${exchange.id} --unsafe-show-secrets\` if you need to ` +
            'verify it, and treat it as live until you have.',
          remediation:
            'Move the credential server-side. Then rotate it: it has been served to every ' +
            'client that loaded this response, and it is in their caches and your logs.',
        });
        break;
      }
    }

    return out;
  },
};

export const internalDisclosureCheck: PassiveCheck = {
  id: 'AWB-P033',
  title: 'Response discloses internal addresses or hostnames',
  description:
    'Internal hostnames and private addresses map the network behind the application, ' +
    'which is what a server-side request forgery needs in order to be aimed at anything.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined) return [];

    const out: FindingDraft[] = [];
    const haystack = [
      ...response.headers.map(([k, v]) => `${k}: ${v}`),
      bodyText(response.headers, response.body).slice(0, 200_000),
    ].join('\n');

    const privateAddress =
      /\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|169\.254(?:\.\d{1,3}){2})\b/g;
    const found = new Set<string>();
    let match: RegExpExecArray | null;
    while ((match = privateAddress.exec(haystack)) !== null && found.size < 8) {
      found.add(match[0]);
    }

    if (found.size > 0) {
      const linkLocal = [...found].some((a) => a.startsWith('169.254.'));
      out.push({
        check: this.id,
        title: 'Private network address in the response',
        severity: linkLocal ? 'low' : 'info',
        confidence: 'firm',
        detail:
          `The response mentions ${[...found].join(', ')}. That is infrastructure behind the ` +
          'application rather than anything a client needs.' +
          (linkLocal
            ? ' One of them is in 169.254.0.0/16, the link-local range used by cloud instance ' +
              'metadata services, which is the first place a server-side request forgery is pointed.'
            : ''),
        remediation:
          'Keep internal addresses out of responses, including out of error messages and ' +
          'debug headers.',
      });
    }

    const internalHost = /\b[a-z0-9][a-z0-9-]*\.(?:internal|local|localdomain|intranet|corp|lan)\b/gi;
    const hosts = new Set<string>();
    while ((match = internalHost.exec(haystack)) !== null && hosts.size < 8) {
      hosts.add(match[0].toLowerCase());
    }
    if (hosts.size > 0) {
      out.push({
        check: this.id,
        title: 'Internal hostname in the response',
        severity: 'info',
        confidence: 'firm',
        detail: `The response mentions ${[...hosts].join(', ')}, which resolves only inside the network.`,
        remediation: 'Use externally meaningful names in anything a client receives.',
      });
    }

    return out;
  },
};

export const directoryListingCheck: PassiveCheck = {
  id: 'AWB-P034',
  title: 'Directory listing enabled',
  description:
    'A listing enumerates what is on disk, including backups, editor leftovers and ' +
    'files whose names were the only thing keeping them private.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined || response.status !== 200 || !isHtmlDocument(exchange)) return [];
    const text = bodyText(response.headers, response.body);

    const signatures: readonly [RegExp, string][] = [
      [/<title>Index of \//i, 'Apache'],
      [/<h1>Index of \//i, 'Apache'],
      [/Directory Listing For/i, 'Tomcat'],
      [/<title>Directory listing for /i, "Python's http.server"],
      [/\[To Parent Directory\]/i, 'IIS'],
      [/<h1>Index of .*<\/h1><hr><pre><a href="\.\.\/">/i, 'nginx autoindex'],
    ];

    for (const [pattern, server] of signatures) {
      if (!pattern.test(text)) continue;
      const entries = (text.match(/<a href="[^"]+"/g) ?? []).length;
      return [
        {
          check: this.id,
          title: `Directory listing served (${server} style)`,
          severity: 'low',
          confidence: 'certain',
          detail:
            `This URL returns a generated directory index with roughly ${entries} entries. ` +
            'Listings reveal filenames that are otherwise unguessable, which is frequently ' +
            'the whole of the access control on a static path.',
          remediation:
            `Disable autoindex for this path. On ${server} that is one directive; also check ` +
            'whether anything in the listing should have been deployed at all.',
        },
      ];
    }

    return [];
  },
};

function excerpt(text: string, at: number, width = 160): string {
  const start = Math.max(0, at - 20);
  return text.slice(start, start + width).replace(/\s+/g, ' ');
}

export const DISCLOSURE_CHECKS: readonly PassiveCheck[] = [
  errorDisclosureCheck,
  sourceMapCheck,
  secretInResponseCheck,
  internalDisclosureCheck,
  directoryListingCheck,
];
