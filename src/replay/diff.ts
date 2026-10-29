/**
 * Comparing two responses, and deciding whether the difference means anything.
 *
 * This is the primitive underneath almost every manual test. Did changing the
 * id change the answer? Did removing the cookie change the answer? Did the
 * payload change the answer? A diff that only says "the bytes differ" is
 * useless on a real application, because real applications put a CSRF token,
 * a timestamp and a request id in every response -- so every response differs
 * from every other one, and the signal is buried.
 *
 * So this does two things. It reports the structural differences, and it
 * computes a similarity that ignores the parts that always change. The second
 * is what makes an automated verdict possible.
 */

import { type HeaderList, getAll } from '../core/headers.js';
import type { HttpResponse } from '../core/message.js';
import { bodyText } from '../core/encoding.js';

export interface HeaderDiff {
  readonly name: string;
  readonly kind: 'added' | 'removed' | 'changed';
  readonly before?: readonly string[];
  readonly after?: readonly string[];
}

export interface ResponseDiff {
  readonly statusChanged: boolean;
  readonly statusBefore: number;
  readonly statusAfter: number;
  readonly headers: readonly HeaderDiff[];
  readonly lengthBefore: number;
  readonly lengthAfter: number;
  /** 1 means identical once volatile content is ignored, 0 nothing in common. */
  readonly similarity: number;
  /** Lines present only in the second response, capped. */
  readonly addedLines: readonly string[];
  /** Lines present only in the first response, capped. */
  readonly removedLines: readonly string[];
  readonly elapsedBefore: number;
  readonly elapsedAfter: number;
  /** A one-line summary for a terminal. */
  readonly summary: string;
}

/**
 * Headers that differ on every response of a healthy application and carry no
 * information about the request. Excluded from the diff so the diff is
 * readable; a check that cares about one of these asks for it directly.
 */
const VOLATILE_HEADERS = [
  'date',
  'age',
  'expires',
  'last-modified',
  'etag',
  'x-request-id',
  'x-correlation-id',
  'x-trace-id',
  'x-amzn-requestid',
  'x-amzn-trace-id',
  'cf-ray',
  'x-runtime',
  'x-response-time',
  'server-timing',
  'report-to',
  'nel',
  'keep-alive',
  'content-length',
];

/**
 * Patterns whose matches are blanked before comparing bodies.
 *
 * Every one of these is something an application legitimately regenerates per
 * response, and leaving them in means two identical pages score as different.
 * They are blanked rather than deleted so that a shifted offset does not
 * cascade through the rest of the comparison.
 */
const VOLATILE_PATTERNS: readonly RegExp[] = [
  // CSRF and anti-forgery tokens in hidden inputs or meta tags.
  /(name=["'](?:_?csrf[_-]?token|authenticity_token|__RequestVerificationToken|_token)["']\s+(?:[^>]*?)value=["'])[^"']*/gi,
  /(<meta[^>]+name=["']csrf-token["'][^>]+content=["'])[^"']*/gi,
  // JSON-embedded tokens and ids.
  /("(?:csrf|csrfToken|_token|requestId|request_id|traceId|nonce|sessionId)"\s*:\s*")[^"]*/gi,
  // CSP nonces.
  /(nonce=["'])[^"']*/gi,
  // ISO timestamps and epoch millis.
  /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?/g,
  /\b1[6-9]\d{11}\b/g,
  // UUIDs.
  /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
  // Cache-busting query strings on assets.
  /(\.(?:js|css|png|jpg|svg|woff2?)\?)[A-Za-z0-9_=.&-]+/gi,
];

export function normaliseVolatile(text: string): string {
  let out = text;
  for (const re of VOLATILE_PATTERNS) {
    out = out.replace(new RegExp(re.source, re.flags), (whole, prefix?: string) =>
      prefix === undefined ? '\u0000'.repeat(Math.min(whole.length, 8)) : prefix,
    );
  }
  return out;
}

function headerSnapshot(headers: HeaderList): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const [name] of headers) {
    const lower = name.toLowerCase();
    if (VOLATILE_HEADERS.includes(lower)) continue;
    if (!out.has(lower)) out.set(lower, getAll(headers, name));
  }
  return out;
}

export function diffHeaders(before: HeaderList, after: HeaderList): HeaderDiff[] {
  const a = headerSnapshot(before);
  const b = headerSnapshot(after);
  const names = [...new Set([...a.keys(), ...b.keys()])].sort();
  const out: HeaderDiff[] = [];

  for (const name of names) {
    const va = a.get(name);
    const vb = b.get(name);
    if (va === undefined && vb !== undefined) {
      out.push({ name, kind: 'added', after: vb });
    } else if (va !== undefined && vb === undefined) {
      out.push({ name, kind: 'removed', before: va });
    } else if (va !== undefined && vb !== undefined && va.join('\u0000') !== vb.join('\u0000')) {
      out.push({ name, kind: 'changed', before: va, after: vb });
    }
  }
  return out;
}

/**
 * Similarity, by Jaccard index over multisets of shingles.
 *
 * Not a character-level edit distance: those are quadratic, and on a 500KB
 * single-page-app response that is seconds per comparison, which rules out
 * using it inside a fuzzing loop. Jaccard over shingles is linear.
 *
 * Which shingle depends on the shape of the input, and getting this wrong is
 * what makes naive diffing useless. Lines are the right unit for a document:
 * one changed row in a table of four hundred should score near 1. Lines are
 * the *wrong* unit for a short response, because `record 1 ok` and
 * `record 2 ok` share no line at all and would score 0 -- so anything short
 * falls back to character trigrams, where they score about 0.6, which is the
 * answer a human would give.
 */
const LINE_THRESHOLD = 8;

export function similarity(a: string, b: string): number {
  if (a === b) return 1;
  const la = splitLines(a);
  const lb = splitLines(b);
  if (la.length === 0 && lb.length === 0) return 1;

  if (la.length >= LINE_THRESHOLD && lb.length >= LINE_THRESHOLD) {
    return jaccard(la, lb);
  }
  return jaccard(trigrams(a), trigrams(b));
}

function trigrams(text: string): string[] {
  const squashed = text.replace(/\s+/g, ' ').trim();
  if (squashed.length <= 3) return squashed.length === 0 ? [] : [squashed];
  const out: string[] = [];
  for (let i = 0; i + 3 <= squashed.length; i += 1) out.push(squashed.slice(i, i + 3));
  return out;
}

/** Jaccard index over multisets: shared elements over the union's size. */
function jaccard(a: readonly string[], b: readonly string[]): number {
  if (a.length === 0 && b.length === 0) return 1;
  const counts = new Map<string, number>();
  for (const item of a) counts.set(item, (counts.get(item) ?? 0) + 1);
  let shared = 0;
  for (const item of b) {
    const n = counts.get(item);
    if (n !== undefined && n > 0) {
      counts.set(item, n - 1);
      shared += 1;
    }
  }
  const union = a.length + b.length - shared;
  return union === 0 ? 1 : shared / union;
}

function splitLines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

export interface DiffOptions {
  /** Maximum added/removed lines to report. */
  readonly maxLines?: number;
  /** Compare raw bytes instead of ignoring volatile content. */
  readonly exact?: boolean;
}

export function diffResponses(
  before: HttpResponse,
  after: HttpResponse,
  options: DiffOptions = {},
): ResponseDiff {
  const maxLines = options.maxLines ?? 20;
  const rawA = bodyText(before.headers, before.body);
  const rawB = bodyText(after.headers, after.body);
  const a = options.exact === true ? rawA : normaliseVolatile(rawA);
  const b = options.exact === true ? rawB : normaliseVolatile(rawB);

  const headers = diffHeaders(before.headers, after.headers);
  const sim = similarity(a, b);

  const setA = new Set(splitLines(a));
  const setB = new Set(splitLines(b));
  const addedLines = [...setB].filter((l) => !setA.has(l)).slice(0, maxLines);
  const removedLines = [...setA].filter((l) => !setB.has(l)).slice(0, maxLines);

  const statusChanged = before.status !== after.status;
  const parts: string[] = [];
  if (statusChanged) parts.push(`status ${before.status} -> ${after.status}`);
  const delta = after.body.length - before.body.length;
  if (delta !== 0) parts.push(`${delta > 0 ? '+' : ''}${delta} bytes`);
  if (headers.length > 0) parts.push(`${headers.length} header${headers.length === 1 ? '' : 's'}`);
  if (sim < 1) parts.push(`similarity ${sim.toFixed(3)}`);
  if (parts.length === 0) parts.push('no material difference');

  return {
    statusChanged,
    statusBefore: before.status,
    statusAfter: after.status,
    headers,
    lengthBefore: before.body.length,
    lengthAfter: after.body.length,
    similarity: sim,
    addedLines,
    removedLines,
    elapsedBefore: before.elapsedMs,
    elapsedAfter: after.elapsedMs,
    summary: parts.join(', '),
  };
}

/**
 * Is a difference worth a human looking at it?
 *
 * The thresholds are deliberately not tunable from the command line. A knob
 * here would be turned until the output was quiet, and the point of the
 * function is to be the same judgement every time so that two runs are
 * comparable.
 *
 * Similarity is only consulted on responses large enough for it to mean
 * something. Below that, almost any change in a short body scores poorly --
 * `record 1 ok` against `record 2 ok` is a 0.6 -- and treating that as a
 * finding would mark every row of an enumeration as interesting, which is
 * the same as marking none of them.
 */
const SIMILARITY_FLOOR = 512;

export function isMaterial(diff: ResponseDiff): boolean {
  if (diff.statusChanged) return true;
  if (diff.headers.some((h) => SECURITY_RELEVANT.includes(h.name))) return true;

  const biggest = Math.max(diff.lengthBefore, diff.lengthAfter);
  if (biggest >= SIMILARITY_FLOOR && diff.similarity < 0.95) return true;

  // A size change relative to the baseline, which is how a list that gained
  // rows -- the signal in an authorisation test -- shows up.
  const delta = Math.abs(diff.lengthAfter - diff.lengthBefore);
  return delta > Math.max(SIMILARITY_FLOOR, diff.lengthBefore * 0.25);
}

const SECURITY_RELEVANT = [
  'set-cookie',
  'location',
  'www-authenticate',
  'access-control-allow-origin',
  'access-control-allow-credentials',
  'content-security-policy',
  'x-frame-options',
];

/**
 * Where a value appears in a response, which is what decides whether a
 * reflection is exploitable and in what context.
 */
export interface Reflection {
  readonly where: 'body' | 'header';
  readonly headerName?: string;
  /** Byte offset in the decoded body. */
  readonly offset?: number;
  /** The surrounding characters, for judging the escaping context. */
  readonly context: string;
  /** Did the value survive unescaped? */
  readonly verbatim: boolean;
}

/**
 * Find a value reflected in a response.
 *
 * Reports both the verbatim appearance and HTML-escaped appearances, because
 * "reflected but escaped" is the single most common false positive in
 * cross-site scripting detection and the difference has to be visible rather
 * than inferred.
 */
export function findReflections(
  response: HttpResponse,
  value: string,
  limit = 10,
): Reflection[] {
  if (value.length < 3) return [];
  const out: Reflection[] = [];

  for (const [name, headerValue] of response.headers) {
    if (headerValue.includes(value)) {
      out.push({
        where: 'header',
        headerName: name,
        context: headerValue.slice(0, 200),
        verbatim: true,
      });
      if (out.length >= limit) return out;
    }
  }

  const text = bodyText(response.headers, response.body);
  const escaped = htmlEscape(value);

  for (const [needle, verbatim] of [
    [value, true],
    ...(escaped === value ? [] : ([[escaped, false]] as const)),
  ] as readonly (readonly [string, boolean])[]) {
    let at = text.indexOf(needle);
    while (at >= 0 && out.length < limit) {
      out.push({
        where: 'body',
        offset: at,
        context: text.slice(Math.max(0, at - 60), at + needle.length + 60),
        verbatim,
      });
      at = text.indexOf(needle, at + needle.length);
    }
  }

  return out;
}

function htmlEscape(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * The HTML context a reflection landed in.
 *
 * Whether a reflection is exploitable is a question about context, not about
 * whether a character survived: `<` inside an attribute value is harmless and
 * a bare `"` there is not. This is a heuristic read of the surrounding text,
 * reported as such.
 */
export type ReflectionContext =
  | 'html-text'
  | 'attribute-double'
  | 'attribute-single'
  | 'attribute-unquoted'
  | 'script'
  | 'style'
  | 'comment'
  | 'url'
  | 'unknown';

/** Attributes whose value is fetched or navigated to, so a scheme matters. */
const URL_ATTRIBUTES = [
  'href',
  'src',
  'srcset',
  'action',
  'formaction',
  'data',
  'poster',
  'background',
  'cite',
  'ping',
  'profile',
  'longdesc',
  'usemap',
  'codebase',
];

export function classifyContext(context: string, value: string): ReflectionContext {
  const at = context.indexOf(value);
  if (at < 0) return 'unknown';
  const before = context.slice(0, at);

  const lastOpenComment = before.lastIndexOf('<!--');
  if (lastOpenComment >= 0 && before.indexOf('-->', lastOpenComment) < 0) return 'comment';

  const lastScript = before.toLowerCase().lastIndexOf('<script');
  if (lastScript >= 0 && before.toLowerCase().indexOf('</script', lastScript) < 0) return 'script';

  const lastStyle = before.toLowerCase().lastIndexOf('<style');
  if (lastStyle >= 0 && before.toLowerCase().indexOf('</style', lastStyle) < 0) return 'style';

  const lastTagOpen = before.lastIndexOf('<');
  const lastTagClose = before.lastIndexOf('>');
  if (lastTagOpen > lastTagClose) {
    const inTag = before.slice(lastTagOpen);

    // Which attribute are we inside? A URL-bearing one is reported as `url`
    // even though it is also a quoted attribute, because the quoting decides
    // whether you can break out and the attribute decides whether you need
    // to -- a `javascript:` scheme in an href needs no quote at all.
    const attribute = /([A-Za-z-]+)\s*=\s*(?:"[^"]*|'[^']*|[^\s"'>]*)$/.exec(inTag)?.[1];
    if (attribute !== undefined && URL_ATTRIBUTES.includes(attribute.toLowerCase())) return 'url';

    const doubles = (inTag.match(/"/g) ?? []).length;
    const singles = (inTag.match(/'/g) ?? []).length;
    if (doubles % 2 === 1) return 'attribute-double';
    if (singles % 2 === 1) return 'attribute-single';
    return 'attribute-unquoted';
  }

  if (/\b(?:href|src|action)\s*=\s*["']?[^"'>]*$/i.test(before)) return 'url';
  return 'html-text';
}
