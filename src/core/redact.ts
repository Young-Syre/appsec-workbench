/**
 * Redaction, applied on the way out of the tool rather than on the way in.
 *
 * A project file is a complete record of an authenticated session: session
 * cookies, bearer tokens, CSRF tokens, whatever the application put in a
 * response body. That record has to stay intact, because replaying it is the
 * entire point. What must never happen is that record reaching a terminal
 * somebody screenshots, a report somebody attaches to a ticket, or a prompt
 * somebody sends to a model.
 *
 * So nothing is redacted in storage and everything is redacted at every
 * boundary. `--unsafe-show-secrets` turns it off, and the name is the
 * documentation.
 */

import { type HeaderList, nameEquals } from './headers.js';

/** Headers whose entire value is a credential. */
const CREDENTIAL_HEADERS = [
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
  'x-access-token',
  'x-csrf-token',
  'x-xsrf-token',
  'x-session-token',
  'api-key',
  'apikey',
];

/** Parameter and field names whose value is a credential wherever it appears. */
const CREDENTIAL_FIELDS = [
  'password',
  'passwd',
  'pwd',
  'secret',
  'token',
  'access_token',
  'refresh_token',
  'id_token',
  'client_secret',
  'api_key',
  'apikey',
  'session',
  'sessionid',
  'sid',
  'auth',
  'authorization',
  'csrf',
  'xsrf',
  'otp',
  'mfa_code',
  'private_key',
  'passphrase',
  'nonce',
];

/**
 * Credential names too generic to match as a suffix.
 *
 * `code` is an OAuth authorization code -- short-lived, single-use, and enough
 * to complete a login -- but suffix-matching it would also redact
 * `status_code`, `error_code` and `country_code`, and a status code is
 * something a report has to be able to show. These are compared whole.
 */
const CREDENTIAL_FIELDS_EXACT = ['code', 'code_verifier', 'device_code', 'user_code'];

/**
 * Value shapes that are credentials wherever they appear, including in a
 * response body that no header named.
 */
const CREDENTIAL_PATTERNS: readonly { readonly name: string; readonly re: RegExp }[] = [
  { name: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  { name: 'aws-access-key-id', re: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g },
  { name: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{36}\b/g },
  { name: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g },
  { name: 'stripe-secret-key', re: /\bsk_(?:live|test)_[A-Za-z0-9]{16,}/g },
  { name: 'google-api-key', re: /\bAIza[A-Za-z0-9_-]{35}\b/g },
  { name: 'private-key-block', re: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----/g },
  { name: 'bearer', re: /\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*/gi },
];

export interface RedactOptions {
  /** Turns redaction off entirely. */
  readonly showSecrets?: boolean;
  /** Extra literal values to scrub wherever they appear. */
  readonly extraValues?: readonly string[];
}

/**
 * Replace a value with a marker that preserves its length class and a short
 * fingerprint, so two redacted values can still be compared for equality.
 *
 * This matters more than it looks: "did the session cookie change after the
 * privilege escalation" is answerable from a redacted transcript only if
 * equal inputs redact to equal outputs.
 */
export function redactValue(value: string): string {
  if (value.length === 0) return value;
  const fp = fingerprint(value);
  return `[redacted:${value.length}b:${fp}]`;
}

function fingerprint(value: string): string {
  // FNV-1a, 32 bit. Not a security property -- it is an equality witness for
  // a human reading a transcript, and it is deliberately short enough that
  // it cannot be inverted into the original.
  let h = 0x811c9dc5;
  for (let i = 0; i < value.length; i += 1) {
    h ^= value.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0').slice(0, 6);
}

export function redactHeaders(headers: HeaderList, options: RedactOptions = {}): HeaderList {
  if (options.showSecrets) return headers;
  return headers.map(([name, value]) => {
    if (CREDENTIAL_HEADERS.some((c) => nameEquals(c, name))) {
      return [name, redactCookieAware(name, value)] as const;
    }
    return [name, redactText(value, options)] as const;
  });
}

/**
 * Cookies get per-cookie treatment: the names stay, the values go.
 *
 * Replacing the whole header with one marker would hide which cookies were
 * present, and which cookies an application sets is frequently the finding.
 */
function redactCookieAware(name: string, value: string): string {
  if (nameEquals(name, 'cookie')) {
    return value
      .split(';')
      .map((part) => {
        const eq = part.indexOf('=');
        if (eq < 0) return part;
        return `${part.slice(0, eq)}=${redactValue(part.slice(eq + 1).trim())}`;
      })
      .join(';');
  }
  if (nameEquals(name, 'set-cookie')) {
    const semi = value.indexOf(';');
    const pair = semi < 0 ? value : value.slice(0, semi);
    const attrs = semi < 0 ? '' : value.slice(semi);
    const eq = pair.indexOf('=');
    if (eq < 0) return redactValue(value);
    // Attributes (HttpOnly, Secure, SameSite) are kept: they are the finding.
    return `${pair.slice(0, eq)}=${redactValue(pair.slice(eq + 1))}${attrs}`;
  }
  return redactValue(value);
}

/** Scrub credential-shaped substrings out of arbitrary text. */
export function redactText(text: string, options: RedactOptions = {}): string {
  if (options.showSecrets) return text;
  let out = text;

  for (const value of options.extraValues ?? []) {
    if (value.length >= 8 && out.includes(value)) {
      out = out.split(value).join(redactValue(value));
    }
  }

  for (const { re } of CREDENTIAL_PATTERNS) {
    out = out.replace(new RegExp(re.source, re.flags), (m) => redactValue(m));
  }

  out = redactMultipart(out);
  out = redactKeyValues(out);

  return out;
}

/**
 * Redact the credential-named parts of a multipart body.
 *
 * multipart/form-data puts the field name in a `Content-Disposition` header
 * and the value on its own line after a blank line, so the key/value pass
 * below cannot reach it: there is no credential name in front of the value.
 * A password typed into an ordinary HTML login form arrives this way, the
 * proxy captures it, and it survived into reports, SARIF and AI prompts.
 *
 * The boundary is read from the body's own opening delimiter, because
 * redactText is given text with no content type. Only a part whose name reads
 * as a credential is touched; everything else, boundaries and part headers
 * included, is left byte for byte.
 */
function redactMultipart(text: string): string {
  const first = /^--(\S+?)\r?\n/.exec(text);
  const boundary = first?.[1];
  if (boundary === undefined || boundary === '') return text;

  const delimiter = `--${boundary}`;
  let changed = false;
  const rewritten = text.split(delimiter).map((chunk) => {
    const lead = /^\r?\n/.exec(chunk)?.[0] ?? '';
    const rest = chunk.slice(lead.length);
    if (rest === '' || rest.startsWith('--')) return chunk;
    const split = /\r?\n\r?\n/.exec(rest);
    if (split === null) return chunk;
    const head = rest.slice(0, split.index);
    const tail = rest.slice(split.index + split[0].length);
    const named = /name=(?:"([^"]*)"|([^;\r\n]+))/i.exec(head);
    const name = named?.[1] ?? named?.[2];
    if (name === undefined || !isCredentialField(name)) return chunk;
    const trailing = /\r?\n$/.exec(tail)?.[0] ?? '';
    const value = tail.slice(0, tail.length - trailing.length);
    if (value === '') return chunk;
    changed = true;
    return `${lead}${head}${split[0]}${redactValue(value)}${trailing}`;
  });
  return changed ? rewritten.join(delimiter) : text;
}

/** `key=value` and `"key": "value"`, for the fields named above. */
const KEY_VALUE_RE = /(["']?)([A-Za-z0-9_.-]{2,40})\1(\s*[:=]\s*)(["']?)([^"'&,}\s][^"'&,}\n]{0,512})\4/g;

/**
 * Redact the credential-named key/value pairs in a run of text.
 *
 * A manual scan rather than `String.prototype.replace`, because when the key
 * is not a credential field the scan has to resume just after that key and
 * not after the value it matched. In `https://host/cb?access_token=...` the
 * pattern matches with key `https` and a value running to the next `&`;
 * declining that match still consumed it, so the `access_token` inside never
 * got a match of its own and every credential carried in a URL survived
 * redaction -- in header values, in bodies, and anywhere else redactText is
 * the function that runs. redactUrl was never the problem; it is simply not
 * what gets called on a header or a body.
 */
function redactKeyValues(text: string): string {
  const re = new RegExp(KEY_VALUE_RE.source, 'g');
  let out = '';
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    const whole = match[0];
    const q1 = match[1] ?? '';
    const key = match[2] ?? '';
    const sep = match[3] ?? '';
    const q2 = match[4] ?? '';
    const value = match[5] ?? '';
    if (!isCredentialField(key)) {
      // Resume immediately after the key. The key is at least two characters,
      // so this always advances and cannot loop.
      re.lastIndex = match.index + q1.length + key.length;
      continue;
    }
    out += text.slice(last, match.index) + `${q1}${key}${q1}${sep}${q2}${redactValue(value)}${q2}`;
    last = match.index + whole.length;
  }
  return out + text.slice(last);
}

function isCredentialField(key: string): boolean {
  const k = key.toLowerCase().replace(/[_-]/g, '');
  if (CREDENTIAL_FIELDS_EXACT.some((f) => k === f.replace(/[_-]/g, ''))) return true;
  return CREDENTIAL_FIELDS.some((f) => {
    const target = f.replace(/[_-]/g, '');
    return k === target || k.endsWith(target);
  });
}

/** Redact a URL's query string, leaving the path intact. */
export function redactUrl(raw: string, options: RedactOptions = {}): string {
  if (options.showSecrets) return raw;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return redactText(raw, options);
  }
  const params = new URLSearchParams(url.search);
  let changed = false;
  for (const key of [...params.keys()]) {
    if (!isCredentialField(key)) continue;
    const values = params.getAll(key);
    params.delete(key);
    for (const v of values) params.append(key, redactValue(v));
    changed = true;
  }
  if (changed) url.search = params.toString();
  // A JWT or key can be in the path as well as the query.
  return redactText(url.toString(), options);
}

/**
 * Every literal credential value observed in a set of headers.
 *
 * Used to scrub those same values out of bodies and context snippets, which
 * is where they leak when a tool only redacts the header it matched.
 */
/** Headers whose value is a URL, so its query and fragment carry credentials. */
const URL_VALUED_HEADERS = ['referer', 'location', 'content-location'];

/** The credential-named query and fragment values of a URL. */
function credentialValuesInUrl(raw: string): string[] {
  const start = raw.search(/[?#]/);
  if (start === -1) return [];
  const out: string[] = [];
  for (const part of raw.slice(start + 1).split(/[&;?#]/)) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    if (!isCredentialField(part.slice(0, eq))) continue;
    const value = part.slice(eq + 1);
    out.push(value);
    try {
      const decoded = decodeURIComponent(value);
      if (decoded !== value) out.push(decoded);
    } catch {
      // A malformed escape is not a reason to drop the raw value.
    }
  }
  return out;
}

export function observedSecrets(headers: HeaderList, url?: string): string[] {
  const out: string[] = [];
  // Credential values carried in a URL, from the request line and from any
  // header whose value is itself a URL. Harvesting only credential *headers*
  // meant a token that arrived as `?access_token=...` was never collected, so
  // a response body echoing it under a name no field list contains -- which is
  // what makes the literal set necessary in the first place -- was rendered
  // verbatim. The fragment counts: an OAuth implicit-flow redirect puts the
  // token after the `#`, and a captured `Location` is where that lands.
  if (url !== undefined) out.push(...credentialValuesInUrl(url));
  for (const [name, value] of headers) {
    if (URL_VALUED_HEADERS.some((c) => nameEquals(c, name))) {
      out.push(...credentialValuesInUrl(value));
    }
    if (!CREDENTIAL_HEADERS.some((c) => nameEquals(c, name))) continue;
    if (nameEquals(name, 'cookie')) {
      for (const part of value.split(';')) {
        const eq = part.indexOf('=');
        if (eq >= 0) out.push(part.slice(eq + 1).trim());
      }
      continue;
    }
    if (nameEquals(name, 'set-cookie')) {
      const semi = value.indexOf(';');
      const pair = semi < 0 ? value : value.slice(0, semi);
      const eq = pair.indexOf('=');
      if (eq >= 0) out.push(pair.slice(eq + 1));
      continue;
    }
    const bearer = /^Bearer\s+(.+)$/i.exec(value);
    out.push(bearer ? (bearer[1] as string) : value);
  }
  return out.filter((v) => v.length >= 8);
}
