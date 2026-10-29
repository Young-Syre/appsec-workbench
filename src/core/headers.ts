/**
 * Header lists, not header maps.
 *
 * Every convenient HTTP client in Node hands you headers as an object. That
 * representation silently destroys three things a security tool depends on:
 *
 *   - **Order.** `Host` arriving after `Content-Length` is a request smuggling
 *     signal. A map has no order to inspect.
 *   - **Duplicates.** Two `Content-Length` headers, or two `Host` headers, is
 *     the entire bug in a desync. A map keeps one of them and discards the
 *     evidence.
 *   - **Exact spelling.** `content-length` and `Content-Length` reach
 *     different middleboxes differently. A map that lowercases has already
 *     normalised away the thing under test.
 *
 * So headers here are an ordered list of pairs, and every lookup is explicit
 * about which of possibly several values it wants.
 */

export type HeaderPair = readonly [name: string, value: string];
export type HeaderList = readonly HeaderPair[];

/** Case-insensitive name comparison, which is what RFC 9110 specifies. */
export function nameEquals(a: string, b: string): boolean {
  return a.length === b.length && a.toLowerCase() === b.toLowerCase();
}

/** Every value for `name`, in wire order. */
export function getAll(headers: HeaderList, name: string): string[] {
  const out: string[] = [];
  for (const [k, v] of headers) if (nameEquals(k, name)) out.push(v);
  return out;
}

/**
 * The first value for `name`, or undefined.
 *
 * "First" rather than "the" value on purpose: when a header is duplicated, the
 * first is usually what the nearest hop acted on, and the caller that cares
 * about the rest should ask for all of them.
 */
export function get(headers: HeaderList, name: string): string | undefined {
  for (const [k, v] of headers) if (nameEquals(k, name)) return v;
  return undefined;
}

export function has(headers: HeaderList, name: string): boolean {
  return get(headers, name) !== undefined;
}

export function count(headers: HeaderList, name: string): number {
  let n = 0;
  for (const [k] of headers) if (nameEquals(k, name)) n += 1;
  return n;
}

/**
 * Replace every occurrence of `name` with one header carrying `value`.
 *
 * The replacement keeps the position of the first occurrence rather than
 * appending, because moving a header changes the request.
 */
export function set(headers: HeaderList, name: string, value: string): HeaderList {
  const out: HeaderPair[] = [];
  let placed = false;
  for (const [k, v] of headers) {
    if (!nameEquals(k, name)) {
      out.push([k, v]);
      continue;
    }
    if (!placed) {
      out.push([name, value]);
      placed = true;
    }
  }
  if (!placed) out.push([name, value]);
  return out;
}

/** Append without touching any existing header of the same name. */
export function add(headers: HeaderList, name: string, value: string): HeaderList {
  return [...headers, [name, value]];
}

export function remove(headers: HeaderList, name: string): HeaderList {
  return headers.filter(([k]) => !nameEquals(k, name));
}

/** Insert at an explicit index, so a test can place a header before `Host`. */
export function insertAt(
  headers: HeaderList,
  index: number,
  name: string,
  value: string,
): HeaderList {
  const out = [...headers];
  const at = Math.max(0, Math.min(index, out.length));
  out.splice(at, 0, [name, value]);
  return out;
}

/**
 * Node's `IncomingMessage.rawHeaders` is a flat array of alternating names and
 * values. It is the only place Node preserves order and duplicates, which is
 * why the proxy reads from it rather than from `.headers`.
 */
export function fromRawHeaders(raw: readonly string[]): HeaderList {
  const out: HeaderPair[] = [];
  for (let i = 0; i + 1 < raw.length; i += 2) {
    out.push([raw[i] as string, raw[i + 1] as string]);
  }
  return out;
}

/** Flatten back to Node's raw form for `writeHead`/`request`. */
export function toRawHeaders(headers: HeaderList): string[] {
  const out: string[] = [];
  for (const [k, v] of headers) out.push(k, v);
  return out;
}

/**
 * Headers that must not be forwarded across a hop, per RFC 9110 section 7.6.1
 * plus the two Node sets itself.
 */
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

export function isHopByHop(name: string): boolean {
  return HOP_BY_HOP.has(name.toLowerCase());
}

/**
 * Serialise exactly as it would go on the wire, with CRLF line endings.
 *
 * Used for display, for the `.http` file format the replay command reads, and
 * for hashing an exchange. It is deliberately lossless: what you read back is
 * what was sent.
 */
export function serialiseHeaders(headers: HeaderList): string {
  return headers.map(([k, v]) => `${k}: ${v}`).join('\r\n');
}

/** Anomalies worth surfacing before anything else looks at the message. */
export interface HeaderAnomaly {
  readonly kind:
    | 'duplicate-singleton'
    | 'conflicting-length'
    | 'length-and-chunked'
    | 'whitespace-in-name'
    | 'obs-fold'
    | 'empty-name';
  readonly header: string;
  readonly detail: string;
}

/**
 * Structural problems in a header list.
 *
 * These are not "findings" about the application -- they are facts about the
 * message, and they are the preconditions for request smuggling. A tool that
 * normalises them away before you look cannot tell you they were there.
 */
export function headerAnomalies(headers: HeaderList): HeaderAnomaly[] {
  const out: HeaderAnomaly[] = [];
  const singletons = ['host', 'content-length', 'authorization', 'content-type'];

  for (const name of singletons) {
    const values = getAll(headers, name);
    if (values.length > 1) {
      out.push({
        kind: 'duplicate-singleton',
        header: name,
        detail: `${values.length} ${name} headers: ${values.map((v) => JSON.stringify(v)).join(', ')}`,
      });
    }
  }

  const lengths = new Set(getAll(headers, 'content-length').map((v) => v.trim()));
  if (lengths.size > 1) {
    out.push({
      kind: 'conflicting-length',
      header: 'content-length',
      detail: `disagreeing Content-Length values: ${[...lengths].join(', ')}`,
    });
  }
  if (has(headers, 'content-length') && has(headers, 'transfer-encoding')) {
    out.push({
      kind: 'length-and-chunked',
      header: 'transfer-encoding',
      detail:
        'both Content-Length and Transfer-Encoding are present; RFC 9112 says ' +
        'Transfer-Encoding wins and Content-Length must be ignored, and ' +
        'disagreement between two hops about that is a desync',
    });
  }

  for (const [k, v] of headers) {
    if (k.length === 0) {
      out.push({ kind: 'empty-name', header: '', detail: 'a header with an empty name' });
      continue;
    }
    if (/[\s]/.test(k)) {
      out.push({
        kind: 'whitespace-in-name',
        header: k,
        detail: `header name contains whitespace: ${JSON.stringify(k)}`,
      });
    }
    if (/\r|\n/.test(v)) {
      out.push({
        kind: 'obs-fold',
        header: k,
        detail: 'header value contains CR or LF, which is obs-fold or injection',
      });
    }
  }

  return out;
}
