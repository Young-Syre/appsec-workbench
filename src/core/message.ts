/**
 * The exchange: one request, one response, and everything observed about them.
 *
 * Every other module in this tool consumes and produces these. A finding is
 * never a sentence on its own -- it is a sentence plus the exchange id that
 * produced it, so that anybody reading the report can replay the exact bytes.
 */

import { createHash } from 'node:crypto';
import {
  type HeaderList,
  get as headerGet,
  serialiseHeaders,
} from './headers.js';

export interface HttpRequest {
  readonly method: string;
  /** Absolute URL. The proxy reconstructs it from the CONNECT host + path. */
  readonly url: string;
  /** `1.1`, `2`, `3`. Recorded because it changes what is even expressible. */
  readonly httpVersion: string;
  readonly headers: HeaderList;
  readonly body: Buffer;
  /** Milliseconds since the epoch, when the first byte was sent. */
  readonly startedAt: number;
}

export interface HttpResponse {
  readonly status: number;
  readonly statusText: string;
  readonly httpVersion: string;
  readonly headers: HeaderList;
  readonly body: Buffer;
  /** Milliseconds from request start to response end. */
  readonly elapsedMs: number;
}

export type ExchangeSource =
  | 'proxy'
  | 'browser'
  | 'replay'
  | 'fuzz'
  | 'active-scan'
  | 'import';

export interface Exchange {
  readonly id: string;
  readonly request: HttpRequest;
  /** Absent when the request never completed. The error says why. */
  readonly response?: HttpResponse;
  readonly error?: string;
  readonly source: ExchangeSource;
  /** Free-form labels: a session name, a fuzz job id, a check id. */
  readonly tags: readonly string[];
  /** The exchange this one was derived from, for replay and fuzz lineage. */
  readonly parentId?: string;
}

export interface WebSocketFrame {
  readonly exchangeId: string;
  readonly direction: 'sent' | 'received';
  readonly opcode: 'text' | 'binary' | 'close' | 'ping' | 'pong';
  readonly payload: Buffer;
  readonly at: number;
}

/**
 * A stable id for an exchange.
 *
 * Derived from the request bytes and the start time rather than from a
 * counter, so that two runs over the same captured traffic produce the same
 * ids and two reports can be diffed.
 */
export function exchangeId(request: HttpRequest, salt = ''): string {
  const h = createHash('sha256');
  h.update(request.method);
  h.update('\0');
  h.update(request.url);
  h.update('\0');
  h.update(serialiseHeaders(request.headers));
  h.update('\0');
  h.update(request.body);
  h.update('\0');
  h.update(String(request.startedAt));
  h.update('\0');
  h.update(salt);
  return h.digest('hex').slice(0, 16);
}

/**
 * The request line as it goes on the wire.
 *
 * Origin form for an ordinary request (`GET /a?b=c HTTP/1.1`), which is what a
 * server sees, rather than the absolute form a proxy sees.
 */
export function requestLine(request: HttpRequest): string {
  let target: string;
  try {
    const u = new URL(request.url);
    target = `${u.pathname}${u.search}`;
  } catch {
    target = request.url;
  }
  return `${request.method} ${target} HTTP/${request.httpVersion}`;
}

export function statusLine(response: HttpResponse): string {
  const text = response.statusText ? ` ${response.statusText}` : '';
  return `HTTP/${response.httpVersion} ${response.status}${text}`;
}

/** The full request, byte for byte, as text. Bodies are decoded as UTF-8. */
export function serialiseRequest(request: HttpRequest): string {
  const head = `${requestLine(request)}\r\n${serialiseHeaders(request.headers)}\r\n\r\n`;
  return head + request.body.toString('utf8');
}

export function serialiseResponse(response: HttpResponse): string {
  const head = `${statusLine(response)}\r\n${serialiseHeaders(response.headers)}\r\n\r\n`;
  return head + response.body.toString('utf8');
}

/**
 * Parse a raw request, the inverse of `serialiseRequest`.
 *
 * This is what makes a request editable in `$EDITOR`: the replay command
 * writes the exchange out as text, you change whatever you like including the
 * header order and any duplicates, and this reads it back without
 * interpreting anything. Nothing is recomputed -- if you edit the body and
 * leave Content-Length wrong, the wrong length is what gets sent, because
 * that is frequently the point.
 */
export function parseRawRequest(
  raw: string,
  origin: string,
  startedAt = Date.now(),
): HttpRequest {
  const split = raw.indexOf('\r\n\r\n');
  const lfSplit = raw.indexOf('\n\n');
  let headEnd: number;
  let bodyStart: number;
  if (split >= 0 && (lfSplit < 0 || split <= lfSplit)) {
    headEnd = split;
    bodyStart = split + 4;
  } else if (lfSplit >= 0) {
    headEnd = lfSplit;
    bodyStart = lfSplit + 2;
  } else {
    headEnd = raw.length;
    bodyStart = raw.length;
  }

  const head = raw.slice(0, headEnd);
  const body = Buffer.from(raw.slice(bodyStart), 'utf8');
  const lines = head.split(/\r?\n/);
  const first = lines.shift() ?? '';
  const m = /^(\S+)\s+(\S+)(?:\s+HTTP\/(\S+))?\s*$/.exec(first);
  if (!m) throw new Error(`not a request line: ${JSON.stringify(first)}`);
  const method = m[1] as string;
  const target = m[2] as string;
  const httpVersion = m[3] ?? '1.1';

  const headers: [string, string][] = [];
  for (const line of lines) {
    if (line.length === 0) continue;
    const i = line.indexOf(':');
    if (i < 0) throw new Error(`not a header line: ${JSON.stringify(line)}`);
    headers.push([line.slice(0, i), line.slice(i + 1).replace(/^ /, '')]);
  }

  const url = resolveTarget(target, headers, origin);
  return { method, url, httpVersion, headers, body, startedAt };
}

function resolveTarget(
  target: string,
  headers: readonly (readonly [string, string])[],
  origin: string,
): string {
  if (/^https?:\/\//i.test(target)) return target;
  const host = headerGet(headers, 'host');
  const base = host ? inferOrigin(host, origin) : origin;
  try {
    return new URL(target, base).toString();
  } catch {
    return base.replace(/\/$/, '') + target;
  }
}

/**
 * Build an origin from a Host header, keeping the scheme of the origin the
 * exchange came from. A Host header carries no scheme, and guessing https
 * for a capture taken over http would silently retarget the request.
 */
function inferOrigin(host: string, fallback: string): string {
  let scheme = 'http';
  try {
    scheme = new URL(fallback).protocol.replace(':', '');
  } catch {
    /* fallback is not a URL; http is the safer assumption */
  }
  return `${scheme}://${host}`;
}

/** The declared media type, lowercased, without parameters. */
export function contentType(headers: HeaderList): string | undefined {
  const raw = headerGet(headers, 'content-type');
  if (raw === undefined) return undefined;
  const semi = raw.indexOf(';');
  return (semi < 0 ? raw : raw.slice(0, semi)).trim().toLowerCase();
}

export function charsetOf(headers: HeaderList): string | undefined {
  const raw = headerGet(headers, 'content-type');
  if (raw === undefined) return undefined;
  const m = /;\s*charset\s*=\s*"?([^";]+)"?/i.exec(raw);
  return m ? (m[1] as string).trim().toLowerCase() : undefined;
}

export function isTextual(headers: HeaderList): boolean {
  const ct = contentType(headers);
  if (ct === undefined) return false;
  return (
    ct.startsWith('text/') ||
    ct.endsWith('+json') ||
    ct.endsWith('+xml') ||
    [
      'application/json',
      'application/xml',
      'application/javascript',
      'application/x-javascript',
      'application/x-www-form-urlencoded',
      'application/graphql',
    ].includes(ct)
  );
}
