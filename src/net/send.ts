/**
 * Sending a request over a raw socket, and parsing the response ourselves.
 *
 * Node's http client is excellent and completely unsuitable here. It
 * normalises what it sends: it reorders headers, collapses duplicates, adds
 * its own `Host` and `Connection`, and recomputes `Content-Length`. Every one
 * of those is a correctness feature for an application and a defect for a
 * security tool, because the whole class of request smuggling, header
 * injection and parser-differential bugs lives precisely in the bytes it
 * tidies up.
 *
 * So this writes the request onto a socket exactly as given, byte for byte,
 * and reads the response with a parser that reports what it saw rather than
 * what it expected. A malformed response is data, not an exception.
 */

import { connect as netConnect, type Socket } from 'node:net';
import { connect as tlsConnect, type TLSSocket } from 'node:tls';

import {
  type HeaderList,
  get as getHeader,
  serialiseHeaders,
} from '../core/headers.js';
import { type HttpRequest, type HttpResponse, requestLine } from '../core/message.js';

export interface SendOptions {
  /** Milliseconds to wait for the whole exchange. */
  readonly timeoutMs?: number;
  /**
   * Recompute Content-Length from the body before sending.
   *
   * Off by default, which is the opposite of every HTTP client: a deliberate
   * mismatch between declared and actual length is a test, and a tool that
   * fixes it has removed the test.
   */
  readonly fixContentLength?: boolean;
  /** Skip certificate verification. Needed for a target with a bad cert. */
  readonly insecure?: boolean;
  /** SNI name, when it must differ from the connected host. */
  readonly servername?: string;
  /** Connect here instead of the URL's host, for testing and for pinning. */
  readonly connectTo?: { readonly host: string; readonly port: number };
  /** Maximum response body to buffer. Larger responses are truncated. */
  readonly maxBodyBytes?: number;
  /** Extra CA certificates to trust, as PEM. */
  readonly ca?: readonly string[];
}

export interface SendResult {
  readonly response?: HttpResponse;
  readonly error?: string;
  /** The exact bytes written, for the record. */
  readonly wire: Buffer;
  /** Response anomalies the parser noticed. */
  readonly notes: readonly string[];
  readonly truncated: boolean;
}

const DEFAULT_TIMEOUT = 20_000;
const DEFAULT_MAX_BODY = 16 * 1024 * 1024;

/** Build the exact request bytes. Nothing is added that was not asked for. */
export function serialiseToWire(request: HttpRequest, options: SendOptions = {}): Buffer {
  let headers: HeaderList = request.headers;
  if (options.fixContentLength === true) {
    const declared = getHeader(headers, 'content-length');
    if (declared !== undefined) {
      headers = headers.map(([k, v]) =>
        k.toLowerCase() === 'content-length'
          ? ([k, String(request.body.length)] as const)
          : ([k, v] as const),
      );
    }
  }
  const head = `${requestLine(request)}\r\n${serialiseHeaders(headers)}\r\n\r\n`;
  return Buffer.concat([Buffer.from(head, 'latin1'), request.body]);
}

export interface ParsedResponse {
  readonly response: HttpResponse;
  readonly notes: readonly string[];
  readonly truncated: boolean;
}

/**
 * Parse an HTTP/1.x response from a buffer.
 *
 * Framing follows RFC 9112 section 6: Transfer-Encoding wins over
 * Content-Length, and when both are present that disagreement is recorded as
 * a note rather than resolved silently, because it is the precondition for a
 * desync.
 */
export function parseResponse(
  buf: Buffer,
  elapsedMs: number,
  maxBodyBytes = DEFAULT_MAX_BODY,
): ParsedResponse {
  const notes: string[] = [];
  const headEnd = indexOfHeadEnd(buf);
  if (headEnd < 0) throw new Error('response ended before the headers were complete');

  const headText = buf.subarray(0, headEnd).toString('latin1');
  const crlfTerminated = buf.subarray(headEnd, headEnd + 4).toString('latin1') === '\r\n\r\n';
  const bodyStart = headEnd + (crlfTerminated ? 4 : 2);

  const lines = headText.split(/\r?\n/);
  const statusLineText = lines.shift() ?? '';
  const m = /^HTTP\/(\d(?:\.\d)?)\s+(\d{3})(?:\s+(.*))?$/.exec(statusLineText);
  if (!m) throw new Error(`not a status line: ${JSON.stringify(statusLineText.slice(0, 80))}`);
  const httpVersion = m[1] as string;
  const status = Number(m[2]);
  const statusText = (m[3] ?? '').trimEnd();

  const headers: [string, string][] = [];
  for (const line of lines) {
    if (line.length === 0) continue;
    if (/^[ \t]/.test(line)) {
      // obs-fold: deprecated by RFC 9112 and a smuggling primitive. Record it
      // and append to the previous value, which is what a lenient parser does
      // and therefore what the next hop may also do.
      notes.push('response used obs-fold (a continuation line), deprecated by RFC 9112');
      const last = headers[headers.length - 1];
      if (last !== undefined) last[1] = `${last[1]} ${line.trim()}`;
      continue;
    }
    const i = line.indexOf(':');
    if (i < 0) {
      notes.push(`response header line without a colon: ${JSON.stringify(line.slice(0, 60))}`);
      continue;
    }
    headers.push([line.slice(0, i), line.slice(i + 1).replace(/^ /, '')]);
  }

  const te = getHeader(headers, 'transfer-encoding');
  const cl = getHeader(headers, 'content-length');
  if (te !== undefined && cl !== undefined) {
    notes.push(
      'response carries both Transfer-Encoding and Content-Length; per RFC 9112 ' +
        'Transfer-Encoding wins and Content-Length must be ignored',
    );
  }

  const raw = buf.subarray(bodyStart);
  let body: Buffer;
  let truncated = false;

  const bodyless = status === 204 || status === 304 || (status >= 100 && status < 200);
  if (bodyless) {
    body = Buffer.alloc(0);
    if (raw.length > 0) {
      notes.push(`a ${status} response must have no body, and ${raw.length} bytes followed`);
    }
  } else if (te !== undefined && /chunked/i.test(te)) {
    const dechunked = dechunk(raw, maxBodyBytes);
    body = dechunked.body;
    truncated = dechunked.truncated;
    notes.push(...dechunked.notes);
  } else if (cl !== undefined) {
    const declared = Number(cl);
    if (!Number.isInteger(declared) || declared < 0) {
      notes.push(`Content-Length is not a non-negative integer: ${JSON.stringify(cl)}`);
      body = raw;
    } else if (raw.length < declared) {
      notes.push(`Content-Length declared ${declared} bytes but only ${raw.length} arrived`);
      body = raw;
    } else {
      if (raw.length > declared) {
        notes.push(
          `${raw.length - declared} bytes followed the declared Content-Length of ${declared}; ` +
            'on a keep-alive connection that is a queued response',
        );
      }
      body = raw.subarray(0, Math.min(declared, maxBodyBytes));
      truncated = declared > maxBodyBytes;
    }
  } else {
    body = raw.subarray(0, maxBodyBytes);
    truncated = raw.length > maxBodyBytes;
  }

  return {
    response: { status, statusText, httpVersion, headers, body, elapsedMs },
    notes,
    truncated,
  };
}

function indexOfHeadEnd(buf: Buffer): number {
  const crlf = buf.indexOf('\r\n\r\n', 0, 'latin1');
  const lf = buf.indexOf('\n\n', 0, 'latin1');
  if (crlf >= 0 && (lf < 0 || crlf <= lf)) return crlf;
  return lf;
}

interface Dechunked {
  readonly body: Buffer;
  readonly notes: readonly string[];
  readonly truncated: boolean;
}

function dechunk(raw: Buffer, maxBodyBytes: number): Dechunked {
  const notes: string[] = [];
  const parts: Buffer[] = [];
  let total = 0;
  let at = 0;

  for (;;) {
    const lineEnd = raw.indexOf('\r\n', at, 'latin1');
    if (lineEnd < 0) {
      notes.push('chunked body ended without a terminating chunk');
      break;
    }
    const header = raw.subarray(at, lineEnd).toString('latin1');
    const semi = header.indexOf(';');
    const sizeText = (semi < 0 ? header : header.slice(0, semi)).trim();
    if (semi >= 0) {
      notes.push(`chunk extension present: ${JSON.stringify(header.slice(semi + 1).trim())}`);
    }
    const size = parseInt(sizeText, 16);
    if (!Number.isInteger(size) || size < 0) {
      notes.push(`chunk size is not hexadecimal: ${JSON.stringify(sizeText)}`);
      break;
    }
    at = lineEnd + 2;
    if (size === 0) {
      const trailerEnd = raw.indexOf('\r\n', at, 'latin1');
      if (trailerEnd > at) notes.push('chunked body carried trailer fields');
      break;
    }
    if (at + size > raw.length) {
      notes.push(`a chunk declared ${size} bytes but only ${raw.length - at} remained`);
      parts.push(raw.subarray(at));
      break;
    }
    if (total + size <= maxBodyBytes) {
      parts.push(raw.subarray(at, at + size));
      total += size;
    } else {
      const room = Math.max(0, maxBodyBytes - total);
      if (room > 0) parts.push(raw.subarray(at, at + room));
      return { body: Buffer.concat(parts), notes, truncated: true };
    }
    at += size + 2;
  }

  return { body: Buffer.concat(parts), notes, truncated: false };
}

/**
 * Send one request and read one response.
 *
 * `Connection: close` is not forced. If the caller's headers say keep-alive,
 * the socket is closed after the first complete response anyway, and anything
 * the server pipelined behind it is reported as a note -- which is how a
 * queued-response desync becomes visible.
 */
export async function send(
  request: HttpRequest,
  options: SendOptions = {},
): Promise<SendResult> {
  const wire = serialiseToWire(request, options);
  const notes: string[] = [];

  let url: URL;
  try {
    url = new URL(request.url);
  } catch {
    return { error: `not a sendable URL: ${request.url}`, wire, notes, truncated: false };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return {
      error: `only http and https can be sent, not ${url.protocol}`,
      wire,
      notes,
      truncated: false,
    };
  }

  const secure = url.protocol === 'https:';
  const host = options.connectTo?.host ?? url.hostname;
  const port = options.connectTo?.port ?? Number(url.port || (secure ? 443 : 80));
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT;
  const maxBody = options.maxBodyBytes ?? DEFAULT_MAX_BODY;

  return new Promise<SendResult>((resolve) => {
    const started = Date.now();
    const chunks: Buffer[] = [];
    let settled = false;

    const finish = (result: SendResult): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };

    const tryParse = (final: boolean): void => {
      if (settled) return;
      const buf = Buffer.concat(chunks);
      if (indexOfHeadEnd(buf) < 0) {
        if (final) {
          finish({
            error:
              buf.length === 0
                ? 'the server closed the connection without sending anything'
                : 'the server closed the connection before the headers were complete',
            wire,
            notes,
            truncated: false,
          });
        }
        return;
      }
      let parsed: ParsedResponse;
      try {
        parsed = parseResponse(buf, Date.now() - started, maxBody);
      } catch (err) {
        if (final) finish({ error: (err as Error).message, wire, notes, truncated: false });
        return;
      }
      if (!final && !isComplete(parsed, buf)) return;
      finish({
        response: parsed.response,
        wire,
        notes: [...notes, ...parsed.notes],
        truncated: parsed.truncated,
      });
    };

    const onConnect = (): void => {
      socket.write(wire);
    };

    let socket: Socket | TLSSocket;
    if (secure) {
      socket = tlsConnect(
        {
          host,
          port,
          servername: options.servername ?? url.hostname,
          rejectUnauthorized: options.insecure !== true,
          ALPNProtocols: ['http/1.1'],
          ...(options.ca === undefined ? {} : { ca: [...options.ca] }),
        },
        onConnect,
      );
      socket.on('secureConnect', () => {
        const s = socket as TLSSocket;
        if (!s.authorized && s.authorizationError) {
          notes.push(`TLS certificate was not verified: ${String(s.authorizationError)}`);
        }
      });
    } else {
      socket = netConnect({ host, port }, onConnect);
    }

    socket.setTimeout(timeoutMs, () => {
      notes.push(`no complete response within ${timeoutMs}ms`);
      tryParse(true);
      finish({ error: `timed out after ${timeoutMs}ms`, wire, notes, truncated: false });
    });

    socket.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
      tryParse(false);
    });
    socket.on('end', () => tryParse(true));
    socket.on('close', () => tryParse(true));
    socket.on('error', (err: Error) => {
      finish({ error: err.message, wire, notes, truncated: false });
    });
  });
}

/**
 * Do we have the whole response yet?
 *
 * Only answerable when the response frames itself. Without Content-Length or
 * chunked encoding the body runs to end-of-connection, so we must wait for
 * the close -- which is also why a server that omits both makes every request
 * as slow as its keep-alive timeout.
 */
function isComplete(parsed: ParsedResponse, buf: Buffer): boolean {
  const { response } = parsed;
  const status = response.status;
  if (status === 204 || status === 304 || (status >= 100 && status < 200)) return true;

  const te = getHeader(response.headers, 'transfer-encoding');
  const cl = getHeader(response.headers, 'content-length');
  if (te !== undefined && /chunked/i.test(te)) {
    return buf.indexOf('\r\n0\r\n', 0, 'latin1') >= 0;
  }
  if (cl !== undefined) {
    const declared = Number(cl);
    if (!Number.isInteger(declared)) return false;
    const headEnd = indexOfHeadEnd(buf);
    if (headEnd < 0) return false;
    const crlfTerminated = buf.subarray(headEnd, headEnd + 4).toString('latin1') === '\r\n\r\n';
    const bodyStart = headEnd + (crlfTerminated ? 4 : 2);
    return buf.length - bodyStart >= declared;
  }
  return false;
}
