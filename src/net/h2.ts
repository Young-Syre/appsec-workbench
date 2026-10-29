/**
 * Sending a request over HTTP/2.
 *
 * The HTTP/1.1 sender writes bytes onto a socket exactly as given. This one
 * cannot make the same promise, and it is worth being precise about why: an
 * HTTP/2 request is not text. It is a HEADERS frame whose fields are HPACK
 * encoded, so "the bytes" are a function of an encoder's choices, and Node's
 * HTTP/2 implementation validates fields as it encodes them -- names must be
 * lowercase, connection-specific headers are refused, and a value containing
 * CR or LF is an error.
 *
 * So the contract here is the one HTTP/2 itself states: the *fields* are sent
 * as given, in the order given, duplicates included, and anything the
 * protocol forbids is removed rather than smuggled through. Every such
 * removal is reported in `notes`, and the request handed back in `sent` is
 * the request as it actually went out. The proxy records `sent`, not what it
 * was asked to send, so the project still holds what was on the wire.
 *
 * Representation. Pseudo-header fields are not stored as headers: `:method`,
 * `:scheme` and `:path` are the method and the URL, and `:authority` is kept
 * as a `host` header, which is the mapping RFC 9113 section 8.3.1 gives. That
 * keeps an HTTP/2 exchange readable, editable and checkable by everything
 * that already reads an HTTP/1.1 one.
 */

import { connect as h2Connect, constants as h2Constants, type ClientHttp2Session } from 'node:http2';
import { connect as netConnect, type Socket } from 'node:net';
import { connect as tlsConnect, type TLSSocket } from 'node:tls';

import { type HeaderList, get as getHeader } from '../core/headers.js';
import type { HttpRequest, HttpResponse } from '../core/message.js';
import type { SendOptions, SendResult } from './send.js';

const DEFAULT_TIMEOUT = 20_000;
const DEFAULT_MAX_BODY = 16 * 1024 * 1024;

/**
 * Fields HTTP/2 forbids in a request (RFC 9113 section 8.2.2). `te` is
 * allowed with the single value `trailers`, and is kept when it has it.
 */
const CONNECTION_SPECIFIC = new Set([
  'connection',
  'keep-alive',
  'proxy-connection',
  'transfer-encoding',
  'upgrade',
]);

/** Is this request meant to go over HTTP/2? */
export function isHttp2(request: { readonly httpVersion: string }): boolean {
  return request.httpVersion === '2' || request.httpVersion === '2.0';
}

export interface H2Fields {
  /** The header block, pseudo-header fields first, as name-value pairs. */
  readonly fields: readonly (readonly [string, string])[];
  /** The request as it can actually be sent, in this tool's representation. */
  readonly sent: HttpRequest;
  readonly notes: readonly string[];
}

/**
 * Turn a request into the field list HTTP/2 will carry.
 *
 * Pure, so the translation can be tested and shown (`awb replay --dry-run`)
 * without a connection.
 */
export function toH2Fields(request: HttpRequest): H2Fields {
  const notes: string[] = [];
  const url = new URL(request.url);
  const host = getHeader(request.headers, 'host');
  const authority = host ?? url.host;
  if (host !== undefined && host !== url.host) {
    notes.push(
      `:authority was sent as ${JSON.stringify(host)} from the Host header, which differs from the URL's ${JSON.stringify(url.host)}`,
    );
  }

  const kept: [string, string][] = [];
  const lowered: string[] = [];
  let sawHost = false;
  for (const [name, value] of request.headers) {
    const lower = name.toLowerCase();
    if (lower === 'host') {
      if (sawHost) notes.push('a second Host header was dropped; :authority carries one value');
      sawHost = true;
      continue;
    }
    if (CONNECTION_SPECIFIC.has(lower)) {
      notes.push(`${name} was not sent: HTTP/2 forbids connection-specific header fields`);
      continue;
    }
    if (lower === 'te' && value.trim().toLowerCase() !== 'trailers') {
      notes.push(`TE: ${value} was not sent: HTTP/2 allows TE only with the value "trailers"`);
      continue;
    }
    if (/[\r\n\0]/.test(value)) {
      notes.push(`${name} was not sent: its value contains CR, LF or NUL, which HTTP/2 field values cannot`);
      continue;
    }
    if (name !== lower) lowered.push(name);
    kept.push([lower, value]);
  }
  if (lowered.length > 0) {
    // One note, not one per header: every captured HTTP/1.1 request has
    // capitalised names, and a note per name buries the ones that matter.
    notes.push(
      `${lowered.length} field name${lowered.length === 1 ? ' was' : 's were'} lowercased, as HTTP/2 requires ` +
        `(${lowered.slice(0, 4).join(', ')}${lowered.length > 4 ? ', ...' : ''})`,
    );
  }

  const path = `${url.pathname}${url.search}` || '/';
  const fields: [string, string][] = [
    [':method', request.method],
    [':scheme', url.protocol.replace(':', '')],
    [':authority', authority],
    [':path', path],
    ...kept,
  ];

  const sent: HttpRequest = {
    ...request,
    httpVersion: '2',
    headers: [['host', authority], ...kept],
  };
  return { fields, sent, notes: dedupe(notes) };
}

function dedupe(notes: readonly string[]): string[] {
  return [...new Set(notes)];
}

/**
 * Node takes the header block as an object. Repeated names become arrays, so
 * duplicates survive and distinct names keep their order; what an object
 * cannot express is two duplicates interleaved with a third name, and those
 * go out grouped.
 */
function toNodeHeaders(fields: readonly (readonly [string, string])[]): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [name, value] of fields) {
    const existing = out[name];
    if (existing === undefined) out[name] = value;
    else if (Array.isArray(existing)) existing.push(value);
    else out[name] = [existing, value];
  }
  return out;
}

/** Outcome of the ALPN negotiation, so a caller can fall back. */
export interface H2SendResult extends SendResult {
  /** Set when the server would not speak HTTP/2; the request was not sent. */
  readonly refusedH2?: boolean;
  readonly sent?: HttpRequest;
}

/**
 * Send one request over a new HTTP/2 connection.
 *
 * Over https the connection asks for `h2` by ALPN and offers `http/1.1` as
 * well, so that a server without HTTP/2 can say so instead of failing the
 * handshake; when it does, nothing is sent and `refusedH2` is set. Over plain
 * http this is HTTP/2 with prior knowledge (h2c), which only works against a
 * server that expects it.
 */
export async function sendH2(request: HttpRequest, options: SendOptions = {}): Promise<H2SendResult> {
  let url: URL;
  try {
    url = new URL(request.url);
  } catch {
    return { error: `not a sendable URL: ${request.url}`, wire: Buffer.alloc(0), notes: [], truncated: false };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { error: `only http and https can be sent, not ${url.protocol}`, wire: Buffer.alloc(0), notes: [], truncated: false };
  }

  const { fields, sent, notes: fieldNotes } = toH2Fields(request);
  const notes = [...fieldNotes];
  // There is no wire text for an HPACK block; what is recorded is the field
  // list in order, which is what a reader needs to know was sent.
  const wire = Buffer.from(
    fields.map(([k, v]) => `${k}: ${v}`).join('\r\n') + '\r\n\r\n',
    'latin1',
  );

  const secure = url.protocol === 'https:';
  const host = options.connectTo?.host ?? url.hostname;
  const port = options.connectTo?.port ?? Number(url.port || (secure ? 443 : 80));
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT;
  const maxBody = options.maxBodyBytes ?? DEFAULT_MAX_BODY;
  const started = Date.now();

  let socket: Socket | TLSSocket;
  try {
    socket = await openSocket(secure, host, port, url.hostname, options, timeoutMs);
  } catch (err) {
    return { error: (err as Error).message, wire, notes, truncated: false, sent };
  }

  if (secure) {
    const tlsSocket = socket as TLSSocket;
    if (!tlsSocket.authorized && tlsSocket.authorizationError) {
      notes.push(`TLS certificate was not verified: ${String(tlsSocket.authorizationError)}`);
    }
    if (tlsSocket.alpnProtocol !== 'h2') {
      socket.destroy();
      return {
        error: `the server does not offer HTTP/2 (ALPN chose ${tlsSocket.alpnProtocol || 'nothing'})`,
        refusedH2: true,
        wire: Buffer.alloc(0),
        notes,
        truncated: false,
      };
    }
  }

  return new Promise<H2SendResult>((resolve) => {
    let settled = false;
    let session: ClientHttp2Session | undefined;
    const finish = (result: H2SendResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      session?.destroy();
      socket.destroy();
      resolve(result);
    };
    const timer = setTimeout(() => {
      finish({ error: `timed out after ${timeoutMs}ms`, wire, notes, truncated: false, sent });
    }, timeoutMs);

    session = h2Connect(`${url.protocol}//${url.host}`, { createConnection: () => socket });
    session.on('error', (err) => finish({ error: err.message, wire, notes, truncated: false, sent }));
    session.on('goaway', (code) => {
      if (code !== h2Constants.NGHTTP2_NO_ERROR) notes.push(`the server sent GOAWAY with error code ${code}`);
    });

    const hasBody = request.body.length > 0;
    let stream;
    try {
      stream = session.request(toNodeHeaders(fields), { endStream: !hasBody });
    } catch (err) {
      finish({ error: `HTTP/2 refused the request: ${(err as Error).message}`, wire, notes, truncated: false, sent });
      return;
    }

    const declared = getHeader(request.headers, 'content-length');
    if (declared !== undefined && Number(declared) !== request.body.length) {
      notes.push(
        `content-length says ${declared} and the body is ${request.body.length} bytes; ` +
          'HTTP/2 frames the body itself, so a server should treat this as malformed',
      );
    }

    let status = 0;
    let headers: HeaderList = [];
    const chunks: Buffer[] = [];
    let total = 0;
    let truncated = false;

    stream.on('response', (object, _flags, raw?: string[]) => {
      status = Number(object[':status'] ?? 0);
      headers = fromRaw(raw, object);
    });
    stream.on('data', (chunk: Buffer) => {
      if (total + chunk.length <= maxBody) {
        chunks.push(chunk);
        total += chunk.length;
      } else {
        const room = Math.max(0, maxBody - total);
        if (room > 0) chunks.push(chunk.subarray(0, room));
        total = maxBody;
        truncated = true;
      }
    });
    stream.on('trailers', () => notes.push('the response carried trailer fields'));
    stream.on('end', () => {
      const response: HttpResponse = {
        status,
        statusText: '',
        httpVersion: '2',
        headers,
        body: Buffer.concat(chunks),
        elapsedMs: Date.now() - started,
      };
      finish({ response, wire, notes, truncated, sent });
    });
    stream.on('error', (err) => finish({ error: err.message, wire, notes, truncated: false, sent }));
    stream.on('close', () => {
      if (stream.rstCode !== undefined && stream.rstCode !== h2Constants.NGHTTP2_NO_ERROR && status === 0) {
        finish({ error: `the server reset the stream (code ${stream.rstCode})`, wire, notes, truncated: false, sent });
      }
    });
    if (hasBody) stream.end(request.body);
  });
}

function openSocket(
  secure: boolean,
  host: string,
  port: number,
  servername: string,
  options: SendOptions,
  timeoutMs: number,
): Promise<Socket | TLSSocket> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    const done = (): void => {
      clearTimeout(timer);
      socket.removeListener('error', fail);
      resolve(socket);
    };
    const fail = (err: Error): void => {
      clearTimeout(timer);
      reject(err);
    };
    const socket: Socket | TLSSocket = secure
      ? tlsConnect(
          {
            host,
            port,
            servername: options.servername ?? servername,
            rejectUnauthorized: options.insecure !== true,
            ALPNProtocols: ['h2', 'http/1.1'],
            ...(options.ca === undefined ? {} : { ca: [...options.ca] }),
          },
          done,
        )
      : netConnect({ host, port }, done);
    socket.once('error', fail);
  });
}

/** Response fields in arrival order, pseudo-header fields removed. */
function fromRaw(raw: readonly string[] | undefined, object: Record<string, unknown>): HeaderList {
  const out: [string, string][] = [];
  if (raw !== undefined) {
    for (let i = 0; i + 1 < raw.length; i += 2) {
      const name = raw[i] as string;
      if (!name.startsWith(':')) out.push([name, raw[i + 1] as string]);
    }
    return out;
  }
  // Older runtimes do not pass the raw list. The object keeps insertion order
  // and gathers duplicates into arrays, which is the next best thing.
  for (const [name, value] of Object.entries(object)) {
    if (name.startsWith(':')) continue;
    for (const v of Array.isArray(value) ? value : [value]) out.push([name, String(v)]);
  }
  return out;
}
