/**
 * Content coding, decoded on read rather than on capture.
 *
 * The stored body is the body that was on the wire, gzip and all. That is a
 * deliberate choice: a capture is evidence, and a tool that silently rewrites
 * the bytes it recorded has made its own output unverifiable. If the
 * application sent a malformed gzip stream, or declared `br` and sent
 * deflate, the capture has to still contain that.
 *
 * So decoding happens where a human or a check needs to read text, it is
 * allowed to fail, and a failure is itself reportable: `Content-Encoding`
 * disagreeing with the bytes is a finding about a middlebox, not an
 * inconvenience.
 */

import {
  brotliDecompressSync,
  gunzipSync,
  inflateRawSync,
  inflateSync,
  unzipSync,
} from 'node:zlib';
import * as zlib from 'node:zlib';

import { type HeaderList, get as getHeader } from './headers.js';

export interface Decoded {
  readonly body: Buffer;
  /** The codings applied, outermost first, as declared. */
  readonly codings: readonly string[];
  /** Set when a declared coding could not be undone. */
  readonly error?: string;
}

/** zstd arrived in Node 22.15; older runtimes have no decompressor for it. */
const zstdDecompressSync =
  (zlib as unknown as { zstdDecompressSync?: (buf: Buffer) => Buffer }).zstdDecompressSync;

export function supportedCodings(): string[] {
  const out = ['gzip', 'x-gzip', 'deflate', 'br', 'identity'];
  if (zstdDecompressSync !== undefined) out.push('zstd');
  return out;
}

function decodeOne(coding: string, body: Buffer): Buffer {
  switch (coding) {
    case '':
    case 'identity':
      return body;
    case 'gzip':
    case 'x-gzip':
      // unzipSync accepts both gzip and zlib wrappers, which matters because
      // servers labelled `gzip` do sometimes send a bare zlib stream.
      try {
        return gunzipSync(body);
      } catch {
        return unzipSync(body);
      }
    case 'deflate':
      // RFC 9110 says zlib-wrapped; a good deal of the web sends raw deflate.
      try {
        return inflateSync(body);
      } catch {
        return inflateRawSync(body);
      }
    case 'br':
      return brotliDecompressSync(body);
    case 'zstd':
      if (zstdDecompressSync === undefined) {
        throw new Error(
          `zstd needs Node 22.15 or newer; this is ${process.version}`,
        );
      }
      return zstdDecompressSync(body);
    default:
      throw new Error(`unknown content coding ${JSON.stringify(coding)}`);
  }
}

/**
 * Undo `Content-Encoding`, which can legitimately be a list.
 *
 * `Content-Encoding: gzip, br` means br was applied last, so it comes off
 * first. Getting that order wrong produces garbage that looks like a
 * corrupted response.
 */
export function decodeBody(headers: HeaderList, body: Buffer): Decoded {
  const declared = getHeader(headers, 'content-encoding');
  if (declared === undefined || declared.trim().length === 0) {
    return { body, codings: [] };
  }

  const codings = declared
    .split(',')
    .map((c) => c.trim().toLowerCase())
    .filter((c) => c.length > 0);

  let current = body;
  for (const coding of [...codings].reverse()) {
    try {
      current = decodeOne(coding, current);
    } catch (err) {
      return {
        body,
        codings,
        error:
          `Content-Encoding declares ${declared} but the body could not be decoded as ` +
          `${coding}: ${(err as Error).message}`,
      };
    }
  }

  return { body: current, codings };
}

/**
 * Body as text for reading and matching.
 *
 * The charset is honoured where Node can, because a check that greps a
 * Shift_JIS page as UTF-8 finds nothing and reports nothing.
 */
export function bodyText(headers: HeaderList, body: Buffer): string {
  const decoded = decodeBody(headers, body);
  const charset = charsetFrom(headers);
  if (charset === undefined || charset === 'utf-8' || charset === 'utf8') {
    return decoded.body.toString('utf8');
  }
  try {
    return new TextDecoder(charset, { fatal: false }).decode(decoded.body);
  } catch {
    return decoded.body.toString('utf8');
  }
}

function charsetFrom(headers: HeaderList): string | undefined {
  const raw = getHeader(headers, 'content-type');
  if (raw === undefined) return undefined;
  const m = /;\s*charset\s*=\s*"?([^";]+)"?/i.exec(raw);
  return m ? (m[1] as string).trim().toLowerCase() : undefined;
}
