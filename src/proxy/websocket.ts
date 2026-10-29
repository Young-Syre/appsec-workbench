/**
 * WebSocket frame parsing, for logging what passes through the proxy.
 *
 * A great deal of modern application logic moved into WebSocket messages, and
 * a proxy that records the upgrade handshake and then shows a blank tunnel
 * has recorded the least interesting part. Authorisation decisions, GraphQL
 * subscriptions and trading operations all travel as frames.
 *
 * This is a decoder, not an implementation: it never produces frames, so it
 * cannot be used to speak the protocol. It reads a byte stream in whatever
 * sized pieces the socket delivers, emits whole messages, and gives up
 * loudly on a stream it cannot follow rather than guessing.
 */

export type Opcode = 'continuation' | 'text' | 'binary' | 'close' | 'ping' | 'pong' | 'reserved';

export interface Frame {
  readonly fin: boolean;
  readonly opcode: Opcode;
  readonly masked: boolean;
  readonly payload: Buffer;
  /** Total bytes this frame occupied on the wire. */
  readonly size: number;
}

const OPCODES: Record<number, Opcode> = {
  0x0: 'continuation',
  0x1: 'text',
  0x2: 'binary',
  0x8: 'close',
  0x9: 'ping',
  0xa: 'pong',
};

export function opcodeName(code: number): Opcode {
  return OPCODES[code] ?? 'reserved';
}

/**
 * Parse one frame from the front of `buf`.
 *
 * Returns undefined when the buffer does not yet hold a whole frame, which is
 * the normal case on a socket: a 2MB message arrives as a hundred reads.
 */
export function parseFrame(buf: Buffer): Frame | undefined {
  if (buf.length < 2) return undefined;
  const first = buf[0] as number;
  const second = buf[1] as number;

  const fin = (first & 0x80) !== 0;
  const opcode = opcodeName(first & 0x0f);
  const masked = (second & 0x80) !== 0;
  let length = second & 0x7f;
  let at = 2;

  if (length === 126) {
    if (buf.length < at + 2) return undefined;
    length = buf.readUInt16BE(at);
    at += 2;
  } else if (length === 127) {
    if (buf.length < at + 8) return undefined;
    const big = buf.readBigUInt64BE(at);
    // A frame larger than Node can address in a Buffer is not something to
    // try to hold; the caller is told, and drops the connection's log.
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error('websocket frame declares a length larger than this runtime can hold');
    }
    length = Number(big);
    at += 8;
  }

  let mask: Buffer | undefined;
  if (masked) {
    if (buf.length < at + 4) return undefined;
    mask = buf.subarray(at, at + 4);
    at += 4;
  }

  if (buf.length < at + length) return undefined;
  const raw = buf.subarray(at, at + length);
  const payload = mask === undefined ? Buffer.from(raw) : unmask(raw, mask);

  return { fin, opcode, masked, payload, size: at + length };
}

function unmask(payload: Buffer, mask: Buffer): Buffer {
  const out = Buffer.allocUnsafe(payload.length);
  for (let i = 0; i < payload.length; i += 1) {
    out[i] = (payload[i] as number) ^ (mask[i % 4] as number);
  }
  return out;
}

export interface Message {
  readonly opcode: Opcode;
  readonly payload: Buffer;
  /** True when the message arrived across more than one frame. */
  readonly fragmented: boolean;
}

/**
 * A stateful reader that reassembles fragmented messages.
 *
 * One per direction per connection: client-to-server frames are masked and
 * server-to-client frames are not, and a single reader for both would
 * mis-parse one of them.
 */
export class FrameReader {
  private buffer: Buffer = Buffer.alloc(0);
  private pending: Buffer[] = [];
  private pendingOpcode: Opcode | undefined;
  private readonly maxMessageBytes: number;
  /** Set once the stream stops making sense; no further output is produced. */
  desynchronised: string | undefined;

  constructor(maxMessageBytes = 8 * 1024 * 1024) {
    this.maxMessageBytes = maxMessageBytes;
  }

  /** Feed bytes, get back whole messages. */
  push(chunk: Buffer): Message[] {
    if (this.desynchronised !== undefined) return [];
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    const out: Message[] = [];

    for (;;) {
      let frame: Frame | undefined;
      try {
        frame = parseFrame(this.buffer);
      } catch (err) {
        this.desynchronised = (err as Error).message;
        return out;
      }
      if (frame === undefined) break;
      this.buffer = this.buffer.subarray(frame.size);

      // Control frames may be interleaved inside a fragmented message and are
      // never themselves fragmented.
      if (frame.opcode === 'close' || frame.opcode === 'ping' || frame.opcode === 'pong') {
        out.push({ opcode: frame.opcode, payload: frame.payload, fragmented: false });
        continue;
      }

      if (frame.opcode === 'continuation') {
        if (this.pendingOpcode === undefined) {
          this.desynchronised = 'a continuation frame arrived with no message open';
          return out;
        }
        this.pending.push(frame.payload);
      } else {
        if (this.pendingOpcode !== undefined) {
          this.desynchronised = `a ${frame.opcode} frame arrived while a ${this.pendingOpcode} message was still open`;
          return out;
        }
        this.pendingOpcode = frame.opcode;
        this.pending = [frame.payload];
      }

      const total = this.pending.reduce((n, b) => n + b.length, 0);
      if (total > this.maxMessageBytes) {
        this.desynchronised = `a websocket message exceeded ${this.maxMessageBytes} bytes and was not buffered`;
        this.pending = [];
        this.pendingOpcode = undefined;
        return out;
      }

      if (frame.fin) {
        out.push({
          opcode: this.pendingOpcode,
          payload: Buffer.concat(this.pending),
          fragmented: this.pending.length > 1,
        });
        this.pending = [];
        this.pendingOpcode = undefined;
      }
    }

    return out;
  }

  /** Bytes held because they do not yet form a frame. */
  buffered(): number {
    return this.buffer.length;
  }
}

/**
 * Was this HTTP exchange a successful WebSocket upgrade?
 *
 * Checked on the response rather than the request, because a request asking
 * to upgrade that got a 200 back is an ordinary response and the connection
 * stays HTTP.
 */
export function isWebSocketUpgrade(
  status: number,
  headers: readonly (readonly [string, string])[],
): boolean {
  if (status !== 101) return false;
  const upgrade = headers.find(([k]) => k.toLowerCase() === 'upgrade')?.[1] ?? '';
  return upgrade.toLowerCase() === 'websocket';
}
