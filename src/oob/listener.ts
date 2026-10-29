/**
 * Out-of-band interaction capture: DNS and HTTP.
 *
 * The bugs that matter most are often the ones with no response to look at.
 * A server-side request forgery into an internal host returns the same page
 * either way. An XXE that reads a file and posts it somewhere shows nothing
 * locally. A blind SQL injection that can run `LOAD_FILE` over UNC shows
 * nothing either. In each case the evidence is a connection the target made,
 * and to see it you need something listening.
 *
 * Burp's answer is Collaborator, a hosted service. This is the same idea you
 * run yourself: a DNS server that records every lookup under a domain you
 * control, and an HTTP server that records every request to it. Both are
 * read-only recorders -- the DNS server answers with an address you give it
 * and nothing else, and the HTTP server answers 200 with a fixed body.
 *
 * **Correlation is the whole design.** Every payload embeds a token this
 * process minted. An interaction whose token was never minted is noise from
 * the internet at large and is dropped rather than reported, which is what
 * stops a public listener producing phantom findings.
 */

import { createServer as createHttpServer, type Server } from 'node:http';
import { createSocket, type Socket } from 'node:dgram';
import { randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';

export type InteractionKind = 'dns' | 'http';

export interface Interaction {
  readonly kind: InteractionKind;
  /** The token that correlates this back to a payload. */
  readonly token: string;
  /** The full name looked up, or the path requested. */
  readonly target: string;
  /** Where the connection came from. For DNS this is the resolver, not the target. */
  readonly remoteAddress: string;
  readonly at: number;
  /** DNS query type, or HTTP method. */
  readonly detail: string;
  /** HTTP only: headers and body, which is how exfiltrated data arrives. */
  readonly headers?: readonly (readonly [string, string])[];
  readonly body?: string;
}

export interface OobOptions {
  /** The domain whose subdomains are tokens, e.g. `oob.example.com`. */
  readonly domain: string;
  /** Address to answer DNS queries with. Usually this host's public address. */
  readonly answerAddress?: string;
  readonly httpPort?: number;
  readonly dnsPort?: number;
  readonly host?: string;
  readonly onInteraction?: (interaction: Interaction) => void;
  /** Record interactions whose token was never minted. Off by default. */
  readonly recordUnknown?: boolean;
}

/** A minted token and the places a payload can put it. */
export interface Canary {
  readonly token: string;
  /** `<token>.oob.example.com` */
  readonly hostname: string;
  /** `http://<token>.oob.example.com/` */
  readonly url: string;
  /** A path on the listener, for when only a path can be injected. */
  readonly path: string;
  readonly mintedAt: number;
  /** What this canary was minted for, so a finding can say. */
  readonly purpose: string;
}

/**
 * Tokens are 10 lowercase base32 characters.
 *
 * Long enough that nothing guesses one, short enough to fit in a DNS label
 * with room for a prefix, and restricted to characters that survive a
 * hostname, a URL path, an XML entity and a SQL string without escaping --
 * which is the point, because the token has to travel through whatever
 * mangles the payload.
 */
const ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

/** What a token looks like, used to recognise one before checking the ledger. */
const TOKEN_SHAPE = /^[a-z2-7]{10}$/;

export function mintToken(): string {
  const bytes = randomBytes(10);
  let out = '';
  for (const b of bytes) out += ALPHABET[b % ALPHABET.length] as string;
  return out;
}

export class OobListener extends EventEmitter {
  private readonly options: OobOptions;
  private readonly minted = new Map<string, Canary>();
  private readonly interactions: Interaction[] = [];
  private http: Server | undefined;
  private dns: Socket | undefined;
  private httpBound = 0;
  private dnsBound = 0;
  /** Interactions dropped because their token was unknown. */
  unknownDropped = 0;

  constructor(options: OobOptions) {
    super();
    this.options = options;
  }

  /** Mint a canary. Nothing is recorded for a token that was not minted. */
  mint(purpose: string): Canary {
    const token = mintToken();
    const canary: Canary = {
      token,
      hostname: `${token}.${this.options.domain}`,
      url: `http://${token}.${this.options.domain}/`,
      path: `/${token}`,
      mintedAt: Date.now(),
      purpose,
    };
    this.minted.set(token, canary);
    return canary;
  }

  canaryFor(token: string): Canary | undefined {
    return this.minted.get(token);
  }

  /** Every interaction seen so far, in arrival order. */
  all(): readonly Interaction[] {
    return this.interactions;
  }

  /** Interactions for one token. The question an active check asks. */
  forToken(token: string): Interaction[] {
    return this.interactions.filter((i) => i.token === token);
  }

  /**
   * Wait for an interaction on a token.
   *
   * Resolves with whatever arrived by the deadline, including nothing. A
   * blind test's negative result is as important as its positive one, and a
   * function that throws on timeout makes the caller treat "no callback" as
   * an error rather than as the answer.
   */
  async wait(token: string, timeoutMs = 10_000): Promise<Interaction[]> {
    const existing = this.forToken(token);
    if (existing.length > 0) return existing;

    return new Promise<Interaction[]>((resolve) => {
      const timer = setTimeout(() => {
        this.off('interaction', onInteraction);
        resolve(this.forToken(token));
      }, timeoutMs);
      timer.unref();

      const onInteraction = (interaction: Interaction): void => {
        if (interaction.token !== token) return;
        clearTimeout(timer);
        this.off('interaction', onInteraction);
        resolve(this.forToken(token));
      };
      this.on('interaction', onInteraction);
    });
  }

  private record(interaction: Interaction): void {
    if (!this.minted.has(interaction.token) && this.options.recordUnknown !== true) {
      this.unknownDropped += 1;
      return;
    }
    this.interactions.push(interaction);
    this.options.onInteraction?.(interaction);
    this.emit('interaction', interaction);
  }

  async listen(): Promise<{ httpPort: number; dnsPort: number }> {
    const host = this.options.host ?? '0.0.0.0';

    this.http = createHttpServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => {
        // A body is how exfiltrated data arrives, and it is also how somebody
        // fills this process's memory. Capped.
        if (chunks.reduce((n, b) => n + b.length, 0) < 64 * 1024) chunks.push(c);
      });
      req.on('end', () => {
        const hostHeader = (req.headers.host ?? '').split(':')[0] ?? '';
        const path = req.url ?? '/';
        const token = this.tokenFrom(hostHeader, path);
        if (token !== undefined) {
          this.record({
            kind: 'http',
            token,
            target: `${hostHeader}${path}`,
            remoteAddress: req.socket.remoteAddress ?? 'unknown',
            at: Date.now(),
            detail: req.method ?? 'GET',
            headers: pairsFrom(req.rawHeaders),
            body: Buffer.concat(chunks).toString('utf8'),
          });
        }
        // The same answer every time: a recorder that varies its response is
        // a side channel and an invitation to use this as an open redirect.
        res.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'no-store' });
        res.end('appsec-workbench out-of-band listener\n');
      });
    });

    await new Promise<void>((resolve, reject) => {
      this.http?.once('error', reject);
      this.http?.listen(this.options.httpPort ?? 8081, host, () => {
        this.http?.removeListener('error', reject);
        resolve();
      });
    });
    const httpAddress = this.http.address();
    this.httpBound = typeof httpAddress === 'object' && httpAddress !== null ? httpAddress.port : 0;

    this.dns = createSocket('udp4');
    this.dns.on('message', (message, remote) => {
      const query = parseDnsQuery(message);
      if (query === undefined) return;
      const token = this.tokenFrom(query.name, '');
      if (token !== undefined) {
        this.record({
          kind: 'dns',
          token,
          target: query.name,
          remoteAddress: remote.address,
          at: Date.now(),
          detail: query.typeName,
        });
      }
      const answer = buildDnsAnswer(message, query, this.options.answerAddress);
      if (answer !== undefined) this.dns?.send(answer, remote.port, remote.address);
    });

    await new Promise<void>((resolve, reject) => {
      this.dns?.once('error', reject);
      this.dns?.bind(this.options.dnsPort ?? 5353, host, () => {
        this.dns?.removeListener('error', reject);
        resolve();
      });
    });
    const dnsAddress = this.dns.address();
    this.dnsBound = dnsAddress.port;

    return { httpPort: this.httpBound, dnsPort: this.dnsBound };
  }

  get ports(): { httpPort: number; dnsPort: number } {
    return { httpPort: this.httpBound, dnsPort: this.dnsBound };
  }

  async close(): Promise<void> {
    this.http?.closeAllConnections?.();
    await new Promise<void>((resolve) => {
      if (this.http === undefined) {
        resolve();
        return;
      }
      this.http.close(() => resolve());
    });
    await new Promise<void>((resolve) => {
      if (this.dns === undefined) {
        resolve();
        return;
      }
      this.dns.close(() => resolve());
    });
  }

  /**
   * Pull the candidate token out of a hostname or a path.
   *
   * Accepts the token as any label of the name, not only the first, because
   * payloads frequently end up with a prefix attached -- a library that
   * prepends `www.`, or an XXE that resolves `file://<token>.domain/x`.
   *
   * Whether the token was actually minted is deliberately *not* decided here.
   * This returns anything token-shaped and `record` drops what it does not
   * recognise, so that the count of dropped interactions is real and so that
   * `recordUnknown` has something to turn on.
   */
  private tokenFrom(hostname: string, path: string): string | undefined {
    const domain = this.options.domain.toLowerCase();
    const host = hostname.toLowerCase();
    if (host.endsWith(domain)) {
      const prefix = host.slice(0, Math.max(0, host.length - domain.length - 1));
      const labels = prefix.split('.').filter((l) => l.length > 0);
      // A minted label wins over a merely token-shaped one, so `www.<token>`
      // and `<token>.www` both correlate.
      for (const label of labels) {
        if (this.minted.has(label)) return label;
      }
      for (const label of labels) {
        if (TOKEN_SHAPE.test(label)) return label;
      }
    }
    const fromPath = /^\/([a-z2-7]{10})(?:\/|$|\?)/.exec(path);
    if (fromPath !== null) return fromPath[1] as string;
    return undefined;
  }
}

function pairsFrom(raw: readonly string[]): [string, string][] {
  const out: [string, string][] = [];
  for (let i = 0; i + 1 < raw.length; i += 2) out.push([raw[i] as string, raw[i + 1] as string]);
  return out;
}

// ---- just enough DNS ------------------------------------------------------

export interface DnsQuery {
  readonly name: string;
  readonly type: number;
  readonly typeName: string;
  /** Offset just past the question section. */
  readonly end: number;
}

const TYPE_NAMES: Record<number, string> = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  12: 'PTR',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
  33: 'SRV',
  255: 'ANY',
};

/**
 * Parse the question from a DNS query.
 *
 * Deliberately minimal: we need the name and the type, and we need to not
 * crash on a malformed packet from the internet. Compression pointers cannot
 * appear in a question's name, so they are not handled -- a packet that uses
 * one is rejected rather than followed.
 */
export function parseDnsQuery(message: Buffer): DnsQuery | undefined {
  if (message.length < 12) return undefined;
  const questionCount = message.readUInt16BE(4);
  if (questionCount < 1) return undefined;

  const labels: string[] = [];
  let at = 12;
  for (;;) {
    if (at >= message.length) return undefined;
    const length = message[at] as number;
    if (length === 0) {
      at += 1;
      break;
    }
    if ((length & 0xc0) !== 0) return undefined; // a pointer: not valid here
    at += 1;
    if (at + length > message.length) return undefined;
    labels.push(message.subarray(at, at + length).toString('latin1'));
    at += length;
    if (labels.length > 64) return undefined;
  }
  if (at + 4 > message.length) return undefined;
  const type = message.readUInt16BE(at);
  return {
    name: labels.join('.'),
    type,
    typeName: TYPE_NAMES[type] ?? `TYPE${type}`,
    end: at + 4,
  };
}

/**
 * Build a reply.
 *
 * An A query gets the configured address so that a target which resolves the
 * name then connects to the HTTP listener, which turns one DNS interaction
 * into two and confirms the request was actually made rather than merely
 * resolved. Everything else gets NOERROR with no answers: enough to stop the
 * resolver retrying, and nothing a caller can use.
 */
export function buildDnsAnswer(
  message: Buffer,
  query: DnsQuery | undefined,
  answerAddress: string | undefined,
): Buffer | undefined {
  if (query === undefined || message.length < 12) return undefined;

  const header = Buffer.alloc(12);
  message.copy(header, 0, 0, 12);
  header.writeUInt16BE(0x8180, 2); // response, recursion available
  header.writeUInt16BE(1, 4); // one question
  header.writeUInt16BE(0, 6); // answers, set below
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);

  const question = message.subarray(12, query.end);

  if (query.type !== 1 || answerAddress === undefined) {
    return Buffer.concat([header, question]);
  }

  const octets = answerAddress.split('.').map((o) => Number(o));
  if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
    return Buffer.concat([header, question]);
  }

  const answer = Buffer.alloc(16);
  answer.writeUInt16BE(0xc00c, 0); // pointer to the name in the question
  answer.writeUInt16BE(1, 2); // A
  answer.writeUInt16BE(1, 4); // IN
  answer.writeUInt32BE(30, 6); // short TTL: the next lookup should reach us too
  answer.writeUInt16BE(4, 10);
  for (let i = 0; i < 4; i += 1) answer[12 + i] = octets[i] as number;

  header.writeUInt16BE(1, 6);
  return Buffer.concat([header, question, answer]);
}

/** Encode a query, used by the test suite and by `awb oob test`. */
export function buildDnsQuery(name: string, id = 0x1234, type = 1): Buffer {
  const labels = name.split('.').filter((l) => l.length > 0);
  const nameLength = labels.reduce((n, l) => n + 1 + l.length, 0) + 1;
  const buf = Buffer.alloc(12 + nameLength + 4);
  buf.writeUInt16BE(id, 0);
  buf.writeUInt16BE(0x0100, 2); // standard query, recursion desired
  buf.writeUInt16BE(1, 4);
  let at = 12;
  for (const label of labels) {
    buf[at] = label.length;
    at += 1;
    buf.write(label, at, 'latin1');
    at += label.length;
  }
  buf[at] = 0;
  at += 1;
  buf.writeUInt16BE(type, at);
  buf.writeUInt16BE(1, at + 2);
  return buf;
}
