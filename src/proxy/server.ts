/**
 * The intercepting proxy.
 *
 * Three behaviours worth knowing before reading the code.
 *
 * **Out of scope means out of sight.** A CONNECT to a host scope has not
 * cleared is tunnelled blind: no certificate is minted for it, its TLS is
 * never terminated, and nothing about it is recorded. Burp decrypts
 * everything and then filters the display, which means a project file
 * contains the operator's own webmail if they left the proxy on. Declining to
 * decrypt is both the safer default and the easier thing to justify when
 * somebody asks what the capture contains.
 *
 * **What is recorded is what was on the wire.** The exchange stored is the
 * upstream request and the upstream response, compressed bodies and all.
 * What is handed back to the browser may be normalised -- hop-by-hop headers
 * dropped, framing recomputed -- because the browser needs a message it can
 * parse. The two are kept separate on purpose: the evidence is the former.
 *
 * **It listens on loopback.** Binding a MITM proxy to 0.0.0.0 offers anyone
 * on the network a man in the middle for every host in scope. Overriding that
 * is possible and says so loudly.
 */

import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import {
  Server as TlsServer,
  createSecureContext,
  connect as tlsConnect,
  type TLSSocket,
} from 'node:tls';
import { connect as netConnect, type Socket } from 'node:net';
import { EventEmitter } from 'node:events';

import {
  type HeaderList,
  fromRawHeaders,
  get as getHeader,
  isHopByHop,
  remove as removeHeader,
  set as setHeader,
  toRawHeaders,
} from '../core/headers.js';
import {
  type Exchange,
  type HttpRequest,
  type HttpResponse,
  exchangeId,
} from '../core/message.js';
import { type ScopeConfig, decide } from '../core/scope.js';
import { type Rule, applyRequestRules, applyResponseRules } from './rules.js';
import { CertCache, type CaPaths, ensureCa } from './ca.js';
import { FrameReader, isWebSocketUpgrade } from './websocket.js';
import { send } from '../net/send.js';
import type { Interceptor } from './intercept.js';
import type { WebSocketFrame } from '../core/message.js';

export interface ProxyOptions {
  readonly port?: number;
  /** Defaults to loopback. Anything else is a decision, not a default. */
  readonly host?: string;
  readonly scope: ScopeConfig;
  readonly ca: CaPaths | string;
  readonly rules?: readonly Rule[];
  /** Called for every recorded exchange. */
  readonly onExchange?: (exchange: Exchange) => void;
  readonly onFrame?: (frame: WebSocketFrame) => void;
  /** Called for traffic that was tunnelled without interception. */
  readonly onTunnel?: (host: string, reason: string) => void;
  readonly onError?: (err: Error, context: string) => void;
  /**
   * Hold in-scope messages for a person to forward, edit or drop. Without
   * one, nothing waits.
   */
  readonly interceptor?: Interceptor;
  /** Do not verify upstream TLS. For a target with a self-signed certificate. */
  readonly insecureUpstream?: boolean;
  readonly maxBodyBytes?: number;
  readonly timeoutMs?: number;
  readonly env?: NodeJS.ProcessEnv;
}

export interface ProxyStats {
  recorded: number;
  tunnelled: number;
  blocked: number;
  failed: number;
  frames: number;
  certsMinted: number;
  /** Requests the operator dropped at the intercept, so never sent. */
  dropped: number;
}

const CONNECT_HOST = Symbol('awb.connectHost');

interface TaggedSocket extends Socket {
  [CONNECT_HOST]?: string;
}

export class Proxy extends EventEmitter {
  private readonly options: ProxyOptions;
  private readonly certs: CertCache;
  private readonly outer: Server;
  private readonly inner: Server;
  private readonly tls: TlsServer;
  private readonly sockets = new Set<Socket>();
  readonly stats: ProxyStats = {
    recorded: 0,
    tunnelled: 0,
    blocked: 0,
    failed: 0,
    frames: 0,
    certsMinted: 0,
    dropped: 0,
  };
  private listeningPort = 0;

  constructor(options: ProxyOptions) {
    super();
    this.options = options;
    const paths = typeof options.ca === 'string' ? ensureCa(options.ca) : options.ca;
    this.certs = new CertCache(paths);

    // The inner server handles requests after TLS has been terminated.
    this.inner = createHttpServer((req, res) => {
      void this.handle(req, res, true);
    });
    this.inner.on('upgrade', (req, socket, head) => {
      this.handleUpgrade(req, socket as Socket, head, true);
    });
    this.inner.on('clientError', (err, socket) => {
      this.options.onError?.(err as Error, 'inner clientError');
      (socket as Socket).destroy();
    });

    this.tls = new TlsServer({
      SNICallback: (servername, cb) => {
        try {
          const pair = this.certs.for(servername);
          this.stats.certsMinted = this.certs.minted;
          cb(null, createSecureContext({ cert: pair.cert, key: pair.key }));
        } catch (err) {
          cb(err as Error);
        }
      },
    });
    this.tls.on('secureConnection', (tlsSocket: TLSSocket) => {
      const host = (tlsSocket as unknown as { _parent?: TaggedSocket })._parent?.[CONNECT_HOST];
      if (host !== undefined) (tlsSocket as unknown as TaggedSocket)[CONNECT_HOST] = host;
      this.inner.emit('connection', tlsSocket);
    });
    this.tls.on('tlsClientError', (err) => {
      // A browser probing for HTTP/2 or abandoning a handshake is routine.
      this.options.onError?.(err as Error, 'tlsClientError');
    });

    this.outer = createHttpServer((req, res) => {
      void this.handle(req, res, false);
    });
    this.outer.on('connect', (req, socket, head) => {
      this.handleConnect(req, socket as Socket, head);
    });
    this.outer.on('upgrade', (req, socket, head) => {
      this.handleUpgrade(req, socket as Socket, head, false);
    });
    this.outer.on('connection', (socket) => {
      this.sockets.add(socket);
      socket.on('close', () => this.sockets.delete(socket));
    });
    this.outer.on('clientError', (err, socket) => {
      this.options.onError?.(err as Error, 'clientError');
      (socket as Socket).destroy();
    });
  }

  async listen(): Promise<number> {
    const host = this.options.host ?? '127.0.0.1';
    const port = this.options.port ?? 8080;
    await new Promise<void>((resolve, reject) => {
      this.outer.once('error', reject);
      this.outer.listen(port, host, () => {
        this.outer.removeListener('error', reject);
        resolve();
      });
    });
    const address = this.outer.address();
    this.listeningPort = typeof address === 'object' && address !== null ? address.port : port;
    return this.listeningPort;
  }

  get port(): number {
    return this.listeningPort;
  }

  /**
   * Shut down, and do not wait politely.
   *
   * A proxy's sockets include hijacked upgrades and blind tunnels, neither of
   * which a graceful `server.close()` can drain -- it waits for connections
   * that are, by design, open until somebody closes them. So every tracked
   * socket is destroyed first and each close is bounded, which is the
   * difference between a test suite that exits and one that hangs.
   */
  async close(): Promise<void> {
    // Anything parked at the intercept is released first, so its handler
    // runs to completion against a socket that is about to go, rather than
    // waiting on a decision nobody will now make.
    this.options.interceptor?.releaseAll();
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    this.outer.closeAllConnections?.();
    this.inner.closeAllConnections?.();
    await Promise.all([closeServer(this.outer), closeServer(this.inner)]);
  }

  // ---- CONNECT -----------------------------------------------------------

  private handleConnect(req: IncomingMessage, socket: Socket, head: Buffer): void {
    const target = req.url ?? '';
    const [rawHost, rawPort] = splitAuthority(target);
    if (rawHost === undefined) {
      socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
      return;
    }
    const port = rawPort ?? 443;
    // Scope is asked about the origin the tunnel is for. A path is not known
    // yet, so a rule with a path cannot decide here; the inner handler checks
    // again once the request line is visible.
    const verdict = decide(this.options.scope, `https://${rawHost}:${port}/`);

    if (verdict.verdict !== 'in-scope') {
      this.tunnel(socket, head, rawHost, port, verdict.reason);
      return;
    }

    socket.on('error', (err) => this.options.onError?.(err, 'connect socket'));
    socket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: appsec-workbench\r\n\r\n');
    (socket as TaggedSocket)[CONNECT_HOST] = `${rawHost}:${port}`;
    if (head.length > 0) socket.unshift(head);
    this.tls.emit('connection', socket);
  }

  /**
   * Pass bytes through without looking at them.
   *
   * No certificate is minted, so the client sees the real one and TLS is
   * end-to-end. Nothing is recorded beyond the fact that a tunnel existed.
   */
  private tunnel(socket: Socket, head: Buffer, host: string, port: number, reason: string): void {
    this.stats.tunnelled += 1;
    this.options.onTunnel?.(`${host}:${port}`, reason);
    const upstream = netConnect({ host, port }, () => {
      socket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: appsec-workbench\r\n\r\n');
      if (head.length > 0) upstream.write(head);
      socket.pipe(upstream);
      upstream.pipe(socket);
    });
    this.sockets.add(upstream);
    upstream.on('close', () => this.sockets.delete(upstream));
    upstream.on('error', () => socket.destroy());
    socket.on('error', () => upstream.destroy());
  }

  // ---- requests ----------------------------------------------------------

  private async handle(
    req: IncomingMessage,
    res: ServerResponse,
    secure: boolean,
  ): Promise<void> {
    const url = this.absoluteUrl(req, secure);
    if (url === undefined) {
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end('appsec-workbench: could not determine the target of this request\n');
      return;
    }

    const verdict = decide(this.options.scope, url);
    if (verdict.verdict !== 'in-scope') {
      this.stats.blocked += 1;
      res.writeHead(403, { 'content-type': 'text/plain', 'x-awb-scope': verdict.verdict });
      res.end(
        `appsec-workbench refused this request.\n\n  ${url}\n  ${verdict.reason}\n\n` +
          'Scope is deny by default. Add the host with `awb scope add` if you are\n' +
          'authorised to test it.\n',
      );
      return;
    }

    let body: Buffer;
    try {
      body = await readBody(req, this.options.maxBodyBytes ?? 32 * 1024 * 1024);
    } catch (err) {
      this.stats.failed += 1;
      res.writeHead(413, { 'content-type': 'text/plain' });
      res.end(`appsec-workbench: ${(err as Error).message}\n`);
      return;
    }

    const captured: HttpRequest = {
      method: req.method ?? 'GET',
      url,
      httpVersion: req.httpVersion,
      headers: proxyCleanHeaders(fromRawHeaders(req.rawHeaders)),
      body,
      startedAt: Date.now(),
    };

    const { message: ruled, applied } = applyRequestRules(
      this.options.rules ?? [],
      captured,
      this.options.env,
    );

    // The client's connection, as a signal: a request held at the intercept
    // for a browser that has hung up should leave the queue, not wait there.
    const clientGone = new AbortController();
    res.on('close', () => {
      if (!res.writableFinished) clientGone.abort();
    });

    const interceptTags: string[] = [];
    let request = ruled;
    const interceptor = this.options.interceptor;
    if (interceptor !== undefined) {
      const decision = await interceptor.holdRequest(ruled, clientGone.signal);
      if (decision.by === 'timeout') interceptTags.push('intercept:timeout');
      if (decision.action === 'drop') {
        if (decision.by !== 'abandoned') this.stats.dropped += 1;
        if (!res.headersSent && !res.destroyed) {
          res.writeHead(502, { 'content-type': 'text/plain', 'x-awb-intercept': 'dropped' });
          res.end('appsec-workbench: the request was dropped at the intercept and never sent.\n');
        }
        return;
      }
      if (decision.request !== undefined) {
        // An edit can change the target. The edited request is a new request
        // as far as scope is concerned, and is asked about as one.
        const edited = decide(this.options.scope, decision.request.url);
        if (edited.verdict !== 'in-scope') {
          this.stats.blocked += 1;
          res.writeHead(403, { 'content-type': 'text/plain', 'x-awb-scope': edited.verdict });
          res.end(
            `appsec-workbench refused the edited request.\n\n  ${decision.request.url}\n  ${edited.reason}\n`,
          );
          return;
        }
        request = decision.request;
        interceptTags.push('intercept:edited');
      }
      if (res.destroyed) return;
    }

    const result = await send(request, {
      timeoutMs: this.options.timeoutMs ?? 30_000,
      ...(this.options.insecureUpstream === true ? { insecure: true } : {}),
      maxBodyBytes: this.options.maxBodyBytes ?? 32 * 1024 * 1024,
    });

    const id = exchangeId(request, String(this.stats.recorded));

    if (result.response === undefined) {
      this.stats.failed += 1;
      const exchange: Exchange = {
        id,
        request,
        error: result.error ?? 'the request failed for an unstated reason',
        source: 'proxy',
        tags: [...tagsFor(applied), ...interceptTags],
      };
      this.options.onExchange?.(exchange);
      this.emit('exchange', exchange);
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'text/plain', 'x-awb-exchange': id });
        res.end(`appsec-workbench could not reach the target.\n\n  ${result.error ?? ''}\n`);
      }
      return;
    }

    const { message: response, applied: responseApplied } = applyResponseRules(
      this.options.rules ?? [],
      request,
      result.response,
      this.options.env,
    );

    // The response can be held too. What is recorded is the response as it
    // arrived; an edit changes only what the browser is handed, and the tag
    // says so, because the evidence is the upstream bytes.
    let delivered = response;
    if (interceptor !== undefined && !res.destroyed) {
      const decision = await interceptor.holdResponse(request, response, clientGone.signal);
      if (decision.by === 'timeout') interceptTags.push('intercept:response-timeout');
      if (decision.action === 'drop') {
        interceptTags.push('intercept:response-dropped');
      } else if (decision.response !== undefined) {
        delivered = decision.response;
        interceptTags.push('intercept:response-edited');
      }
    }

    const exchange: Exchange = {
      id,
      request,
      response,
      source: 'proxy',
      tags: [
        ...tagsFor(applied),
        ...tagsFor(responseApplied),
        ...interceptTags,
        ...result.notes.map((n) => `note:${n}`),
      ],
    };
    this.stats.recorded += 1;
    this.options.onExchange?.(exchange);
    this.emit('exchange', exchange);

    if (interceptTags.includes('intercept:response-dropped')) {
      // A dropped response is a connection the browser sees fail. The
      // exchange is still recorded: the request was sent and this came back.
      res.destroy();
      return;
    }
    this.writeResponse(res, delivered, id);
  }

  /**
   * Hand the response to the browser.
   *
   * Hop-by-hop headers go, and the framing is recomputed from the body we
   * actually hold. The stored exchange keeps the originals; this copy only
   * has to be parseable.
   */
  private writeResponse(res: ServerResponse, response: HttpResponse, id: string): void {
    let headers: HeaderList = response.headers.filter(([k]) => !isHopByHop(k));
    headers = removeHeader(headers, 'content-length');
    headers = setHeader(headers, 'content-length', String(response.body.length));
    headers = setHeader(headers, 'x-awb-exchange', id);
    try {
      res.writeHead(response.status, response.statusText || undefined, toRawHeaders(headers));
      res.end(response.body);
    } catch (err) {
      this.options.onError?.(err as Error, 'writing response');
      res.destroy();
    }
  }

  // ---- websockets --------------------------------------------------------

  private handleUpgrade(
    req: IncomingMessage,
    socket: Socket,
    head: Buffer,
    secure: boolean,
  ): void {
    const url = this.absoluteUrl(req, secure);
    if (url === undefined || decide(this.options.scope, url).verdict !== 'in-scope') {
      this.stats.blocked += 1;
      socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
      return;
    }

    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
      return;
    }

    const port = Number(parsed.port || (secure ? 443 : 80));
    const upstream: Socket = secure
      ? tlsConnect({
          host: parsed.hostname,
          port,
          servername: parsed.hostname,
          rejectUnauthorized: this.options.insecureUpstream !== true,
        })
      : netConnect({ host: parsed.hostname, port });

    // Tracked so that close() can tear a live tunnel down; an upgrade's
    // upstream socket never passes through the server's connection event.
    this.sockets.add(upstream);
    upstream.on('close', () => this.sockets.delete(upstream));

    const requestHeaders = proxyCleanKeepUpgrade(fromRawHeaders(req.rawHeaders));
    const id = exchangeId(
      {
        method: req.method ?? 'GET',
        url,
        httpVersion: req.httpVersion,
        headers: requestHeaders,
        body: Buffer.alloc(0),
        startedAt: Date.now(),
      },
      `ws${this.stats.recorded}`,
    );

    const wire =
      `${req.method ?? 'GET'} ${parsed.pathname}${parsed.search} HTTP/1.1\r\n` +
      requestHeaders.map(([k, v]) => `${k}: ${v}`).join('\r\n') +
      '\r\n\r\n';

    const fromClient = new FrameReader();
    const fromServer = new FrameReader();
    let handshakeDone = false;
    let pendingServer = Buffer.alloc(0);

    upstream.on('connect', () => {
      upstream.write(wire);
      if (head.length > 0) upstream.write(head);
    });
    upstream.on('secureConnect', () => {
      upstream.write(wire);
      if (head.length > 0) upstream.write(head);
    });

    upstream.on('data', (chunk: Buffer) => {
      if (!handshakeDone) {
        pendingServer = Buffer.concat([pendingServer, chunk]);
        const end = pendingServer.indexOf('\r\n\r\n', 0, 'latin1');
        if (end < 0) return;
        const headText = pendingServer.subarray(0, end).toString('latin1');
        socket.write(pendingServer.subarray(0, end + 4));
        const rest = pendingServer.subarray(end + 4);
        pendingServer = Buffer.alloc(0);
        handshakeDone = true;

        const statusMatch = /^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(headText);
        const status = statusMatch ? Number(statusMatch[1]) : 0;
        const responseHeaders = headText
          .split(/\r?\n/)
          .slice(1)
          .flatMap((line): [string, string][] => {
            const i = line.indexOf(':');
            return i < 0 ? [] : [[line.slice(0, i), line.slice(i + 1).replace(/^ /, '')]];
          });
        if (!isWebSocketUpgrade(status, responseHeaders)) {
          // Not an upgrade after all: let the bytes flow and stop decoding.
          socket.write(rest);
          socket.pipe(upstream);
          upstream.pipe(socket);
          return;
        }
        this.emit('websocket-open', { id, url });
        if (rest.length > 0) this.recordFrames(id, 'received', fromServer.push(rest));
        return;
      }
      socket.write(chunk);
      this.recordFrames(id, 'received', fromServer.push(chunk));
    });

    socket.on('data', (chunk: Buffer) => {
      upstream.write(chunk);
      if (handshakeDone) this.recordFrames(id, 'sent', fromClient.push(chunk));
    });

    const shutdown = (): void => {
      socket.destroy();
      upstream.destroy();
    };
    socket.on('error', shutdown);
    upstream.on('error', shutdown);
    socket.on('close', shutdown);
    upstream.on('close', shutdown);
  }

  private recordFrames(
    exchangeId_: string,
    direction: 'sent' | 'received',
    messages: readonly { opcode: string; payload: Buffer }[],
  ): void {
    for (const m of messages) {
      if (m.opcode === 'continuation' || m.opcode === 'reserved') continue;
      this.stats.frames += 1;
      const frame: WebSocketFrame = {
        exchangeId: exchangeId_,
        direction,
        opcode: m.opcode as WebSocketFrame['opcode'],
        payload: m.payload,
        at: Date.now(),
      };
      this.options.onFrame?.(frame);
      this.emit('frame', frame);
    }
  }

  // ---- helpers -----------------------------------------------------------

  /**
   * Reconstruct the absolute URL.
   *
   * A plain-HTTP proxy request carries it already. After TLS termination the
   * request line is origin-form, so the authority comes from the CONNECT that
   * opened the tunnel, and the Host header is only a fallback -- preferring
   * Host would let a request retarget itself to another host inside somebody
   * else's tunnel.
   */
  private absoluteUrl(req: IncomingMessage, secure: boolean): string | undefined {
    const target = req.url ?? '';
    if (/^https?:\/\//i.test(target)) return target;

    const tagged = (req.socket as unknown as TaggedSocket)[CONNECT_HOST];
    const authority = tagged ?? getHeader(fromRawHeaders(req.rawHeaders), 'host');
    if (authority === undefined) return undefined;
    const scheme = secure ? 'https' : 'http';
    try {
      return new URL(target, `${scheme}://${authority}`).toString();
    } catch {
      return undefined;
    }
  }
}

function splitAuthority(authority: string): [string | undefined, number | undefined] {
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    if (close < 0) return [undefined, undefined];
    const host = authority.slice(0, close + 1);
    const tail = authority.slice(close + 1);
    return [host, tail.startsWith(':') ? Number(tail.slice(1)) : undefined];
  }
  const colon = authority.lastIndexOf(':');
  if (colon <= 0) return [authority.length > 0 ? authority : undefined, undefined];
  const port = Number(authority.slice(colon + 1));
  return [authority.slice(0, colon), Number.isInteger(port) ? port : undefined];
}

/**
 * Strip what belongs to the proxy hop, keep everything that belongs to the
 * request. `Proxy-Connection` is not in any RFC and is sent by real clients.
 */
function proxyCleanHeaders(headers: HeaderList): HeaderList {
  return headers.filter(([k]) => !isHopByHop(k) && k.toLowerCase() !== 'proxy-connection');
}

/** The same, but keeping the headers an upgrade needs. */
function proxyCleanKeepUpgrade(headers: HeaderList): HeaderList {
  return headers.filter(([k]) => {
    const lower = k.toLowerCase();
    if (lower === 'proxy-connection') return false;
    if (lower === 'connection' || lower === 'upgrade') return true;
    return !isHopByHop(k);
  });
}

function tagsFor(applied: readonly { ruleId: string }[]): string[] {
  return [...new Set(applied.map((a) => `rule:${a.ruleId}`))];
}

async function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    total += buf.length;
    if (total > limit) {
      throw new Error(`request body exceeded ${limit} bytes`);
    }
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
}

/** Close a server, tolerating one that never listened, and never hanging. */
async function closeServer(server: Server, capMs = 2000): Promise<void> {
  if (!server.listening) {
    // An inner server driven by emit('connection') never listened, and
    // close() on it would call back with ERR_SERVER_NOT_RUNNING.
    return;
  }
  await Promise.race([
    new Promise<void>((resolve) => server.close(() => resolve())),
    new Promise<void>((resolve) => {
      setTimeout(resolve, capMs).unref();
    }),
  ]);
}

export async function startProxy(options: ProxyOptions): Promise<Proxy> {
  const proxy = new Proxy(options);
  await proxy.listen();
  return proxy;
}
