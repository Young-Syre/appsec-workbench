import { strict as assert } from 'node:assert';
import { createServer as createHttpServer, type Server } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { connect as netConnect } from 'node:net';
import { createHash } from 'node:crypto';
import { connect as tlsConnect } from 'node:tls';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test, { after, before, describe } from 'node:test';

import { Proxy } from '../src/proxy/server.js';
import { createCa, mintCert, caPaths } from '../src/proxy/ca.js';
import { parseScopeConfig } from '../src/core/scope.js';
import type { Exchange, WebSocketFrame } from '../src/core/message.js';
import type { Rule } from '../src/proxy/rules.js';
import { get as getHeader } from '../src/core/headers.js';
import { tempDir } from './helpers.js';

/** An origin server that records what it was asked and replies predictably. */
interface Origin {
  readonly port: number;
  readonly requests: { method: string; url: string; headers: string[]; body: string }[];
  close: () => Promise<void>;
}

async function httpOrigin(
  handler?: (url: string) => { status?: number; headers?: Record<string, string>; body?: string },
): Promise<Origin> {
  const requests: Origin['requests'] = [];
  const server: Server = createHttpServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      requests.push({
        method: req.method ?? '',
        url: req.url ?? '',
        headers: req.rawHeaders,
        body: Buffer.concat(chunks).toString(),
      });
      const out = handler?.(req.url ?? '') ?? {};
      res.writeHead(out.status ?? 200, {
        'content-type': 'text/html',
        ...(out.headers ?? {}),
      });
      res.end(out.body ?? '<html><body>origin</body></html>');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  return {
    port: typeof addr === 'object' && addr !== null ? addr.port : 0,
    requests,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

async function httpsOrigin(cert: string, key: string): Promise<Origin> {
  const requests: Origin['requests'] = [];
  const server = createHttpsServer({ cert, key }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      requests.push({
        method: req.method ?? '',
        url: req.url ?? '',
        headers: req.rawHeaders,
        body: Buffer.concat(chunks).toString(),
      });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"secret":"from-tls-origin"}');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  return {
    port: typeof addr === 'object' && addr !== null ? addr.port : 0,
    requests,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

/** A plain-HTTP request made the way a client configured with a proxy makes it. */
async function viaProxy(
  proxyPort: number,
  absoluteUrl: string,
  options: { method?: string; headers?: [string, string][]; body?: string } = {},
): Promise<{ status: number; headers: string; body: string }> {
  const u = new URL(absoluteUrl);
  const headers = options.headers ?? [['Host', u.host]];
  const body = options.body ?? '';
  const wire =
    `${options.method ?? 'GET'} ${absoluteUrl} HTTP/1.1\r\n` +
    headers.map(([k, v]) => `${k}: ${v}`).join('\r\n') +
    (body.length > 0 ? `\r\nContent-Length: ${body.length}` : '') +
    '\r\nConnection: close\r\n\r\n' +
    body;

  return new Promise((resolve, reject) => {
    const socket = netConnect({ host: '127.0.0.1', port: proxyPort }, () => socket.write(wire));
    const chunks: Buffer[] = [];
    socket.on('data', (c: Buffer) => chunks.push(c));
    socket.on('end', () => {
      const raw = Buffer.concat(chunks).toString('latin1');
      const split = raw.indexOf('\r\n\r\n');
      const head = raw.slice(0, split);
      resolve({
        status: Number(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(head)?.[1] ?? 0),
        headers: head,
        body: raw.slice(split + 4),
      });
    });
    socket.on('error', reject);
    socket.setTimeout(10_000, () => reject(new Error('viaProxy timed out')));
  });
}

/** CONNECT, then TLS inside the tunnel: what a browser does for https. */
async function viaConnect(
  proxyPort: number,
  host: string,
  port: number,
  path: string,
  trustedCa: string,
): Promise<{ status: number; body: string; peerIssuer: string }> {
  return new Promise((resolve, reject) => {
    const socket = netConnect({ host: '127.0.0.1', port: proxyPort }, () => {
      socket.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`);
    });

    let established = false;
    let pre = Buffer.alloc(0);

    socket.on('data', (chunk: Buffer) => {
      if (established) return;
      pre = Buffer.concat([pre, chunk]);
      const end = pre.indexOf('\r\n\r\n');
      if (end < 0) return;
      const head = pre.subarray(0, end).toString('latin1');
      if (!/^HTTP\/\d(?:\.\d)?\s+200/.test(head)) {
        reject(new Error(`CONNECT refused: ${head.split('\r\n')[0] ?? ''}`));
        return;
      }
      established = true;
      socket.removeAllListeners('data');

      const tls = tlsConnect(
        { socket, servername: host, ca: [trustedCa], rejectUnauthorized: true },
        () => {
          tls.write(`GET ${path} HTTP/1.1\r\nHost: ${host}:${port}\r\nConnection: close\r\n\r\n`);
        },
      );
      const chunks: Buffer[] = [];
      const issuer = (): string => {
        const peer = tls.getPeerCertificate();
        return typeof peer.issuer === 'object' && peer.issuer !== null
          ? String((peer.issuer as Record<string, unknown>)['CN'] ?? '')
          : '';
      };
      let seenIssuer = '';
      tls.on('secureConnect', () => {
        seenIssuer = issuer();
      });
      tls.on('data', (c: Buffer) => chunks.push(c));
      tls.on('end', () => {
        const raw = Buffer.concat(chunks).toString('latin1');
        const split = raw.indexOf('\r\n\r\n');
        resolve({
          status: Number(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(raw)?.[1] ?? 0),
          body: raw.slice(split + 4),
          peerIssuer: seenIssuer,
        });
      });
      tls.on('error', reject);
    });

    socket.on('error', reject);
    socket.setTimeout(15_000, () => reject(new Error('viaConnect timed out')));
  });
}

// ---------------------------------------------------------------------------

describe('plain HTTP through the proxy', () => {
  let origin: Origin;
  let proxy: Proxy;
  let recorded: Exchange[];
  let caDir: string;

  before(async () => {
    caDir = join(tempDir(), 'ca');
    createCa(caDir);
    origin = await httpOrigin();
    recorded = [];
    proxy = new Proxy({
      port: 0,
      scope: parseScopeConfig({ include: [`http://127.0.0.1:${origin.port}`] }),
      ca: caPaths(caDir),
      onExchange: (e) => recorded.push(e),
    });
    await proxy.listen();
  });

  after(async () => {
    await proxy.close();
    await origin.close();
  });

  test('the request reaches the origin and the response comes back', async () => {
    const out = await viaProxy(proxy.port, `http://127.0.0.1:${origin.port}/hello`);
    assert.equal(out.status, 200);
    assert.ok(out.body.includes('origin'));
    assert.equal(origin.requests.at(-1)?.url, '/hello');
  });

  test('the exchange is recorded with the absolute URL', () => {
    const last = recorded.at(-1);
    assert.ok(last);
    assert.equal(last.request.url, `http://127.0.0.1:${origin.port}/hello`);
    assert.equal(last.response?.status, 200);
    assert.equal(last.source, 'proxy');
  });

  test('the response carries the exchange id, so the capture can be found', async () => {
    const out = await viaProxy(proxy.port, `http://127.0.0.1:${origin.port}/traced`);
    const id = /x-awb-exchange: ([0-9a-f]+)/i.exec(out.headers)?.[1];
    assert.ok(id);
    assert.ok(recorded.some((e) => e.id === id));
  });

  test('a request body is forwarded and recorded', async () => {
    await viaProxy(proxy.port, `http://127.0.0.1:${origin.port}/submit`, {
      method: 'POST',
      headers: [
        ['Host', `127.0.0.1:${origin.port}`],
        ['Content-Type', 'application/json'],
      ],
      body: '{"a":1}',
    });
    assert.equal(origin.requests.at(-1)?.body, '{"a":1}');
    assert.equal(recorded.at(-1)?.request.body.toString(), '{"a":1}');
  });

  test('duplicate request headers survive the hop', async () => {
    await viaProxy(proxy.port, `http://127.0.0.1:${origin.port}/dup`, {
      headers: [
        ['Host', `127.0.0.1:${origin.port}`],
        ['X-Trace', 'one'],
        ['X-Trace', 'two'],
      ],
    });
    const raw = origin.requests.at(-1)?.headers ?? [];
    const traces: string[] = [];
    for (let i = 0; i + 1 < raw.length; i += 2) {
      if ((raw[i] as string).toLowerCase() === 'x-trace') traces.push(raw[i + 1] as string);
    }
    assert.deepEqual(traces, ['one', 'two']);
  });

  test('the hop-by-hop header the client sent is not forwarded', async () => {
    await viaProxy(proxy.port, `http://127.0.0.1:${origin.port}/hop`, {
      headers: [
        ['Host', `127.0.0.1:${origin.port}`],
        ['Proxy-Connection', 'keep-alive'],
      ],
    });
    const raw = (origin.requests.at(-1)?.headers ?? []).map((h) => h.toLowerCase());
    assert.ok(!raw.includes('proxy-connection'));
  });

  test('the recorded request has no proxy artefacts in it either', () => {
    const headers = (recorded.at(-1)?.request.headers ?? []).map(([k]) => k.toLowerCase());
    assert.ok(!headers.includes('proxy-connection'));
    assert.ok(!headers.includes('connection'));
  });
});

describe('scope is enforced at the proxy, not just in the report', () => {
  let origin: Origin;
  let proxy: Proxy;
  let tunnelled: string[];
  let recorded: Exchange[];

  before(async () => {
    const caDir = join(tempDir(), 'ca');
    createCa(caDir);
    origin = await httpOrigin();
    tunnelled = [];
    recorded = [];
    proxy = new Proxy({
      port: 0,
      scope: parseScopeConfig({
        include: [`http://127.0.0.1:${origin.port}/allowed`],
      }),
      ca: caPaths(caDir),
      onExchange: (e) => recorded.push(e),
      onTunnel: (host) => tunnelled.push(host),
    });
    await proxy.listen();
  });

  after(async () => {
    await proxy.close();
    await origin.close();
  });

  test('an in-scope path is proxied', async () => {
    const out = await viaProxy(proxy.port, `http://127.0.0.1:${origin.port}/allowed/x`);
    assert.equal(out.status, 200);
  });

  test('an out-of-scope path is refused with 403 and an explanation', async () => {
    const before = origin.requests.length;
    const out = await viaProxy(proxy.port, `http://127.0.0.1:${origin.port}/other`);
    assert.equal(out.status, 403);
    assert.match(out.body, /deny by default/);
    assert.match(out.body, /awb scope add/);
    assert.equal(origin.requests.length, before, 'nothing may reach the origin');
  });

  test('the refusal is not recorded as an exchange, because none happened', async () => {
    const before = recorded.length;
    await viaProxy(proxy.port, `http://127.0.0.1:${origin.port}/nope`);
    assert.equal(recorded.length, before);
    assert.ok(proxy.stats.blocked >= 1);
  });

  test('an out-of-scope CONNECT is tunnelled blind rather than intercepted', async () => {
    // Nothing listens on this port; the point is that the proxy does not
    // mint a certificate for it, which is observable in the tunnel callback.
    await new Promise<void>((resolve) => {
      const socket = netConnect({ host: '127.0.0.1', port: proxy.port }, () => {
        socket.write('CONNECT unrelated.example:443 HTTP/1.1\r\nHost: unrelated.example:443\r\n\r\n');
      });
      socket.on('data', () => {
        socket.destroy();
        resolve();
      });
      socket.on('error', () => resolve());
      socket.on('close', () => resolve());
      setTimeout(() => {
        socket.destroy();
        resolve();
      }, 3000).unref();
    });
    assert.ok(
      tunnelled.some((h) => h.startsWith('unrelated.example')),
      `expected a blind tunnel, saw ${JSON.stringify(tunnelled)}`,
    );
    assert.equal(proxy.stats.certsMinted, 0, 'no certificate may be minted for an out-of-scope host');
  });
});

describe('TLS is intercepted for in-scope hosts', () => {
  let origin: Origin;
  let proxy: Proxy;
  let recorded: Exchange[];
  let caDir: string;

  before(async () => {
    // The origin gets its own CA, unrelated to the proxy's, so that a client
    // trusting only the proxy's CA proves interception actually happened.
    const originCaDir = join(tempDir(), 'origin-ca');
    const originCa = createCa(originCaDir, 'test origin CA');
    const leaf = mintCert(originCa, '127.0.0.1');
    origin = await httpsOrigin(leaf.cert, leaf.key);

    caDir = join(tempDir(), 'proxy-ca');
    createCa(caDir, 'appsec-workbench test CA');
    recorded = [];
    proxy = new Proxy({
      port: 0,
      scope: parseScopeConfig({ include: [`https://127.0.0.1:${origin.port}`] }),
      ca: caPaths(caDir),
      insecureUpstream: true,
      onExchange: (e) => recorded.push(e),
    });
    await proxy.listen();
  });

  after(async () => {
    await proxy.close();
    await origin.close();
  });

  test('a client trusting only the proxy CA completes the handshake', async () => {
    const trusted = readFileSync(caPaths(caDir).caCert, 'utf8');
    const out = await viaConnect(proxy.port, '127.0.0.1', origin.port, '/api/me', trusted);
    assert.equal(out.status, 200);
    assert.equal(out.body, '{"secret":"from-tls-origin"}');
  });

  test('the certificate the client saw was issued by the workbench CA', async () => {
    const trusted = readFileSync(caPaths(caDir).caCert, 'utf8');
    const out = await viaConnect(proxy.port, '127.0.0.1', origin.port, '/api/issuer', trusted);
    assert.equal(out.peerIssuer, 'appsec-workbench test CA');
  });

  test('the decrypted exchange is recorded, body included', () => {
    const last = recorded.at(-1);
    assert.ok(last);
    assert.ok(last.request.url.startsWith(`https://127.0.0.1:${origin.port}/api/`));
    assert.equal(last.response?.body.toString(), '{"secret":"from-tls-origin"}');
  });

  test('a certificate was minted, and only one for the host', () => {
    assert.ok(proxy.stats.certsMinted >= 1);
    assert.ok(proxy.stats.certsMinted <= 2, 'the cache must not remint per request');
  });
});

describe('match-and-replace rules act on live traffic', () => {
  let origin: Origin;
  let proxy: Proxy;
  let recorded: Exchange[];

  const rules: readonly Rule[] = [
    {
      id: 'inject-auth',
      on: 'request',
      actions: [{ kind: 'set-header', name: 'Authorization', value: 'Bearer {{env:AWB_TEST_TOKEN}}' }],
    },
    {
      id: 'strip-csp',
      on: 'response',
      match: { status: [200] },
      actions: [{ kind: 'remove-header', name: 'Content-Security-Policy' }],
    },
    {
      id: 'flag-flip',
      on: 'response',
      match: { contentType: 'text/html' },
      actions: [{ kind: 'replace-body', pattern: '"beta":false', replacement: '"beta":true' }],
    },
  ];

  before(async () => {
    const caDir = join(tempDir(), 'ca');
    createCa(caDir);
    origin = await httpOrigin(() => ({
      headers: { 'content-security-policy': "default-src 'none'" },
      body: '<html><script>var flags={"beta":false};</script></html>',
    }));
    recorded = [];
    proxy = new Proxy({
      port: 0,
      scope: parseScopeConfig({ include: [`http://127.0.0.1:${origin.port}`] }),
      ca: caPaths(join(tempDir(), 'unused')),
      rules,
      env: { AWB_TEST_TOKEN: 'injected-token-value' },
      onExchange: (e) => recorded.push(e),
    });
    // The CA is only needed for CONNECT, which this group does not use.
    await proxy.listen();
  });

  after(async () => {
    await proxy.close();
    await origin.close();
  });

  test('a request rule adds a header the client never sent', async () => {
    await viaProxy(proxy.port, `http://127.0.0.1:${origin.port}/x`);
    const raw = origin.requests.at(-1)?.headers ?? [];
    const idx = raw.findIndex((h) => h.toLowerCase() === 'authorization');
    assert.ok(idx >= 0, 'the origin should have received an Authorization header');
    assert.equal(raw[idx + 1], 'Bearer injected-token-value');
  });

  test('the environment reference is resolved, not stored literally', () => {
    const header = getHeader(recorded.at(-1)?.request.headers ?? [], 'authorization');
    assert.equal(header, 'Bearer injected-token-value');
  });

  test('a response rule removes a header before the browser sees it', async () => {
    const out = await viaProxy(proxy.port, `http://127.0.0.1:${origin.port}/y`);
    assert.ok(!/content-security-policy/i.test(out.headers));
  });

  test('a response body rewrite reaches the browser', async () => {
    const out = await viaProxy(proxy.port, `http://127.0.0.1:${origin.port}/z`);
    assert.ok(out.body.includes('"beta":true'));
  });

  test('the applied rules are tagged on the exchange', () => {
    const tags = recorded.at(-1)?.tags ?? [];
    assert.ok(tags.includes('rule:inject-auth'));
    assert.ok(tags.includes('rule:flag-flip'));
  });

  test('Content-Length is corrected for the rewritten body', async () => {
    const out = await viaProxy(proxy.port, `http://127.0.0.1:${origin.port}/len`);
    const declared = Number(/content-length: (\d+)/i.exec(out.headers)?.[1] ?? -1);
    assert.equal(declared, Buffer.byteLength(out.body));
  });
});

describe('an unreachable origin is reported, not swallowed', () => {
  let proxy: Proxy;
  let recorded: Exchange[];

  before(async () => {
    recorded = [];
    proxy = new Proxy({
      port: 0,
      scope: parseScopeConfig({ include: ['http://127.0.0.1:1'] }),
      ca: caPaths(join(tempDir(), 'unused')),
      onExchange: (e) => recorded.push(e),
      timeoutMs: 3000,
    });
    await proxy.listen();
  });

  after(async () => {
    await proxy.close();
  });

  test('the client gets a 502 saying what happened', async () => {
    const out = await viaProxy(proxy.port, 'http://127.0.0.1:1/x');
    assert.equal(out.status, 502);
    assert.match(out.body, /could not reach the target/);
  });

  test('the attempt is still recorded, with its error and no response', () => {
    const last = recorded.at(-1);
    assert.ok(last);
    assert.equal(last.response, undefined);
    assert.ok((last.error ?? '').length > 0);
    assert.ok(proxy.stats.failed >= 1);
  });
});

describe('websocket frames through the proxy are decoded', () => {
  let proxy: Proxy;
  let frames: WebSocketFrame[];
  let wsServer: Server;
  let wsPort: number;
  const wsSockets: import('node:net').Socket[] = [];

  before(async () => {
    // A minimal server that completes the handshake and echoes one text frame.
    wsServer = createHttpServer();
    wsServer.on('upgrade', (req, socket) => {
      wsSockets.push(socket as import('node:net').Socket);
      const key = req.headers['sec-websocket-key'] ?? '';
      const accept = createHash('sha1')
        .update(`${String(key)}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
        .digest('base64');
      socket.write(
        'HTTP/1.1 101 Switching Protocols\r\n' +
          'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
          `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
      );
      socket.on('data', () => {
        // Reply with an unmasked text frame: 0x81, length, payload.
        const payload = Buffer.from('{"from":"server"}');
        socket.write(Buffer.concat([Buffer.from([0x81, payload.length]), payload]));
      });
    });
    await new Promise<void>((resolve) => wsServer.listen(0, '127.0.0.1', resolve));
    const addr = wsServer.address();
    wsPort = typeof addr === 'object' && addr !== null ? addr.port : 0;

    frames = [];
    proxy = new Proxy({
      port: 0,
      scope: parseScopeConfig({ include: [`http://127.0.0.1:${wsPort}`] }),
      ca: caPaths(join(tempDir(), 'unused')),
      onFrame: (f) => frames.push(f),
    });
    await proxy.listen();
  });

  after(async () => {
    await proxy.close();
    for (const s of wsSockets) s.destroy();
    wsServer.closeAllConnections?.();
    await new Promise<void>((resolve) => wsServer.close(() => resolve()));
  });

  test('frames in both directions are decoded and unmasked', async () => {
    await new Promise<void>((resolve, reject) => {
      const socket = netConnect({ host: '127.0.0.1', port: proxy.port }, () => {
        socket.write(
          `GET http://127.0.0.1:${wsPort}/ws HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${wsPort}\r\n` +
            'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
            'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n',
        );
      });

      let upgraded = false;
      socket.on('data', (chunk: Buffer) => {
        if (!upgraded && chunk.toString('latin1').includes('101')) {
          upgraded = true;
          // A masked client text frame, as the protocol requires from a client.
          const payload = Buffer.from('{"from":"client"}');
          const mask = Buffer.from([1, 2, 3, 4]);
          const masked = Buffer.allocUnsafe(payload.length);
          for (let i = 0; i < payload.length; i += 1) {
            masked[i] = (payload[i] as number) ^ (mask[i % 4] as number);
          }
          socket.write(
            Buffer.concat([Buffer.from([0x81, 0x80 | payload.length]), mask, masked]),
          );
          return;
        }
        if (upgraded) {
          setTimeout(() => {
            socket.destroy();
            resolve();
          }, 150).unref();
        }
      });
      socket.on('error', reject);
      setTimeout(() => {
        socket.destroy();
        resolve();
      }, 6000).unref();
    });

    const sent = frames.filter((f) => f.direction === 'sent');
    const received = frames.filter((f) => f.direction === 'received');
    assert.ok(sent.length >= 1, `expected a client frame, saw ${frames.length} frames`);
    assert.equal(sent[0]?.payload.toString(), '{"from":"client"}');
    assert.ok(received.length >= 1, 'expected a server frame');
    assert.equal(received[0]?.payload.toString(), '{"from":"server"}');
    assert.ok(proxy.stats.frames >= 2);
  });
});
