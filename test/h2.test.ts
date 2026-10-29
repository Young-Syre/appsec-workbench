import { strict as assert } from 'node:assert';
import {
  connect as h2Connect,
  createSecureServer,
  createServer as createH2cServer,
  type Http2SecureServer,
  type Http2Server,
} from 'node:http2';
import { createServer as createHttpsServer } from 'node:https';
import { connect as netConnect } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test, { after, before, describe } from 'node:test';

import { Proxy } from '../src/proxy/server.js';
import { createCa, mintCert, caPaths } from '../src/proxy/ca.js';
import { parseScopeConfig } from '../src/core/scope.js';
import type { Exchange } from '../src/core/message.js';
import { asHttp1, send } from '../src/net/send.js';
import { isHttp2, sendH2, toH2Fields } from '../src/net/h2.js';
import { replay } from '../src/replay/replay.js';
import { get as getHeader, getAll } from '../src/core/headers.js';
import { makeRequest, tempDir } from './helpers.js';

interface Seen {
  version: string;
  method: string;
  path: string;
  raw: string[];
  body: string;
}

interface Origin {
  readonly port: number;
  readonly seen: Seen[];
  close: () => Promise<void>;
}

/** An HTTPS origin that speaks HTTP/2, and HTTP/1.1 too when `allowHTTP1`. */
async function h2Origin(cert: string, key: string, allowHTTP1 = false): Promise<Origin> {
  const seen: Seen[] = [];
  const server: Http2SecureServer = createSecureServer({ cert, key, allowHTTP1 }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      seen.push({
        version: req.httpVersion,
        method: req.method,
        path: req.url,
        raw: req.rawHeaders,
        body: Buffer.concat(chunks).toString(),
      });
      res.setHeader('content-type', 'application/json');
      res.setHeader('set-cookie', ['a=1', 'b=2']);
      res.end(JSON.stringify({ over: req.httpVersion }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  return {
    port: typeof addr === 'object' && addr !== null ? addr.port : 0,
    seen,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

/** An HTTPS origin that only speaks HTTP/1.1. */
async function h1Origin(cert: string, key: string): Promise<Origin> {
  const seen: Seen[] = [];
  const server = createHttpsServer({ cert, key }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      seen.push({
        version: req.httpVersion,
        method: req.method ?? '',
        path: req.url ?? '',
        raw: req.rawHeaders,
        body: Buffer.concat(chunks).toString(),
      });
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(`over ${req.httpVersion}`);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  return {
    port: typeof addr === 'object' && addr !== null ? addr.port : 0,
    seen,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

let leaf: { cert: string; key: string };

before(() => {
  const originCa = createCa(join(tempDir(), 'origin-ca'), 'test origin CA');
  leaf = mintCert(originCa, '127.0.0.1');
});

describe('translating a request into HTTP/2 fields', () => {
  test('pseudo-header fields come first, from the method, URL and Host', () => {
    const { fields } = toH2Fields(
      makeRequest({
        method: 'POST',
        url: 'https://target.example/a/b?c=d',
        headers: [['Host', 'target.example'], ['X-One', '1'], ['x-two', '2']],
      }),
    );
    assert.deepEqual(fields, [
      [':method', 'POST'],
      [':scheme', 'https'],
      [':authority', 'target.example'],
      [':path', '/a/b?c=d'],
      ['x-one', '1'],
      ['x-two', '2'],
    ]);
  });

  test('what HTTP/2 forbids is removed, and each removal is a note', () => {
    const { sent, notes } = toH2Fields(
      makeRequest({
        headers: [
          ['Host', 'target.example'],
          ['Connection', 'keep-alive'],
          ['Transfer-Encoding', 'chunked'],
          ['TE', 'gzip'],
          ['X-Bad', 'a\r\nb'],
          ['te', 'trailers'],
        ],
      }),
    );
    assert.deepEqual(sent.headers, [['host', 'target.example'], ['te', 'trailers']]);
    assert.equal(sent.httpVersion, '2');
    for (const name of ['Connection', 'Transfer-Encoding', 'TE: gzip', 'X-Bad']) {
      assert.ok(notes.some((n) => n.includes(name)), `no note for ${name}: ${notes.join(' | ')}`);
    }
  });

  test('a Host that disagrees with the URL is the authority, and says so', () => {
    const { fields, notes } = toH2Fields(
      makeRequest({ url: 'https://target.example/', headers: [['Host', 'other.example']] }),
    );
    assert.deepEqual(fields[2], [':authority', 'other.example']);
    assert.ok(notes.some((n) => n.includes('differs')));
  });

  test('the version decides the protocol', () => {
    assert.equal(isHttp2({ httpVersion: '2' }), true);
    assert.equal(isHttp2({ httpVersion: '2.0' }), true);
    assert.equal(isHttp2({ httpVersion: '1.1' }), false);
  });

  test('going down to HTTP/1.1 joins split cookies and changes nothing else', () => {
    const down = asHttp1(
      makeRequest({
        httpVersion: '2',
        headers: [['host', 't.example'], ['cookie', 'a=1'], ['x', 'y'], ['cookie', 'b=2']],
      }),
    );
    assert.equal(down.httpVersion, '1.1');
    assert.deepEqual(down.headers, [['host', 't.example'], ['cookie', 'a=1; b=2'], ['x', 'y']]);
  });
});

describe('sending over HTTP/2', () => {
  let origin: Origin;
  let plainOnly: Origin;
  let h2c: { port: number; server: Http2Server };

  before(async () => {
    origin = await h2Origin(leaf.cert, leaf.key);
    plainOnly = await h1Origin(leaf.cert, leaf.key);
    const server = createH2cServer((req, res) => res.end(`h2c ${req.httpVersion}`));
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address();
    h2c = { port: typeof addr === 'object' && addr !== null ? addr.port : 0, server };
  });

  after(async () => {
    await origin.close();
    await plainOnly.close();
    await new Promise<void>((resolve) => h2c.server.close(() => resolve()));
  });

  test('a request with version 2 goes out as HTTP/2 and the response is read', async () => {
    const result = await send(
      makeRequest({
        method: 'POST',
        url: `https://127.0.0.1:${origin.port}/x?y=1`,
        httpVersion: '2',
        headers: [['Host', `127.0.0.1:${origin.port}`], ['Content-Type', 'text/plain'], ['X-Order', 'kept']],
        body: Buffer.from('hello'),
      }),
      { insecure: true },
    );
    assert.equal(result.error, undefined);
    assert.equal(result.response?.status, 200);
    assert.equal(result.response?.httpVersion, '2');
    assert.equal(result.response?.body.toString(), '{"over":"2.0"}');
    assert.deepEqual(getAll(result.response?.headers ?? [], 'set-cookie'), ['a=1', 'b=2']);
    assert.ok(!(result.response?.headers ?? []).some(([k]) => k.startsWith(':')), 'no pseudo-header in the stored response');

    const hit = origin.seen.at(-1);
    assert.equal(hit?.version, '2.0');
    assert.equal(hit?.path, '/x?y=1');
    assert.equal(hit?.body, 'hello');
    assert.ok(hit !== undefined && hit.raw.indexOf('content-type') < hit.raw.indexOf('x-order'), 'order is kept');
  });

  test('the request handed back is the one that went out', async () => {
    const result = await send(
      makeRequest({
        url: `https://127.0.0.1:${origin.port}/`,
        httpVersion: '2',
        headers: [['Host', `127.0.0.1:${origin.port}`], ['Connection', 'close']],
      }),
      { insecure: true },
    );
    assert.deepEqual(result.sent?.headers, [['host', `127.0.0.1:${origin.port}`]]);
    assert.ok(result.notes.some((n) => n.includes('Connection was not sent')));
  });

  test('a server without HTTP/2 is detected, and nothing is sent to it', async () => {
    const before_ = plainOnly.seen.length;
    const result = await sendH2(
      makeRequest({ url: `https://127.0.0.1:${plainOnly.port}/`, httpVersion: '2', headers: [] }),
      { insecure: true },
    );
    assert.equal(result.refusedH2, true);
    assert.match(result.error ?? '', /does not offer HTTP\/2/);
    assert.equal(plainOnly.seen.length, before_);
  });

  test('plain http is HTTP/2 with prior knowledge', async () => {
    const result = await send(
      makeRequest({ url: `http://127.0.0.1:${h2c.port}/`, httpVersion: '2', headers: [] }),
    );
    assert.equal(result.response?.body.toString(), 'h2c 2.0');
  });

  test('a replay records the request that went out, not the one asked for', async () => {
    const result = await replay(
      makeRequest({
        url: `https://127.0.0.1:${origin.port}/r`,
        httpVersion: '2',
        headers: [['Host', `127.0.0.1:${origin.port}`], ['Keep-Alive', '5'], ['X-Kept', '1']],
      }),
      { scope: parseScopeConfig({ include: [`https://127.0.0.1:${origin.port}`] }), mutations: [], insecure: true },
    );
    assert.deepEqual(result.exchange.request.headers, [['host', `127.0.0.1:${origin.port}`], ['x-kept', '1']]);
    assert.ok(result.notes.some((n) => n.includes('Keep-Alive')));
  });

  test('an unverified certificate is refused unless insecure is asked for', async () => {
    const result = await send(
      makeRequest({ url: `https://127.0.0.1:${origin.port}/`, httpVersion: '2', headers: [] }),
    );
    assert.equal(result.response, undefined);
    assert.ok(result.error !== undefined);
  });
});

/** CONNECT through the proxy, then HTTP/2 inside the tunnel: what a browser does. */
async function h2ViaProxy(
  proxyPort: number,
  port: number,
  path: string,
  trustedCa: string,
  extra: Record<string, string | string[]> = {},
): Promise<{ status: number; body: string; alpn: string; headers: Record<string, unknown> }> {
  const socket = netConnect({ host: '127.0.0.1', port: proxyPort });
  await new Promise<void>((resolve, reject) => {
    socket.once('connect', () => socket.write(`CONNECT 127.0.0.1:${port} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\n\r\n`));
    let pre = '';
    const onData = (chunk: Buffer): void => {
      pre += chunk.toString('latin1');
      if (!pre.includes('\r\n\r\n')) return;
      socket.removeListener('data', onData);
      if (/^HTTP\/1\.1 200/.test(pre)) resolve();
      else reject(new Error(pre));
    };
    socket.on('data', onData);
    socket.once('error', reject);
  });
  const tls = tlsConnect({ socket, servername: '127.0.0.1', ca: [trustedCa], ALPNProtocols: ['h2', 'http/1.1'] });
  await new Promise<void>((resolve, reject) => {
    tls.once('secureConnect', () => resolve());
    tls.once('error', reject);
  });
  const alpn = tls.alpnProtocol || '';
  const session = h2Connect(`https://127.0.0.1:${port}`, { createConnection: () => tls });
  try {
    return await new Promise((resolve, reject) => {
      const stream = session.request({ ':path': path, ...extra });
      let status = 0;
      let headers: Record<string, unknown> = {};
      const chunks: Buffer[] = [];
      stream.on('response', (h) => {
        status = Number(h[':status']);
        headers = h;
      });
      stream.on('data', (c: Buffer) => chunks.push(c));
      stream.on('end', () => resolve({ status, body: Buffer.concat(chunks).toString(), alpn, headers }));
      stream.on('error', reject);
    });
  } finally {
    session.destroy();
    tls.destroy();
  }
}

describe('HTTP/2 through the proxy', () => {
  let h2: Origin;
  let h1: Origin;
  let proxy: Proxy;
  let trusted: string;
  const recorded: Exchange[] = [];

  before(async () => {
    h2 = await h2Origin(leaf.cert, leaf.key);
    h1 = await h1Origin(leaf.cert, leaf.key);
    const caDir = join(tempDir(), 'proxy-ca');
    createCa(caDir, 'appsec-workbench test CA');
    trusted = readFileSync(caPaths(caDir).caCert, 'utf8');
    proxy = new Proxy({
      port: 0,
      scope: parseScopeConfig({ include: [`https://127.0.0.1:${h2.port}`, `https://127.0.0.1:${h1.port}`] }),
      ca: caPaths(caDir),
      insecureUpstream: true,
      onExchange: (e) => recorded.push(e),
    });
    await proxy.listen();
  });

  after(async () => {
    await proxy.close();
    await h2.close();
    await h1.close();
  });

  test('a client is offered h2, and an h2 target is reached over h2', async () => {
    const out = await h2ViaProxy(proxy.port, h2.port, '/api?x=1', trusted, { 'x-test': 'yes' });
    assert.equal(out.alpn, 'h2');
    assert.equal(out.status, 200);
    assert.equal(out.body, '{"over":"2.0"}');
    assert.deepEqual(out.headers['set-cookie'], ['a=1', 'b=2'], 'repeated response headers survive to the client');
    assert.equal(h2.seen.at(-1)?.version, '2.0');

    const last = recorded.at(-1);
    assert.equal(last?.request.httpVersion, '2');
    assert.equal(last?.request.url, `https://127.0.0.1:${h2.port}/api?x=1`);
    assert.equal(getHeader(last?.request.headers ?? [], 'host'), `127.0.0.1:${h2.port}`);
    assert.equal(getHeader(last?.request.headers ?? [], 'x-test'), 'yes');
    assert.equal(last?.response?.httpVersion, '2');
  });

  test('an h1-only target is reached over HTTP/1.1, and the record says so', async () => {
    const out = await h2ViaProxy(proxy.port, h1.port, '/', trusted, { cookie: ['a=1', 'b=2'] });
    assert.equal(out.alpn, 'h2', 'the client side stays HTTP/2');
    assert.equal(out.body, 'over 1.1');
    const hit = h1.seen.at(-1);
    assert.equal(hit?.version, '1.1');
    assert.deepEqual(
      hit?.raw.filter((_, i, a) => i % 2 === 0 && a[i]?.toLowerCase() === 'cookie').length,
      1,
      'split cookies are joined for HTTP/1.1',
    );
    const last = recorded.at(-1);
    assert.equal(last?.request.httpVersion, '1.1');
    assert.ok(last?.tags.some((t) => t.includes('the target does not offer it')));
  });

  test('a second request to the h1-only target does not offer h2 again', async () => {
    const before_ = recorded.length;
    await h2ViaProxy(proxy.port, h1.port, '/again', trusted);
    assert.equal(recorded.length, before_ + 1);
    assert.equal(recorded.at(-1)?.request.httpVersion, '1.1');
  });

  test('a client that sends no SNI still gets a certificate, for the CONNECT host', async () => {
    // What every browser does for an IP address: RFC 6066 forbids an IP in
    // SNI. A shared TLS server had no default certificate and failed this
    // handshake, which a client setting servername never noticed.
    const socket = netConnect({ host: '127.0.0.1', port: proxy.port });
    await new Promise<void>((resolve) => {
      socket.once('connect', () =>
        socket.write(`CONNECT 127.0.0.1:${h1.port} HTTP/1.1\r\nHost: 127.0.0.1:${h1.port}\r\n\r\n`),
      );
      socket.once('data', () => resolve());
    });
    const tls = tlsConnect({ socket, ca: [trusted], checkServerIdentity: () => undefined });
    const body = await new Promise<string>((resolve, reject) => {
      tls.once('secureConnect', () => {
        assert.equal((tls as unknown as { servername?: unknown }).servername ?? false, false, 'no SNI was sent');
        tls.write(`GET /nosni HTTP/1.1\r\nHost: 127.0.0.1:${h1.port}\r\nConnection: close\r\n\r\n`);
      });
      const chunks: Buffer[] = [];
      tls.on('data', (c: Buffer) => chunks.push(c));
      tls.on('end', () => resolve(Buffer.concat(chunks).toString()));
      tls.on('error', reject);
    });
    assert.match(body, /over 1\.1$/);
    const subject = tls.getPeerCertificate().subjectaltname ?? '';
    assert.match(subject, /IP Address:127\.0\.0\.1/);
  });

  test('with http2 off, clients are offered HTTP/1.1 only', async () => {
    const caDir = join(tempDir(), 'proxy-ca-2');
    createCa(caDir);
    const plain = new Proxy({
      port: 0,
      scope: parseScopeConfig({ include: [`https://127.0.0.1:${h2.port}`] }),
      ca: caPaths(caDir),
      insecureUpstream: true,
      http2: false,
    });
    await plain.listen();
    try {
      const socket = netConnect({ host: '127.0.0.1', port: plain.port });
      await new Promise<void>((resolve) => {
        socket.once('connect', () =>
          socket.write(`CONNECT 127.0.0.1:${h2.port} HTTP/1.1\r\nHost: 127.0.0.1:${h2.port}\r\n\r\n`),
        );
        socket.once('data', () => resolve());
      });
      const tls = tlsConnect({
        socket,
        servername: '127.0.0.1',
        ca: [readFileSync(caPaths(caDir).caCert, 'utf8')],
        ALPNProtocols: ['h2', 'http/1.1'],
      });
      await new Promise<void>((resolve) => tls.once('secureConnect', () => resolve()));
      assert.equal(tls.alpnProtocol, 'http/1.1');
      tls.destroy();
    } finally {
      await plain.close();
    }
  });
});
