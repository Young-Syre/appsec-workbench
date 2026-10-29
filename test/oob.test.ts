import { strict as assert } from 'node:assert';
import { createSocket } from 'node:dgram';
import { request as httpRequest } from 'node:http';
import test, { after, before, describe } from 'node:test';

import {
  OobListener,
  buildDnsAnswer,
  buildDnsQuery,
  mintToken,
  parseDnsQuery,
} from '../src/oob/listener.js';

const DOMAIN = 'oob.test.invalid';

/**
 * A raw HTTP request, because fetch() refuses to set a Host header.
 *
 * Undici treats Host as forbidden, which is correct for a browser-shaped API
 * and useless for testing a listener that keys on it.
 */
async function sendHttp(
  port: number,
  path: string,
  options: { host?: string; method?: string; headers?: [string, string][]; body?: string } = {},
): Promise<{ status: number; body: string; headers: Record<string, string | string[] | undefined> }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: '127.0.0.1', port, path, method: options.method ?? 'GET' },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString(),
            headers: res.headers,
          }),
        );
      },
    );
    if (options.host !== undefined) req.setHeader('Host', options.host);
    for (const [k, v] of options.headers ?? []) req.setHeader(k, v);
    req.on('error', reject);
    req.end(options.body);
  });
}

async function sendDns(port: number, name: string, type = 1): Promise<Buffer> {
  const socket = createSocket('udp4');
  return new Promise<Buffer>((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.close();
      reject(new Error('no DNS reply'));
    }, 4000);
    timer.unref();
    socket.on('message', (message) => {
      clearTimeout(timer);
      socket.close();
      resolve(message);
    });
    socket.on('error', (err) => {
      clearTimeout(timer);
      socket.close();
      reject(err);
    });
    socket.send(buildDnsQuery(name, 0x4321, type), port, '127.0.0.1');
  });
}

describe('tokens', () => {
  test('are ten characters from an alphabet that survives a payload', () => {
    for (let i = 0; i < 50; i += 1) {
      assert.match(mintToken(), /^[a-z2-7]{10}$/);
    }
  });

  test('do not repeat', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 500; i += 1) seen.add(mintToken());
    assert.equal(seen.size, 500);
  });
});

describe('DNS wire format', () => {
  test('a query round-trips through the parser', () => {
    const parsed = parseDnsQuery(buildDnsQuery('abc.oob.test.invalid'));
    assert.equal(parsed?.name, 'abc.oob.test.invalid');
    assert.equal(parsed?.type, 1);
    assert.equal(parsed?.typeName, 'A');
  });

  test('query types are named', () => {
    assert.equal(parseDnsQuery(buildDnsQuery('a.b', 1, 16))?.typeName, 'TXT');
    assert.equal(parseDnsQuery(buildDnsQuery('a.b', 1, 28))?.typeName, 'AAAA');
    assert.equal(parseDnsQuery(buildDnsQuery('a.b', 1, 9999))?.typeName, 'TYPE9999');
  });

  test('a truncated packet is rejected rather than crashing the listener', () => {
    assert.equal(parseDnsQuery(Buffer.alloc(4)), undefined);
    assert.equal(parseDnsQuery(Buffer.from('not a dns packet at all', 'latin1')), undefined);
  });

  test('a packet with no question is rejected', () => {
    const buf = buildDnsQuery('a.b');
    buf.writeUInt16BE(0, 4);
    assert.equal(parseDnsQuery(buf), undefined);
  });

  test('a compression pointer in the question is rejected, not followed', () => {
    const buf = buildDnsQuery('a.b');
    buf[12] = 0xc0;
    assert.equal(parseDnsQuery(buf), undefined);
  });

  test('an A reply carries the configured address and keeps the query id', () => {
    const query = buildDnsQuery('x.oob.test.invalid', 0xbeef, 1);
    const answer = buildDnsAnswer(query, parseDnsQuery(query), '203.0.113.9');
    assert.ok(answer !== undefined);
    assert.equal(answer.readUInt16BE(0), 0xbeef);
    assert.equal(answer.readUInt16BE(6), 1, 'one answer record');
    const rdata = answer.subarray(answer.length - 4);
    assert.deepEqual([...rdata], [203, 0, 113, 9]);
  });

  test('a non-A query gets NOERROR with no answers', () => {
    const query = buildDnsQuery('x.oob.test.invalid', 1, 16);
    const answer = buildDnsAnswer(query, parseDnsQuery(query), '203.0.113.9');
    assert.equal(answer?.readUInt16BE(6), 0);
  });

  test('a malformed answer address yields no answer record rather than garbage', () => {
    const query = buildDnsQuery('x.oob.test.invalid');
    const answer = buildDnsAnswer(query, parseDnsQuery(query), 'not-an-address');
    assert.equal(answer?.readUInt16BE(6), 0);
  });
});

describe('the listener records only what it minted', () => {
  let listener: OobListener;
  let ports: { httpPort: number; dnsPort: number };

  before(async () => {
    listener = new OobListener({
      domain: DOMAIN,
      answerAddress: '127.0.0.1',
      httpPort: 0,
      dnsPort: 0,
      host: '127.0.0.1',
    });
    ports = await listener.listen();
  });

  after(async () => {
    await listener.close();
  });

  test('a minted canary offers every place a payload can put it', () => {
    const canary = listener.mint('ssrf probe');
    assert.match(canary.hostname, new RegExp(`^[a-z2-7]{10}\\.${DOMAIN.replace(/\./g, '\\.')}$`));
    assert.equal(canary.url, `http://${canary.hostname}/`);
    assert.equal(canary.path, `/${canary.token}`);
    assert.equal(canary.purpose, 'ssrf probe');
    assert.equal(listener.canaryFor(canary.token)?.token, canary.token);
  });

  test('a DNS lookup of a minted name is recorded with its query type', async () => {
    const canary = listener.mint('dns exfil');
    await sendDns(ports.dnsPort, canary.hostname, 16);
    const seen = listener.forToken(canary.token);
    assert.equal(seen.length, 1);
    assert.equal(seen[0]?.kind, 'dns');
    assert.equal(seen[0]?.detail, 'TXT');
    assert.equal(seen[0]?.target, canary.hostname);
    assert.ok((seen[0]?.remoteAddress ?? '').length > 0);
  });

  test('a token behind a prefix is still found, because payloads get mangled', async () => {
    const canary = listener.mint('prefixed');
    await sendDns(ports.dnsPort, `www.${canary.hostname}`);
    assert.equal(listener.forToken(canary.token).length, 1);
  });

  test('a lookup for a token nobody minted is dropped, not reported', async () => {
    const before = listener.all().length;
    const dropped = listener.unknownDropped;
    await sendDns(ports.dnsPort, `aaaaaaaaaa.${DOMAIN}`);
    assert.equal(listener.all().length, before, 'internet noise must not become a finding');
    assert.equal(listener.unknownDropped, dropped + 1);
  });

  test('an HTTP request to a minted host is recorded with headers and body', async () => {
    const canary = listener.mint('http callback');
    const response = await sendHttp(ports.httpPort, '/anything', {
      method: 'POST',
      host: canary.hostname,
      headers: [['x-stolen', 'data']],
      body: 'exfiltrated=secret',
    });
    assert.equal(response.status, 200);

    const seen = listener.forToken(canary.token);
    assert.equal(seen.length, 1);
    assert.equal(seen[0]?.kind, 'http');
    assert.equal(seen[0]?.detail, 'POST');
    assert.equal(seen[0]?.body, 'exfiltrated=secret');
    assert.ok(
      seen[0]?.headers?.some(([k, v]) => k.toLowerCase() === 'x-stolen' && v === 'data'),
      'the headers are how a credential arrives',
    );
  });

  test('a token in the path works when only a path can be injected', async () => {
    const canary = listener.mint('path only');
    await sendHttp(ports.httpPort, canary.path);
    assert.equal(listener.forToken(canary.token).length, 1);
  });

  test('the listener always answers the same thing', async () => {
    const canary = listener.mint('fixed response');
    const a = await sendHttp(ports.httpPort, canary.path);
    const b = await sendHttp(ports.httpPort, '/unrelated');
    assert.equal(a.body, b.body);
    assert.equal(a.headers['cache-control'], 'no-store');
  });

  test('waiting on a token that already fired returns immediately', async () => {
    const canary = listener.mint('already fired');
    await sendHttp(ports.httpPort, canary.path);
    const seen = await listener.wait(canary.token, 50);
    assert.equal(seen.length, 1);
  });

  test('waiting on a token that never fires returns empty rather than throwing', async () => {
    const canary = listener.mint('never fires');
    const started = Date.now();
    const seen = await listener.wait(canary.token, 200);
    assert.deepEqual(seen, [], 'no callback is an answer, not an error');
    assert.ok(Date.now() - started >= 150);
  });

  test('waiting resolves as soon as the interaction arrives', async () => {
    const canary = listener.mint('arrives late');
    const started = Date.now();
    const waiting = listener.wait(canary.token, 5000);
    setTimeout(() => {
      void sendHttp(ports.httpPort, canary.path);
    }, 80).unref();
    const seen = await waiting;
    assert.equal(seen.length, 1);
    assert.ok(Date.now() - started < 3000, 'it must not wait out the whole timeout');
  });
});

describe('recordUnknown opens the listener up deliberately', () => {
  test('unminted tokens are kept when asked for', async () => {
    const listener = new OobListener({
      domain: DOMAIN,
      httpPort: 0,
      dnsPort: 0,
      host: '127.0.0.1',
      recordUnknown: true,
    });
    const ports = await listener.listen();
    try {
      await sendHttp(ports.httpPort, '/zzzzzzzzzz');
      assert.ok(listener.all().length >= 1, 'an unminted token is kept when recordUnknown is on');
    } finally {
      await listener.close();
    }
  });
});
