import { strict as assert } from 'node:assert';
import { createServer, type Server } from 'node:net';
import test, { describe } from 'node:test';

import { parseResponse, send, serialiseToWire } from '../src/net/send.js';
import { get as getHeader } from '../src/core/headers.js';
import { makeRequest } from './helpers.js';

/**
 * A server that replies with bytes the test chose, exactly.
 *
 * Nothing in this suite talks to a network it did not start, and every
 * listener binds loopback only.
 */
async function rawServer(
  reply: (received: Buffer) => string | Buffer | undefined,
): Promise<{ port: number; close: () => Promise<void>; received: () => Buffer[] }> {
  const seen: Buffer[] = [];
  const server: Server = createServer((socket) => {
    const chunks: Buffer[] = [];
    socket.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
      const all = Buffer.concat(chunks);
      if (all.includes('\r\n\r\n')) {
        seen.push(all);
        const out = reply(all);
        if (out === undefined) {
          socket.destroy();
          return;
        }
        socket.write(typeof out === 'string' ? Buffer.from(out, 'latin1') : out);
        socket.end();
      }
    });
    socket.on('error', () => {
      /* a destroyed socket during a negative test is expected */
    });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  return {
    port,
    received: () => seen,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}

const OK = 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi';

describe('the request goes on the wire exactly as given', () => {
  test('header order and duplicates are preserved byte for byte', () => {
    const wire = serialiseToWire(
      makeRequest({
        headers: [
          ['Transfer-Encoding', 'chunked'],
          ['Host', 'target.example'],
          ['Content-Length', '5'],
          ['Host', 'second.example'],
        ],
      }),
    ).toString('latin1');
    const head = wire.split('\r\n\r\n')[0] ?? '';
    assert.deepEqual(head.split('\r\n').slice(1), [
      'Transfer-Encoding: chunked',
      'Host: target.example',
      'Content-Length: 5',
      'Host: second.example',
    ]);
  });

  test('a deliberately wrong Content-Length is sent wrong, because that is the test', () => {
    const wire = serialiseToWire(
      makeRequest({
        method: 'POST',
        headers: [
          ['Host', 'target.example'],
          ['Content-Length', '999'],
        ],
        body: Buffer.from('short'),
      }),
    ).toString('latin1');
    assert.ok(wire.includes('Content-Length: 999'));
    assert.ok(wire.endsWith('short'));
  });

  test('fixContentLength repairs it only when asked', () => {
    const request = makeRequest({
      method: 'POST',
      headers: [
        ['Host', 'target.example'],
        ['Content-Length', '999'],
      ],
      body: Buffer.from('short'),
    });
    assert.ok(serialiseToWire(request, { fixContentLength: true }).toString().includes('Content-Length: 5'));
  });

  test('fixContentLength does not invent the header when it was absent', () => {
    const wire = serialiseToWire(
      makeRequest({ method: 'POST', headers: [['Host', 'a.example']], body: Buffer.from('xx') }),
      { fixContentLength: true },
    ).toString('latin1');
    assert.ok(!/content-length/i.test(wire));
  });

  test('nothing is added that the caller did not ask for', () => {
    const wire = serialiseToWire(makeRequest({ headers: [['Host', 'a.example']] })).toString('latin1');
    const head = wire.split('\r\n\r\n')[0] ?? '';
    assert.deepEqual(head.split('\r\n'), ['GET / HTTP/1.1', 'Host: a.example']);
  });

  test('the server receives those exact bytes', async () => {
    const srv = await rawServer(() => OK);
    try {
      await send(makeRequest({ url: `http://127.0.0.1:${srv.port}/x`, headers: [['Host', 'spoofed.example'], ['X-A', '1'], ['X-A', '2']] }));
      const got = srv.received()[0]?.toString('latin1') ?? '';
      assert.ok(got.startsWith('GET /x HTTP/1.1\r\n'));
      assert.ok(got.includes('Host: spoofed.example\r\n'));
      assert.ok(got.includes('X-A: 1\r\nX-A: 2\r\n'));
    } finally {
      await srv.close();
    }
  });
});

describe('response framing by Content-Length', () => {
  test('a well-framed response is read', async () => {
    const srv = await rawServer(() => OK);
    try {
      const out = await send(makeRequest({ url: `http://127.0.0.1:${srv.port}/` }));
      assert.equal(out.error, undefined);
      assert.equal(out.response?.status, 200);
      assert.equal(out.response?.statusText, 'OK');
      assert.equal(out.response?.body.toString(), 'hi');
      assert.deepEqual(out.notes, []);
    } finally {
      await srv.close();
    }
  });

  test('bytes past the declared length are reported as a queued response', () => {
    const parsed = parseResponse(
      Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhiHTTP/1.1 404 Not Found\r\n\r\n', 'latin1'),
      1,
    );
    assert.equal(parsed.response.body.toString(), 'hi');
    assert.ok(parsed.notes.some((n) => /queued response/.test(n)));
  });

  test('a short body is reported rather than silently accepted', () => {
    const parsed = parseResponse(
      Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort', 'latin1'),
      1,
    );
    assert.ok(parsed.notes.some((n) => /declared 100 bytes but only 5 arrived/.test(n)));
  });

  test('a non-numeric Content-Length is a note, not a crash', () => {
    const parsed = parseResponse(
      Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\nbody', 'latin1'),
      1,
    );
    assert.ok(parsed.notes.some((n) => /not a non-negative integer/.test(n)));
    assert.equal(parsed.response.body.toString(), 'body');
  });

  test('a large body is truncated and says so', () => {
    const parsed = parseResponse(
      Buffer.from(`HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n${'x'.repeat(1000)}`, 'latin1'),
      1,
      100,
    );
    assert.equal(parsed.response.body.length, 100);
    assert.equal(parsed.truncated, true);
  });
});

describe('response framing by chunked encoding', () => {
  test('chunks are joined in order', async () => {
    const srv = await rawServer(
      () =>
        'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n',
    );
    try {
      const out = await send(makeRequest({ url: `http://127.0.0.1:${srv.port}/` }));
      assert.equal(out.response?.body.toString(), 'hello world');
    } finally {
      await srv.close();
    }
  });

  test('a chunk extension is recorded', () => {
    const parsed = parseResponse(
      Buffer.from('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;foo=bar\r\nhi\r\n0\r\n\r\n', 'latin1'),
      1,
    );
    assert.equal(parsed.response.body.toString(), 'hi');
    assert.ok(parsed.notes.some((n) => /chunk extension/.test(n)));
  });

  test('a truncated chunked body is reported', () => {
    const parsed = parseResponse(
      Buffer.from('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nshort', 'latin1'),
      1,
    );
    assert.ok(parsed.notes.some((n) => /declared 16 bytes but only 5 remained/.test(n)));
  });

  test('a non-hex chunk size is reported', () => {
    const parsed = parseResponse(
      Buffer.from('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhi\r\n', 'latin1'),
      1,
    );
    assert.ok(parsed.notes.some((n) => /not hexadecimal/.test(n)));
  });

  test('a missing terminating chunk is reported', () => {
    const parsed = parseResponse(
      Buffer.from('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n', 'latin1'),
      1,
    );
    assert.ok(parsed.notes.some((n) => /without a terminating chunk/.test(n)));
  });

  test('trailer fields are noticed', () => {
    const parsed = parseResponse(
      Buffer.from('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nX-T: 1\r\n\r\n', 'latin1'),
      1,
    );
    assert.ok(parsed.notes.some((n) => /trailer fields/.test(n)));
  });
});

describe('the framing anomalies that make smuggling possible are reported', () => {
  test('Transfer-Encoding together with Content-Length', () => {
    const parsed = parseResponse(
      Buffer.from(
        'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n',
        'latin1',
      ),
      1,
    );
    assert.ok(parsed.notes.some((n) => /Transfer-Encoding wins/.test(n)));
    assert.equal(parsed.response.body.toString(), 'hi', 'chunked framing must be the one used');
  });

  test('obs-fold is folded in and flagged', () => {
    const parsed = parseResponse(
      Buffer.from('HTTP/1.1 200 OK\r\nX-Long: first\r\n  second\r\nContent-Length: 0\r\n\r\n', 'latin1'),
      1,
    );
    assert.equal(getHeader(parsed.response.headers, 'x-long'), 'first second');
    assert.ok(parsed.notes.some((n) => /obs-fold/.test(n)));
  });

  test('a header line with no colon is skipped and flagged', () => {
    const parsed = parseResponse(
      Buffer.from('HTTP/1.1 200 OK\r\ngarbage\r\nContent-Length: 0\r\n\r\n', 'latin1'),
      1,
    );
    assert.ok(parsed.notes.some((n) => /without a colon/.test(n)));
    assert.equal(parsed.response.status, 200);
  });

  test('a body on a 204 is flagged, and discarded as the RFC requires', () => {
    const parsed = parseResponse(Buffer.from('HTTP/1.1 204 No Content\r\n\r\nunexpected', 'latin1'), 1);
    assert.equal(parsed.response.body.length, 0);
    assert.ok(parsed.notes.some((n) => /must have no body/.test(n)));
  });

  test('duplicate response headers are both kept', () => {
    const parsed = parseResponse(
      Buffer.from('HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: 0\r\n\r\n', 'latin1'),
      1,
    );
    assert.equal(parsed.response.headers.filter(([k]) => k === 'Set-Cookie').length, 2);
  });
});

describe('malformed and absent responses are errors with a reason', () => {
  test('a garbage status line', () => {
    assert.throws(() => parseResponse(Buffer.from('NOT HTTP\r\n\r\n', 'latin1'), 1), /not a status line/);
  });

  test('headers that never terminate', () => {
    assert.throws(
      () => parseResponse(Buffer.from('HTTP/1.1 200 OK\r\nX: 1', 'latin1'), 1),
      /before the headers were complete/,
    );
  });

  test('a server that closes without replying', async () => {
    const srv = await rawServer(() => undefined);
    try {
      const out = await send(makeRequest({ url: `http://127.0.0.1:${srv.port}/` }));
      assert.match(out.error ?? '', /closed the connection without sending anything/);
    } finally {
      await srv.close();
    }
  });

  test('a refused connection reports the system error', async () => {
    // Port 1 on loopback: privileged, and nothing listens there.
    const out = await send(makeRequest({ url: 'http://127.0.0.1:1/' }), { timeoutMs: 2000 });
    assert.ok(out.error !== undefined);
    assert.match(out.error, /ECONNREFUSED|EACCES/);
  });

  test('a URL that is not a URL', async () => {
    const out = await send(makeRequest({ url: 'nonsense' }));
    assert.match(out.error ?? '', /not a sendable URL/);
  });

  test('a scheme that cannot be sent', async () => {
    const out = await send(makeRequest({ url: 'ftp://a.example/x' }));
    assert.match(out.error ?? '', /only http and https/);
  });

  test('the wire bytes are returned even when the send failed', async () => {
    const out = await send(makeRequest({ url: 'http://127.0.0.1:1/' }), { timeoutMs: 2000 });
    assert.ok(out.wire.toString('latin1').startsWith('GET / HTTP/1.1'));
  });
});

describe('end-of-connection framing', () => {
  test('a response with neither Content-Length nor chunked runs to close', async () => {
    const srv = await rawServer(() => 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nto the end');
    try {
      const out = await send(makeRequest({ url: `http://127.0.0.1:${srv.port}/` }));
      assert.equal(out.response?.body.toString(), 'to the end');
    } finally {
      await srv.close();
    }
  });
});

describe('connectTo sends to one place while addressing another', () => {
  test('the request line and Host describe the target, the socket goes elsewhere', async () => {
    const srv = await rawServer(() => OK);
    try {
      const out = await send(
        makeRequest({ url: 'http://target.example/admin', headers: [['Host', 'target.example']] }),
        { connectTo: { host: '127.0.0.1', port: srv.port } },
      );
      assert.equal(out.response?.status, 200);
      const got = srv.received()[0]?.toString('latin1') ?? '';
      assert.ok(got.startsWith('GET /admin HTTP/1.1'));
      assert.ok(got.includes('Host: target.example'));
    } finally {
      await srv.close();
    }
  });
});
