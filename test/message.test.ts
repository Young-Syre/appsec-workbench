import { strict as assert } from 'node:assert';
import test, { describe } from 'node:test';

import {
  charsetOf,
  contentType,
  exchangeId,
  isTextual,
  parseRawRequest,
  requestLine,
  serialiseRequest,
  serialiseResponse,
  statusLine,
  type HttpRequest,
  type HttpResponse,
} from '../src/core/message.js';

function req(over: Partial<HttpRequest> = {}): HttpRequest {
  return {
    method: 'POST',
    url: 'https://target.example/api/login?next=%2Fhome',
    httpVersion: '1.1',
    headers: [
      ['Host', 'target.example'],
      ['Content-Type', 'application/json; charset=UTF-8'],
      ['Content-Length', '26'],
    ],
    body: Buffer.from('{"user":"a","pass":"b"}'),
    startedAt: 1_700_000_000_000,
    ...over,
  };
}

describe('the request line uses origin form', () => {
  test('path and query, not the absolute URL', () => {
    assert.equal(requestLine(req()), 'POST /api/login?next=%2Fhome HTTP/1.1');
  });

  test('a URL with no path still gets a slash', () => {
    assert.equal(requestLine(req({ url: 'https://target.example' })), 'POST / HTTP/1.1');
  });

  test('an unparseable target is passed through rather than guessed at', () => {
    assert.equal(requestLine(req({ url: '/already-relative' })), 'POST /already-relative HTTP/1.1');
  });
});

describe('status line', () => {
  const res: HttpResponse = {
    status: 302,
    statusText: 'Found',
    httpVersion: '1.1',
    headers: [['Location', '/home']],
    body: Buffer.alloc(0),
    elapsedMs: 12,
  };

  test('includes the reason phrase when there is one', () => {
    assert.equal(statusLine(res), 'HTTP/1.1 302 Found');
  });

  test('omits it cleanly when there is not (HTTP/2 has no reason phrase)', () => {
    assert.equal(statusLine({ ...res, statusText: '', httpVersion: '2' }), 'HTTP/2 302');
  });
});

describe('raw serialisation round-trips byte for byte', () => {
  test('a request serialises to head + CRLFCRLF + body', () => {
    const raw = serialiseRequest(req());
    assert.ok(raw.startsWith('POST /api/login?next=%2Fhome HTTP/1.1\r\n'));
    assert.ok(raw.includes('\r\n\r\n{"user":"a","pass":"b"}'));
  });

  test('parse is the inverse of serialise', () => {
    const original = req();
    const parsed = parseRawRequest(serialiseRequest(original), 'https://target.example');
    assert.equal(parsed.method, original.method);
    assert.equal(parsed.url, original.url);
    assert.deepEqual(parsed.headers, original.headers);
    assert.equal(parsed.body.toString(), original.body.toString());
  });

  test('a response serialises with its status line', () => {
    const raw = serialiseResponse({
      status: 200,
      statusText: 'OK',
      httpVersion: '1.1',
      headers: [['Content-Type', 'text/html']],
      body: Buffer.from('<p>hi</p>'),
      elapsedMs: 3,
    });
    assert.equal(raw, 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p>hi</p>');
  });
});

describe('parsing an edited request changes nothing it was not asked to', () => {
  test('a wrong Content-Length is preserved, because that is often the test', () => {
    const raw = 'POST /x HTTP/1.1\r\nHost: t.example\r\nContent-Length: 999\r\n\r\nshort';
    const parsed = parseRawRequest(raw, 'https://t.example');
    assert.equal(parsed.headers.find(([k]) => k === 'Content-Length')?.[1], '999');
    assert.equal(parsed.body.toString(), 'short');
  });

  test('duplicate headers survive an edit round trip', () => {
    const raw =
      'GET /x HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\nTransfer-Encoding: chunked\r\n\r\n';
    const parsed = parseRawRequest(raw, 'https://a.example');
    assert.equal(parsed.headers.filter(([k]) => k.toLowerCase() === 'host').length, 2);
  });

  test('bare LF line endings are accepted, since editors write them', () => {
    const parsed = parseRawRequest('GET /x HTTP/1.1\nHost: a.example\n\nbody', 'https://a.example');
    assert.equal(parsed.url, 'https://a.example/x');
    assert.equal(parsed.body.toString(), 'body');
  });

  test('the scheme comes from the origin, never from a guess', () => {
    const raw = 'GET /x HTTP/1.1\r\nHost: internal.example\r\n\r\n';
    assert.equal(
      parseRawRequest(raw, 'http://whatever.example').url,
      'http://internal.example/x',
    );
    assert.equal(
      parseRawRequest(raw, 'https://whatever.example').url,
      'https://internal.example/x',
    );
  });

  test('an absolute request target wins over the Host header', () => {
    const raw = 'GET https://elsewhere.example/y HTTP/1.1\r\nHost: a.example\r\n\r\n';
    assert.equal(parseRawRequest(raw, 'https://a.example').url, 'https://elsewhere.example/y');
  });

  test('a missing HTTP version defaults to 1.1 rather than failing', () => {
    assert.equal(parseRawRequest('GET /x\r\nHost: a.example\r\n\r\n', 'https://a.example').httpVersion, '1.1');
  });

  test('a malformed request line is an error, not a silent guess', () => {
    assert.throws(() => parseRawRequest('not a request\r\n\r\n', 'https://a.example'), /not a request line/);
  });

  test('a header line with no colon is an error', () => {
    assert.throws(
      () => parseRawRequest('GET /x HTTP/1.1\r\nbroken\r\n\r\n', 'https://a.example'),
      /not a header line/,
    );
  });

  test('only the first space after the colon is consumed', () => {
    const parsed = parseRawRequest(
      'GET /x HTTP/1.1\r\nHost: a.example\r\nX-Pad:   spaced\r\n\r\n',
      'https://a.example',
    );
    assert.equal(parsed.headers.find(([k]) => k === 'X-Pad')?.[1], '  spaced');
  });
});

describe('exchange ids are stable and content-sensitive', () => {
  test('the same request yields the same id', () => {
    assert.equal(exchangeId(req()), exchangeId(req()));
  });

  test('a changed body yields a different id', () => {
    assert.notEqual(exchangeId(req()), exchangeId(req({ body: Buffer.from('x') })));
  });

  test('a changed header order yields a different id', () => {
    const reordered = req({
      headers: [
        ['Content-Length', '26'],
        ['Content-Type', 'application/json; charset=UTF-8'],
        ['Host', 'target.example'],
      ],
    });
    assert.notEqual(exchangeId(req()), exchangeId(reordered));
  });

  test('a salt separates two sends of identical bytes', () => {
    assert.notEqual(exchangeId(req(), 'a'), exchangeId(req(), 'b'));
  });

  test('ids are 16 hex characters', () => {
    assert.match(exchangeId(req()), /^[0-9a-f]{16}$/);
  });
});

describe('content type parsing', () => {
  test('parameters are dropped and the type lowercased', () => {
    assert.equal(contentType([['Content-Type', 'Application/JSON; charset=utf-8']]), 'application/json');
  });

  test('charset is read separately, quoted or not', () => {
    assert.equal(charsetOf([['Content-Type', 'text/html; charset="ISO-8859-1"']]), 'iso-8859-1');
    assert.equal(charsetOf([['Content-Type', 'text/html; charset=utf-8']]), 'utf-8');
    assert.equal(charsetOf([['Content-Type', 'text/html']]), undefined);
  });

  test('suffixed structured types count as textual', () => {
    assert.ok(isTextual([['Content-Type', 'application/vnd.api+json']]));
    assert.ok(isTextual([['Content-Type', 'image/svg+xml']]));
    assert.ok(isTextual([['Content-Type', 'application/graphql']]));
  });

  test('binary types do not', () => {
    assert.ok(!isTextual([['Content-Type', 'image/png']]));
    assert.ok(!isTextual([['Content-Type', 'application/octet-stream']]));
    assert.ok(!isTextual([]));
  });
});
