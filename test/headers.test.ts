import { strict as assert } from 'node:assert';
import test, { describe } from 'node:test';

import {
  add,
  count,
  fromRawHeaders,
  get,
  getAll,
  headerAnomalies,
  insertAt,
  isHopByHop,
  remove,
  serialiseHeaders,
  set,
  toRawHeaders,
  type HeaderList,
} from '../src/core/headers.js';

const SAMPLE: HeaderList = [
  ['Host', 'target.example'],
  ['User-Agent', 'awb/0.1'],
  ['Accept', 'text/html'],
  ['Accept', 'application/json'],
  ['content-length', '7'],
];

describe('lookup is case-insensitive but spelling is preserved', () => {
  test('get finds a header whatever case it was asked for', () => {
    assert.equal(get(SAMPLE, 'host'), 'target.example');
    assert.equal(get(SAMPLE, 'HOST'), 'target.example');
    assert.equal(get(SAMPLE, 'Content-Length'), '7');
  });

  test('the stored name keeps the case it arrived with', () => {
    const names = SAMPLE.map(([k]) => k);
    assert.ok(names.includes('content-length'));
    assert.ok(!names.includes('Content-Length'));
  });

  test('getAll returns duplicates in wire order', () => {
    assert.deepEqual(getAll(SAMPLE, 'accept'), ['text/html', 'application/json']);
  });

  test('count reports how many of a header there are', () => {
    assert.equal(count(SAMPLE, 'accept'), 2);
    assert.equal(count(SAMPLE, 'host'), 1);
    assert.equal(count(SAMPLE, 'origin'), 0);
  });
});

describe('mutation keeps position, which is part of the message', () => {
  test('set replaces in place rather than appending', () => {
    const out = set(SAMPLE, 'User-Agent', 'curl/8');
    assert.equal(out[1]?.[0], 'User-Agent');
    assert.equal(out[1]?.[1], 'curl/8');
    assert.equal(out.length, SAMPLE.length);
  });

  test('set collapses duplicates to one header at the first position', () => {
    const out = set(SAMPLE, 'Accept', '*/*');
    assert.deepEqual(getAll(out, 'accept'), ['*/*']);
    assert.equal(out[2]?.[0], 'Accept');
  });

  test('set appends when the header was absent', () => {
    const out = set(SAMPLE, 'Origin', 'https://evil.example');
    assert.equal(out[out.length - 1]?.[0], 'Origin');
  });

  test('add leaves the existing header alone', () => {
    const out = add(SAMPLE, 'Host', 'second.example');
    assert.deepEqual(getAll(out, 'host'), ['target.example', 'second.example']);
  });

  test('insertAt can place a header before Host', () => {
    const out = insertAt(SAMPLE, 0, 'Transfer-Encoding', 'chunked');
    assert.equal(out[0]?.[0], 'Transfer-Encoding');
    assert.equal(out[1]?.[0], 'Host');
  });

  test('remove takes every occurrence', () => {
    assert.equal(count(remove(SAMPLE, 'accept'), 'accept'), 0);
  });

  test('mutation never changes the input', () => {
    const before = JSON.stringify(SAMPLE);
    set(SAMPLE, 'Host', 'other');
    remove(SAMPLE, 'Host');
    add(SAMPLE, 'Host', 'other');
    assert.equal(JSON.stringify(SAMPLE), before);
  });
});

describe("Node's raw header form round-trips", () => {
  test('fromRawHeaders preserves order and duplicates', () => {
    const raw = ['Host', 'a.example', 'Cookie', 'x=1', 'Cookie', 'y=2'];
    const list = fromRawHeaders(raw);
    assert.equal(list.length, 3);
    assert.deepEqual(getAll(list, 'cookie'), ['x=1', 'y=2']);
  });

  test('toRawHeaders is its inverse', () => {
    assert.deepEqual(toRawHeaders(fromRawHeaders(['A', '1', 'B', '2'])), ['A', '1', 'B', '2']);
  });

  test('an odd-length raw array drops the dangling name rather than inventing a value', () => {
    assert.deepEqual(fromRawHeaders(['A', '1', 'B']), [['A', '1']]);
  });
});

describe('serialisation is wire-exact', () => {
  test('CRLF between headers, no trailing terminator', () => {
    const out = serialiseHeaders([
      ['Host', 'a.example'],
      ['Accept', '*/*'],
    ]);
    assert.equal(out, 'Host: a.example\r\nAccept: */*');
  });

  test('an empty list serialises to an empty string', () => {
    assert.equal(serialiseHeaders([]), '');
  });
});

describe('hop-by-hop headers are recognised', () => {
  test('the RFC 9110 list plus the usual two', () => {
    for (const h of ['Connection', 'transfer-encoding', 'Upgrade', 'TE', 'Keep-Alive']) {
      assert.ok(isHopByHop(h), `${h} should be hop-by-hop`);
    }
  });

  test('end-to-end headers are not', () => {
    for (const h of ['Host', 'Content-Length', 'Authorization']) {
      assert.ok(!isHopByHop(h), `${h} should not be hop-by-hop`);
    }
  });
});

describe('structural anomalies are reported, not normalised away', () => {
  test('two Host headers', () => {
    const found = headerAnomalies([
      ['Host', 'a.example'],
      ['Host', 'b.example'],
    ]);
    assert.ok(found.some((a) => a.kind === 'duplicate-singleton' && a.header === 'host'));
  });

  test('disagreeing Content-Length values', () => {
    const found = headerAnomalies([
      ['Content-Length', '5'],
      ['Content-Length', '12'],
    ]);
    assert.ok(found.some((a) => a.kind === 'conflicting-length'));
  });

  test('agreeing duplicate Content-Length is still a duplicate but not a conflict', () => {
    const found = headerAnomalies([
      ['Content-Length', '5'],
      ['Content-Length', '5'],
    ]);
    assert.ok(found.some((a) => a.kind === 'duplicate-singleton'));
    assert.ok(!found.some((a) => a.kind === 'conflicting-length'));
  });

  test('Content-Length together with Transfer-Encoding', () => {
    const found = headerAnomalies([
      ['Content-Length', '5'],
      ['Transfer-Encoding', 'chunked'],
    ]);
    const hit = found.find((a) => a.kind === 'length-and-chunked');
    assert.ok(hit);
    assert.match(hit.detail, /desync/);
  });

  test('CR or LF inside a value', () => {
    const found = headerAnomalies([['X-Thing', 'a\r\nInjected: 1']]);
    assert.ok(found.some((a) => a.kind === 'obs-fold'));
  });

  test('whitespace in a header name', () => {
    const found = headerAnomalies([['X Thing', 'a']]);
    assert.ok(found.some((a) => a.kind === 'whitespace-in-name'));
  });

  test('an ordinary request has no anomalies', () => {
    assert.deepEqual(headerAnomalies(SAMPLE.filter(([k]) => k !== 'Accept')), []);
  });
});
