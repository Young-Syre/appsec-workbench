import { strict as assert } from 'node:assert';
import { createServer, type Server } from 'node:http';
import test, { after, before, describe } from 'node:test';

import {
  DEFAULT_MARKER,
  SNIPER_KEEP,
  autoMarkQuery,
  fuzz,
  groupResults,
  parseTemplate,
  planAttack,
  render,
} from '../src/fuzz/engine.js';
import {
  BUILTIN_SETS,
  applyProcessors,
  bruteSource,
  builtinSet,
  canary,
  caseSource,
  fileSource,
  listSource,
  numberSource,
  parsePayloadSpec,
  parseProcessor,
} from '../src/fuzz/payloads.js';
import { parseScopeConfig } from '../src/core/scope.js';
import { makeRequest } from './helpers.js';

describe('payload positions are parsed from markers', () => {
  test('a marked value becomes a position and the markers come out', () => {
    const t = parseTemplate('GET /a?id=§1§ HTTP/1.1');
    assert.equal(t.text, 'GET /a?id=1 HTTP/1.1');
    assert.equal(t.positions.length, 1);
    assert.equal(t.positions[0]?.original, '1');
  });

  test('several positions are found in order', () => {
    const t = parseTemplate('GET /a?x=§1§&y=§2§ HTTP/1.1');
    assert.equal(t.positions.length, 2);
    assert.deepEqual(t.positions.map((p) => p.original), ['1', '2']);
  });

  test('an empty position is allowed', () => {
    const t = parseTemplate('GET /a?id=§§ HTTP/1.1');
    assert.equal(t.positions.length, 1);
    assert.equal(t.positions[0]?.original, '');
  });

  test('an odd number of markers is an error rather than a silent off-by-one', () => {
    assert.throws(() => parseTemplate('GET /a?id=§1 HTTP/1.1'), /odd number/);
  });

  test('no markers yields no positions', () => {
    assert.deepEqual(parseTemplate('GET / HTTP/1.1').positions, []);
  });

  test('rendering substitutes at the recorded offsets', () => {
    const t = parseTemplate('GET /a?x=§1§&y=§2§ HTTP/1.1');
    assert.equal(render(t, ['AAA', 'B']), 'GET /a?x=AAA&y=B HTTP/1.1');
  });

  test('rendering with the wrong number of payloads is an error', () => {
    const t = parseTemplate('GET /a?x=§1§ HTTP/1.1');
    assert.throws(() => render(t, ['a', 'b']), /1 positions but 2 payloads/);
  });

  test('query parameters can be marked automatically', () => {
    const marked = autoMarkQuery(
      makeRequest({ url: 'https://target.example/a?id=1&page=2' }),
      DEFAULT_MARKER,
    );
    assert.equal(parseTemplate(marked).positions.length, 2);
  });
});

describe('attack shapes produce the tuples they promise', () => {
  const two = listSource(['a', 'b']);
  const three = listSource(['x', 'y', 'z']);

  test('sniper walks one position at a time', () => {
    const plan = planAttack('sniper', 2, [two]);
    assert.equal(plan.requests, 4);
    const tuples = [...plan.tuples()];
    assert.deepEqual(tuples, [
      ['a', SNIPER_KEEP],
      ['b', SNIPER_KEEP],
      [SNIPER_KEEP, 'a'],
      [SNIPER_KEEP, 'b'],
    ]);
  });

  test('battering ram puts the same value in every position', () => {
    const plan = planAttack('battering-ram', 3, [two]);
    assert.equal(plan.requests, 2);
    assert.deepEqual([...plan.tuples()], [['a', 'a', 'a'], ['b', 'b', 'b']]);
  });

  test('pitchfork steps the lists together and stops at the shortest', () => {
    const plan = planAttack('pitchfork', 2, [two, three]);
    assert.equal(plan.requests, 2);
    assert.deepEqual([...plan.tuples()], [['a', 'x'], ['b', 'y']]);
  });

  test('cluster bomb is the full product, in a stable order', () => {
    const plan = planAttack('cluster-bomb', 2, [two, three]);
    assert.equal(plan.requests, 6);
    assert.deepEqual([...plan.tuples()], [
      ['a', 'x'],
      ['a', 'y'],
      ['a', 'z'],
      ['b', 'x'],
      ['b', 'y'],
      ['b', 'z'],
    ]);
  });

  test('sniper and battering ram refuse a second payload set', () => {
    assert.throws(() => planAttack('sniper', 1, [two, three]), /sniper uses one payload set/);
    assert.throws(() => planAttack('battering-ram', 1, [two, three]), /battering-ram uses one/);
  });

  test('pitchfork and cluster bomb require one set per position', () => {
    assert.throws(() => planAttack('pitchfork', 3, [two, three]), /3 positions, 2 sets/);
    assert.throws(() => planAttack('cluster-bomb', 1, [two, three]), /1 positions, 2 sets/);
  });

  test('no positions is an error that says how to mark one', () => {
    assert.throws(() => planAttack('sniper', 0, [two]), /Wrap a value in markers/);
  });

  test('an empty list in a cluster bomb yields nothing rather than everything', () => {
    const plan = planAttack('cluster-bomb', 2, [two, listSource([])]);
    assert.equal(plan.requests, 0);
    assert.deepEqual([...plan.tuples()], []);
  });
});

describe('payload sources', () => {
  test('a number range', () => {
    const s = numberSource(1, 5);
    assert.equal(s.length, 5);
    assert.deepEqual([...s.values()], ['1', '2', '3', '4', '5']);
  });

  test('a number range with a step', () => {
    assert.deepEqual([...numberSource(0, 10, 5).values()], ['0', '5', '10']);
  });

  test('a descending range', () => {
    assert.deepEqual([...numberSource(3, 1, -1).values()], ['3', '2', '1']);
  });

  test('a zero step is refused', () => {
    assert.throws(() => numberSource(1, 5, 0), /step cannot be zero/);
  });

  test('an empty range is refused rather than yielding nothing silently', () => {
    assert.throws(() => numberSource(5, 1), /yields nothing/);
  });

  test('brute force enumerates in a stable order', () => {
    const s = bruteSource('ab', 2);
    assert.equal(s.length, 4);
    assert.deepEqual([...s.values()], ['aa', 'ab', 'ba', 'bb']);
  });

  test('brute force refuses a space it would never finish, and says the size', () => {
    assert.throws(() => bruteSource('abcdefghijklmnopqrstuvwxyz', 8), /above the .* limit/);
  });

  test('duplicate characters in a charset are collapsed', () => {
    assert.equal(bruteSource('aab', 1).length, 2);
  });

  test('case permutations cover every combination', () => {
    const s = caseSource('ab');
    assert.equal(s.length, 4);
    assert.deepEqual([...s.values()].sort(), ['AB', 'Ab', 'aB', 'ab']);
  });

  test('case permutations ignore non-letters when counting', () => {
    assert.equal(caseSource('a1b').length, 4);
  });

  test('a file source drops blanks and comments', () => {
    const s = fileSource('one\n\n# a comment\ntwo\n');
    assert.deepEqual([...s.values()], ['one', 'two']);
  });

  test('every built-in set is non-empty and documented', () => {
    for (const set of BUILTIN_SETS) {
      assert.ok(set.values.length > 0, `${set.id} is empty`);
      assert.ok(set.description.length > 40, `${set.id} needs a real description`);
      assert.equal(builtinSet(set.id).length, set.values.length);
    }
  });

  test('an unknown set lists the available ones', () => {
    assert.throws(() => builtinSet('nope'), /Available: quote-probe/);
  });

  test('a canary is stable for a seed and looks like nothing else', () => {
    assert.equal(canary('abc'), canary('abc'));
    assert.match(canary('abc'), /^awb[a-z0-9]+$/);
  });
});

describe('payload specs parse the documented shorthand', () => {
  test('list, numbers, brute, case and set', () => {
    assert.deepEqual([...parsePayloadSpec('list:a,b,c').values()], ['a', 'b', 'c']);
    assert.equal(parsePayloadSpec('numbers:1-10').length, 10);
    assert.equal(parsePayloadSpec('numbers:0-100:10').length, 11);
    assert.equal(parsePayloadSpec('brute:ab:2').length, 4);
    assert.equal(parsePayloadSpec('case:ab').length, 4);
    assert.equal(parsePayloadSpec('set:quote-probe').length, builtinSet('quote-probe').length);
  });

  test('a file spec reads through the supplied reader', () => {
    const s = parsePayloadSpec('file:/words.txt', () => 'a\nb');
    assert.deepEqual([...s.values()], ['a', 'b']);
  });

  test('a file spec with no reader says so rather than touching the disk', () => {
    assert.throws(() => parsePayloadSpec('file:/words.txt'), /not available here/);
  });

  test('a spec with no kind, and an unknown kind, both explain themselves', () => {
    assert.throws(() => parsePayloadSpec('abc'), /needs a kind/);
    assert.throws(() => parsePayloadSpec('nope:x'), /Known: list, numbers, brute, case, set, file/);
  });

  test('a malformed number range is an error', () => {
    assert.throws(() => parsePayloadSpec('numbers:abc'), /needs a range/);
  });
});

describe('processors transform payloads in order', () => {
  test('url encoding, once and twice', () => {
    assert.equal(applyProcessors('a b/c', [parseProcessor('url-encode')]), 'a%20b%2Fc');
    assert.equal(applyProcessors('a b', [parseProcessor('url-encode-twice')]), 'a%2520b');
  });

  test('url-encode-all encodes bytes a normal encoder leaves alone', () => {
    assert.equal(applyProcessors('ab', [parseProcessor('url-encode-all')]), '%61%62');
  });

  test('base64 and html entities', () => {
    assert.equal(applyProcessors('hi', [parseProcessor('base64')]), 'aGk=');
    assert.equal(applyProcessors('<', [parseProcessor('html-entity')]), '&#60;');
  });

  test('prefix and suffix', () => {
    assert.equal(
      applyProcessors('etc/passwd', [parseProcessor('prefix=../../'), parseProcessor('suffix=%00')]),
      '../../etc/passwd%00',
    );
  });

  test('case and reverse', () => {
    assert.equal(applyProcessors('aB', [parseProcessor('upper')]), 'AB');
    assert.equal(applyProcessors('aB', [parseProcessor('lower')]), 'ab');
    assert.equal(applyProcessors('abc', [parseProcessor('reverse')]), 'cba');
  });

  test('hashes are the real digests', () => {
    assert.equal(
      applyProcessors('abc', [parseProcessor('sha256')]),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
    assert.equal(applyProcessors('abc', [parseProcessor('md5')]), '900150983cd24fb0d6963f7d28e17f72');
  });

  test('processors compose left to right', () => {
    assert.equal(
      applyProcessors('a', [parseProcessor('prefix=<'), parseProcessor('url-encode')]),
      '%3Ca',
    );
  });

  test('prefix without a value explains the shape', () => {
    assert.throws(() => parseProcessor('prefix'), /needs a value, as in prefix=/);
  });

  test('an unknown processor lists the known ones', () => {
    assert.throws(() => parseProcessor('rot13'), /Known: url-encode/);
  });
});

describe('a fuzz run against a local target', () => {
  let server: Server;
  let port: number;
  let seen: string[];

  before(async () => {
    seen = [];
    server = createServer((req, res) => {
      const url = new URL(req.url ?? '/', 'http://localhost');
      const id = url.searchParams.get('id') ?? '';
      seen.push(id);
      // id=7 is the needle: a different status and a longer body.
      if (id === '7') {
        res.writeHead(403, { 'content-type': 'text/plain' });
        res.end('forbidden: that record belongs to somebody else' + 'x'.repeat(600));
        return;
      }
      if (id.includes("'")) {
        res.writeHead(500, { 'content-type': 'text/plain' });
        res.end('SQLSTATE[42000]: syntax error near ' + id);
        return;
      }
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(`record ${id} ok`);
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address();
    port = typeof addr === 'object' && addr !== null ? addr.port : 0;
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  const scopeFor = (p: number) => parseScopeConfig({ include: [`http://127.0.0.1:${p}`] });

  test('a sniper run over a number range sends every payload once', async () => {
    const raw = `GET /record?id=§1§ HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`;
    const summary = await fuzz(raw, `http://127.0.0.1:${port}`, {
      scope: scopeFor(port),
      shape: 'sniper',
      sources: [numberSource(1, 10)],
      concurrency: 4,
    });
    assert.equal(summary.plan.requests, 10);
    assert.equal(summary.sent, 10);
    assert.equal(summary.failed, 0);
    assert.deepEqual(
      summary.results.map((r) => r.payloads[0]),
      ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10'],
      'results come back in payload order whatever order they finished in',
    );
  });

  test('the odd response out is flagged material against the baseline', async () => {
    const raw = `GET /record?id=§1§ HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`;
    const summary = await fuzz(raw, `http://127.0.0.1:${port}`, {
      scope: scopeFor(port),
      shape: 'sniper',
      sources: [numberSource(1, 10)],
    });
    const material = summary.results.filter((r) => r.material);
    assert.equal(material.length, 1);
    assert.equal(material[0]?.payloads[0], '7');
    assert.equal(material[0]?.exchange.response?.status, 403);
    assert.ok(summary.baseline !== undefined);
  });

  test('grep patterns are reported per result', async () => {
    const raw = `GET /record?id=§1§ HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`;
    const summary = await fuzz(raw, `http://127.0.0.1:${port}`, {
      scope: scopeFor(port),
      shape: 'sniper',
      sources: [builtinSet('quote-probe')],
      grep: ['SQLSTATE\\[\\d+\\]'],
      processors: [parseProcessor('url-encode')],
    });
    const matched = summary.results.filter((r) => r.matched.length > 0);
    assert.ok(matched.length > 0, 'the error-leaking payloads should have matched');
    assert.equal(matched[0]?.matched[0], 'SQLSTATE\\[\\d+\\]');
  });

  test('reflected payloads are detected', async () => {
    const raw = `GET /record?id=§1§ HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`;
    const summary = await fuzz(raw, `http://127.0.0.1:${port}`, {
      scope: scopeFor(port),
      shape: 'sniper',
      sources: [listSource(['awbcanary123'])],
      baseline: false,
    });
    assert.deepEqual(summary.results[0]?.reflected, ['awbcanary123']);
  });

  test('results group so that the rare response is first', async () => {
    const raw = `GET /record?id=§1§ HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`;
    const summary = await fuzz(raw, `http://127.0.0.1:${port}`, {
      scope: scopeFor(port),
      shape: 'sniper',
      sources: [numberSource(1, 10)],
    });
    const groups = groupResults(summary.results);
    assert.equal(groups[0]?.status, 403);
    assert.equal(groups[0]?.count, 1);
    assert.ok(groups[0]?.material);
    assert.ok(
      groups.some((g) => g.count > 1),
      'the uninteresting responses must collapse rather than being listed one per row',
    );
    assert.ok(groups.length < summary.results.length, 'grouping must reduce the row count');
  });

  test('sniper leaves the other positions as they were', async () => {
    seen.length = 0;
    const raw =
      `GET /record?id=§1§&other=§keepme§ HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`;
    await fuzz(raw, `http://127.0.0.1:${port}`, {
      scope: scopeFor(port),
      shape: 'sniper',
      sources: [listSource(['A'])],
      baseline: false,
    });
    // Two requests: one per position. The first keeps `keepme`, the second
    // keeps id=1 and replaces `keepme`.
    assert.deepEqual(seen, ['A', '1']);
  });

  test('rate limiting spaces the requests out', async () => {
    const raw = `GET /record?id=§1§ HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`;
    const started = Date.now();
    await fuzz(raw, `http://127.0.0.1:${port}`, {
      scope: scopeFor(port),
      shape: 'sniper',
      sources: [numberSource(1, 4)],
      concurrency: 4,
      minIntervalMs: 60,
      baseline: false,
    });
    assert.ok(Date.now() - started >= 150, 'four requests at 60ms apart cannot finish instantly');
  });

  test('an attack above the cap is refused before anything is sent, with the number', async () => {
    seen.length = 0;
    const raw = `GET /record?id=§1§ HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`;
    await assert.rejects(
      () =>
        fuzz(raw, `http://127.0.0.1:${port}`, {
          scope: scopeFor(port),
          shape: 'sniper',
          sources: [numberSource(1, 500)],
          maxRequests: 100,
        }),
      /500 requests, above the cap of 100/,
    );
    assert.equal(seen.length, 0, 'nothing may be sent by a refused attack');
  });

  test('an out-of-scope target is refused before the first request', async () => {
    const raw = `GET /record?id=§1§ HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`;
    await assert.rejects(
      () =>
        fuzz(raw, `http://127.0.0.1:${port}`, {
          scope: parseScopeConfig({ include: ['https://elsewhere.example'] }),
          shape: 'sniper',
          sources: [numberSource(1, 2)],
        }),
      /refusing to send a request/,
    );
  });

  test('a payload that makes the request unparseable is recorded, not thrown', async () => {
    const raw = `GET /record?id=§1§ HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`;
    const summary = await fuzz(raw, `http://127.0.0.1:${port}`, {
      scope: scopeFor(port),
      shape: 'sniper',
      // A newline in the request line destroys the message structure.
      sources: [listSource(['ok', 'broken\r\nnot-a-header'])],
      baseline: false,
    });
    assert.equal(summary.results.length, 2);
    assert.ok(summary.results.some((r) => (r.exchange.error ?? '').includes('unparseable')));
  });
});
