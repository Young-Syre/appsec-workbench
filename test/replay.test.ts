import { strict as assert } from 'node:assert';
import test, { describe } from 'node:test';

import {
  applyMutation,
  bodyKind,
  buildReplayRequest,
  describeMutation,
  fromEditable,
  parseMutation,
  replay,
  setJsonPointer,
  toEditable,
} from '../src/replay/replay.js';
import {
  classifyContext,
  diffHeaders,
  diffResponses,
  findReflections,
  isMaterial,
  normaliseVolatile,
  similarity,
} from '../src/replay/diff.js';
import { get as getHeader, getAll } from '../src/core/headers.js';
import { parseScopeConfig, EMPTY_SCOPE } from '../src/core/scope.js';
import { ScopeViolation } from '../src/core/scope.js';
import { makeRequest, makeResponse } from './helpers.js';

describe('mutation shorthand parses the way it is documented', () => {
  test('header set, add and remove', () => {
    assert.deepEqual(parseMutation('header:X-A=1'), { kind: 'set-header', name: 'X-A', value: '1' });
    assert.deepEqual(parseMutation('+header:X-A=2'), { kind: 'add-header', name: 'X-A', value: '2' });
    assert.deepEqual(parseMutation('-header:Cookie'), { kind: 'remove-header', name: 'Cookie' });
  });

  test('query, form, json and cookie forms', () => {
    assert.deepEqual(parseMutation('query:id=2'), { kind: 'set-query', name: 'id', value: '2' });
    assert.deepEqual(parseMutation('-query:page'), { kind: 'remove-query', name: 'page' });
    assert.deepEqual(parseMutation('form:role=admin'), { kind: 'set-form', name: 'role', value: 'admin' });
    assert.deepEqual(parseMutation('json:user.role=admin'), {
      kind: 'set-json',
      pointer: 'user.role',
      value: 'admin',
    });
    assert.deepEqual(parseMutation('cookie:session=x'), { kind: 'set-cookie', name: 'session', value: 'x' });
    assert.deepEqual(parseMutation('-cookie:remember'), { kind: 'remove-cookie', name: 'remember' });
  });

  test('a value containing = keeps the rest of it', () => {
    assert.deepEqual(parseMutation('header:X-A=a=b=c'), {
      kind: 'set-header',
      name: 'X-A',
      value: 'a=b=c',
    });
  });

  test('an empty value is allowed, because an empty parameter is a test', () => {
    assert.deepEqual(parseMutation('query:id='), { kind: 'set-query', name: 'id', value: '' });
  });

  test('an unknown kind lists what is known', () => {
    assert.throws(() => parseMutation('nonsense:x=1'), /Known: header, method, path, query/);
  });

  test('a missing value is an error naming the mutation', () => {
    assert.throws(() => parseMutation('header:X-A'), /needs a value after =/);
  });

  test('a missing name is an error showing the shape', () => {
    assert.throws(() => parseMutation('header:=1'), /needs a name, as in header:name=value/);
  });

  test('every mutation describes itself for the record', () => {
    for (const text of ['header:A=1', '-header:A', 'method=POST', 'query:id=2', 'json:a.b=1']) {
      assert.ok(describeMutation(parseMutation(text)).length > 0);
    }
  });
});

describe('structural mutations touch only what they name', () => {
  const base = makeRequest({
    method: 'POST',
    url: 'https://target.example/api/items?page=1&sort=asc&q=hello',
    headers: [
      ['Host', 'target.example'],
      ['Cookie', 'session=abc; theme=dark; remember=1'],
      ['Content-Type', 'application/x-www-form-urlencoded'],
      ['Content-Length', '21'],
      ['X-Trace', 'one'],
    ],
    body: Buffer.from('role=user&name=alice'),
  });

  test('one query parameter changes and the others keep their order', () => {
    const out = applyMutation(base, parseMutation('query:page=2'));
    const url = new URL(out.url);
    assert.equal(url.searchParams.get('page'), '2');
    assert.equal(url.searchParams.get('sort'), 'asc');
    assert.equal(url.searchParams.get('q'), 'hello');
    assert.equal([...url.searchParams.keys()].length, 3);
  });

  test('one form field changes and the others survive', () => {
    const out = applyMutation(base, parseMutation('form:role=admin'));
    const params = new URLSearchParams(out.body.toString());
    assert.equal(params.get('role'), 'admin');
    assert.equal(params.get('name'), 'alice');
  });

  test('one cookie changes and the jar keeps the rest', () => {
    const out = applyMutation(base, parseMutation('cookie:session=other'));
    const jar = getHeader(out.headers, 'cookie') ?? '';
    assert.ok(jar.includes('session=other'));
    assert.ok(jar.includes('theme=dark'));
    assert.ok(jar.includes('remember=1'));
  });

  test('removing a cookie leaves the others and keeps the header', () => {
    const out = applyMutation(base, parseMutation('-cookie:theme'));
    const jar = getHeader(out.headers, 'cookie') ?? '';
    assert.ok(!jar.includes('theme'));
    assert.ok(jar.includes('session=abc'));
  });

  test('removing the last cookie removes the header rather than sending an empty one', () => {
    let out = base;
    for (const name of ['session', 'theme', 'remember']) {
      out = applyMutation(out, parseMutation(`-cookie:${name}`));
    }
    assert.equal(getHeader(out.headers, 'cookie'), undefined);
  });

  test('add-header keeps the existing one, set-header replaces it', () => {
    assert.deepEqual(getAll(applyMutation(base, parseMutation('+header:X-Trace=two')).headers, 'x-trace'), [
      'one',
      'two',
    ]);
    assert.deepEqual(getAll(applyMutation(base, parseMutation('header:X-Trace=two')).headers, 'x-trace'), [
      'two',
    ]);
  });

  test('a path change keeps the query string', () => {
    const out = applyMutation(base, parseMutation('path=/api/admin'));
    assert.equal(new URL(out.url).pathname, '/api/admin');
    assert.equal(new URL(out.url).search, '?page=1&sort=asc&q=hello');
  });

  test('Content-Length is corrected when it was correct', () => {
    const correct = { ...base, headers: [...base.headers.filter(([k]) => k !== 'Content-Length'), ['Content-Length', String(base.body.length)] as [string, string]] };
    const out = applyMutation(correct, parseMutation('form:role=administrator'));
    assert.equal(Number(getHeader(out.headers, 'content-length')), out.body.length);
  });

  test('a deliberately wrong Content-Length is left wrong', () => {
    const out = applyMutation(base, parseMutation('form:role=administrator'));
    assert.equal(getHeader(out.headers, 'content-length'), '21');
  });
});

describe('editing JSON bodies by path', () => {
  test('a nested field is set and the rest is preserved', () => {
    const out = setJsonPointer('{"user":{"id":1,"role":"user"},"other":true}', 'user.role', 'admin');
    assert.deepEqual(JSON.parse(out), { user: { id: 1, role: 'admin' }, other: true });
  });

  test('a numeric segment indexes an array', () => {
    const out = setJsonPointer('{"items":[{"qty":1},{"qty":2}]}', 'items.1.qty', '-1');
    assert.deepEqual(JSON.parse(out), { items: [{ qty: 1 }, { qty: -1 }] });
  });

  test('a value that parses as JSON keeps its type, which is often the test', () => {
    assert.equal(JSON.parse(setJsonPointer('{"a":1}', 'a', '-1')).a, -1);
    assert.equal(JSON.parse(setJsonPointer('{"a":1}', 'a', 'true')).a, true);
    assert.equal(JSON.parse(setJsonPointer('{"a":1}', 'a', 'null')).a, null);
    assert.deepEqual(JSON.parse(setJsonPointer('{"a":1}', 'a', '[1,2]')).a, [1, 2]);
  });

  test('a value that is not JSON stays a string', () => {
    assert.equal(JSON.parse(setJsonPointer('{"a":1}', 'a', 'admin')).a, 'admin');
  });

  test('a new field can be added', () => {
    assert.equal(JSON.parse(setJsonPointer('{}', 'isAdmin', 'true')).isAdmin, true);
  });

  test('a non-JSON body says what to use instead', () => {
    assert.throws(() => setJsonPointer('role=user', 'role', 'admin'), /Use form: for urlencoded/);
  });

  test('walking into a scalar is an error naming the path', () => {
    assert.throws(() => setJsonPointer('{"a":1}', 'a.b.c', 'x'), /cannot walk into a because it is number/);
  });

  test('an empty path is an error showing the shape', () => {
    assert.throws(() => setJsonPointer('{}', '', 'x'), /needs a field path/);
  });
});

describe('the editable text form round-trips', () => {
  test('comments are stripped and the request survives', () => {
    const original = makeRequest({
      method: 'POST',
      url: 'https://target.example/x',
      headers: [
        ['Host', 'target.example'],
        ['X-A', '1'],
      ],
      body: Buffer.from('payload'),
    });
    const back = fromEditable(toEditable(original), 'https://target.example');
    assert.equal(back.method, 'POST');
    assert.equal(back.url, original.url);
    assert.deepEqual(back.headers, original.headers);
    assert.equal(back.body.toString(), 'payload');
  });

  test('the header says nothing is recomputed, because nothing is', () => {
    assert.match(toEditable(makeRequest()), /Nothing is recomputed/);
  });
});

describe('body kind detection', () => {
  test('from the content type when it is declared', () => {
    assert.equal(
      bodyKind(makeRequest({ headers: [['Content-Type', 'application/json']], body: Buffer.from('{}') })),
      'json',
    );
    assert.equal(
      bodyKind(
        makeRequest({
          headers: [['Content-Type', 'application/x-www-form-urlencoded']],
          body: Buffer.from('a=1'),
        }),
      ),
      'form',
    );
  });

  test('from the bytes when it is not', () => {
    assert.equal(bodyKind(makeRequest({ body: Buffer.from('{"a":1}') })), 'json');
    assert.equal(bodyKind(makeRequest({ body: Buffer.from('a=1&b=2') })), 'form');
    assert.equal(bodyKind(makeRequest({ body: Buffer.from('\x00\x01binary') })), 'other');
  });

  test('an empty body says so', () => {
    assert.equal(bodyKind(makeRequest()), 'empty');
  });
});

describe('replay checks scope after mutation, not before', () => {
  test('a mutation that moves the request off-scope is refused', async () => {
    const scope = parseScopeConfig({ include: ['https://target.example'] });
    await assert.rejects(
      () =>
        replay(makeRequest({ url: 'https://target.example/x' }), {
          scope,
          mutations: [{ kind: 'set-header', name: 'Host', value: 'elsewhere.example' }, { kind: 'set-path', value: '/y' }],
          raw: 'GET http://elsewhere.example/y HTTP/1.1\r\nHost: elsewhere.example\r\n\r\n',
        }),
      ScopeViolation,
    );
  });

  test('an empty scope refuses everything', async () => {
    await assert.rejects(
      () => replay(makeRequest(), { scope: EMPTY_SCOPE }),
      /refusing to send a request/,
    );
  });

  test('buildReplayRequest produces the bytes without sending them', () => {
    const { request, applied } = buildReplayRequest(makeRequest({ url: 'https://target.example/a?id=1' }), {
      scope: EMPTY_SCOPE,
      mutations: [parseMutation('query:id=2'), parseMutation('header:X-Forwarded-For=127.0.0.1')],
    });
    assert.equal(new URL(request.url).searchParams.get('id'), '2');
    assert.equal(getHeader(request.headers, 'x-forwarded-for'), '127.0.0.1');
    assert.deepEqual(applied, ['query id=2', 'header X-Forwarded-For=127.0.0.1']);
  });
});

describe('volatile content is normalised before comparing', () => {
  test('CSRF tokens in hidden inputs', () => {
    const a = '<input name="_csrf_token" value="aaaaaaaaaaaa">';
    const b = '<input name="_csrf_token" value="bbbbbbbbbbbb">';
    assert.equal(normaliseVolatile(a), normaliseVolatile(b));
  });

  test('CSRF tokens in meta tags', () => {
    const a = '<meta name="csrf-token" content="one">';
    const b = '<meta name="csrf-token" content="two">';
    assert.equal(normaliseVolatile(a), normaliseVolatile(b));
  });

  test('UUIDs, timestamps and CSP nonces', () => {
    const a = 'id 123e4567-e89b-12d3-a456-426614174000 at 2026-01-01T00:00:00Z nonce="abc"';
    const b = 'id 00000000-1111-2222-3333-444444444444 at 2026-06-30T12:34:56Z nonce="xyz"';
    assert.equal(normaliseVolatile(a), normaliseVolatile(b));
  });

  test('asset cache busters', () => {
    assert.equal(
      normaliseVolatile('<script src="/app.js?v=abc123">'),
      normaliseVolatile('<script src="/app.js?v=def456">'),
    );
  });

  test('real content is not normalised away', () => {
    assert.notEqual(normaliseVolatile('<p>alice</p>'), normaliseVolatile('<p>bob</p>'));
  });
});

describe('similarity behaves at the edges', () => {
  test('identical text is 1', () => {
    assert.equal(similarity('a\nb\nc', 'a\nb\nc'), 1);
  });

  test('nothing in common is 0', () => {
    assert.equal(similarity('a\nb', 'c\nd'), 0);
  });

  test('two empty strings are identical rather than undefined', () => {
    assert.equal(similarity('', ''), 1);
  });

  test('a partial overlap is between the two', () => {
    const s = similarity('a\nb\nc\nd', 'a\nb\nc\ne');
    assert.ok(s > 0.5 && s < 1, `expected a middling score, got ${s}`);
  });

  test('a short one-line change scores high, not zero', () => {
    // Line shingles would score this 0 -- the two share no whole line -- and
    // every row of an enumeration would then look like a finding.
    const s = similarity('record 1 ok', 'record 2 ok');
    assert.ok(s > 0.4, `expected a high score for a one-character change, got ${s}`);
  });

  test('a long document with one changed row still scores near 1', () => {
    const rows = Array.from({ length: 200 }, (_, i) => `<tr><td>row ${i}</td></tr>`);
    const before = rows.join('\n');
    const after = [...rows.slice(0, 199), '<tr><td>row CHANGED</td></tr>'].join('\n');
    const s = similarity(before, after);
    assert.ok(s > 0.98, `expected near-identical, got ${s}`);
  });

  test('two short but genuinely unrelated bodies score low', () => {
    assert.ok(similarity('access denied', 'welcome back alice') < 0.3);
  });
});

describe('materiality ignores similarity on bodies too small to judge', () => {
  test('a one-character change in a tiny body is not material on its own', () => {
    const d = diffResponses(
      makeResponse({ body: Buffer.from('record 1 ok') }),
      makeResponse({ body: Buffer.from('record 2 ok') }),
    );
    assert.equal(isMaterial(d), false);
  });

  test('the same change with a status change is material', () => {
    const d = diffResponses(
      makeResponse({ body: Buffer.from('record 1 ok') }),
      makeResponse({ status: 403, body: Buffer.from('record 2 ok') }),
    );
    assert.ok(isMaterial(d));
  });

  test('a proportionally large growth in a small body is material', () => {
    const d = diffResponses(
      makeResponse({ body: Buffer.from('ok') }),
      makeResponse({ body: Buffer.from('x'.repeat(600)) }),
    );
    assert.ok(isMaterial(d));
  });

  test('a genuinely different page of real size is material', () => {
    const d = diffResponses(
      makeResponse({ body: Buffer.from('<p>denied</p>\n'.repeat(60)) }),
      makeResponse({ body: Buffer.from('<p>welcome alice, here is the admin panel</p>\n'.repeat(60)) }),
    );
    assert.ok(isMaterial(d));
  });
});

describe('response diffing reports structure and judges materiality', () => {
  test('a status change is material', () => {
    const d = diffResponses(makeResponse({ status: 200 }), makeResponse({ status: 302 }));
    assert.ok(d.statusChanged);
    assert.ok(isMaterial(d));
    assert.match(d.summary, /status 200 -> 302/);
  });

  test('two identical responses are not material', () => {
    const d = diffResponses(makeResponse(), makeResponse());
    assert.equal(d.similarity, 1);
    assert.equal(isMaterial(d), false);
    assert.match(d.summary, /no material difference/);
  });

  test('a response differing only in a volatile header is not material', () => {
    const d = diffResponses(
      makeResponse({ headers: [['Content-Type', 'text/html'], ['Date', 'Mon, 01 Jan 2026 00:00:00 GMT']] }),
      makeResponse({ headers: [['Content-Type', 'text/html'], ['Date', 'Tue, 02 Jan 2026 00:00:00 GMT']] }),
    );
    assert.deepEqual(d.headers, []);
    assert.equal(isMaterial(d), false);
  });

  test('a new Set-Cookie is material even when the body is identical', () => {
    const d = diffResponses(
      makeResponse(),
      makeResponse({ headers: [['Content-Type', 'text/html'], ['Set-Cookie', 'admin=1']] }),
    );
    assert.ok(d.headers.some((h) => h.name === 'set-cookie' && h.kind === 'added'));
    assert.ok(isMaterial(d));
  });

  test('added and removed lines are reported and capped', () => {
    const before = makeResponse({ body: Buffer.from('keep\nold-one\nold-two') });
    const after = makeResponse({ body: Buffer.from('keep\nnew-one\nnew-two') });
    const d = diffResponses(before, after, { maxLines: 1 });
    assert.equal(d.addedLines.length, 1);
    assert.equal(d.removedLines.length, 1);
  });

  test('header diffing distinguishes added, removed and changed', () => {
    const diffs = diffHeaders(
      [['A', '1'], ['B', '2']],
      [['A', '9'], ['C', '3']],
    );
    assert.deepEqual(
      diffs.map((d) => [d.name, d.kind]),
      [
        ['a', 'changed'],
        ['b', 'removed'],
        ['c', 'added'],
      ],
    );
  });

  test('duplicate headers are compared as the list they are', () => {
    const diffs = diffHeaders([['Set-Cookie', 'a=1']], [['Set-Cookie', 'a=1'], ['Set-Cookie', 'b=2']]);
    assert.equal(diffs[0]?.kind, 'changed');
    assert.deepEqual(diffs[0]?.after, ['a=1', 'b=2']);
  });

  test('a large size change with high similarity is still material', () => {
    const d = diffResponses(
      makeResponse({ body: Buffer.from('row\n'.repeat(10)) }),
      makeResponse({ body: Buffer.from('row\n'.repeat(400)) }),
    );
    assert.ok(isMaterial(d), 'a list that got much longer is the signal in an IDOR test');
  });

  test('exact mode does not normalise', () => {
    const a = makeResponse({ body: Buffer.from('<meta name="csrf-token" content="one">') });
    const b = makeResponse({ body: Buffer.from('<meta name="csrf-token" content="two">') });
    assert.equal(diffResponses(a, b).similarity, 1);
    assert.ok(diffResponses(a, b, { exact: true }).similarity < 1);
  });
});

describe('reflections are found and their context classified', () => {
  const canary = 'awbc4n4ry';

  test('a verbatim body reflection is reported with context', () => {
    const r = findReflections(makeResponse({ body: Buffer.from(`<p>hello ${canary}</p>`) }), canary);
    assert.equal(r.length, 1);
    assert.equal(r[0]?.where, 'body');
    assert.equal(r[0]?.verbatim, true);
    assert.ok(r[0]?.context.includes(canary));
  });

  test('an escaped reflection is reported as not verbatim, which is the difference that matters', () => {
    const r = findReflections(
      makeResponse({ body: Buffer.from(`<p>&lt;${canary}&gt;</p>`) }),
      `<${canary}>`,
    );
    assert.equal(r.length, 1);
    assert.equal(r[0]?.verbatim, false);
  });

  test('a header reflection is reported separately', () => {
    const r = findReflections(
      makeResponse({ headers: [['Location', `/next?from=${canary}`]], body: Buffer.alloc(0) }),
      canary,
    );
    assert.equal(r[0]?.where, 'header');
    assert.equal(r[0]?.headerName, 'Location');
  });

  test('several occurrences are all reported, up to the limit', () => {
    const body = Buffer.from(`${canary} ${canary} ${canary} ${canary}`);
    assert.equal(findReflections(makeResponse({ body }), canary, 3).length, 3);
  });

  test('a value too short to be meaningful is not searched for', () => {
    assert.deepEqual(findReflections(makeResponse({ body: Buffer.from('aaa') }), 'a'), []);
  });

  test('no reflection returns nothing rather than a guess', () => {
    assert.deepEqual(findReflections(makeResponse(), canary), []);
  });

  test('context classification distinguishes the cases that decide exploitability', () => {
    const cases: readonly [string, string][] = [
      [`<p>${canary}</p>`, 'html-text'],
      [`<input value="${canary}">`, 'attribute-double'],
      [`<input value='${canary}'>`, 'attribute-single'],
      [`<input value=${canary}>`, 'attribute-unquoted'],
      [`<script>var a="${canary}"</script>`, 'script'],
      [`<style>.a{content:"${canary}"}</style>`, 'style'],
      [`<!-- ${canary} -->`, 'comment'],
      [`<a href="${canary}">x</a>`, 'url'],
    ];
    for (const [html, expected] of cases) {
      assert.equal(classifyContext(html, canary), expected, `for ${html}`);
    }
  });

  test('a value not present in the context is unknown rather than guessed', () => {
    assert.equal(classifyContext('<p>nothing here</p>', canary), 'unknown');
  });
});
