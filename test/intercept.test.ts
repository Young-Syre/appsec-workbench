import { strict as assert } from 'node:assert';
import { createServer as createHttpServer, type Server } from 'node:http';
import { connect as netConnect } from 'node:net';
import { join } from 'node:path';
import test, { after, before, describe } from 'node:test';

import { Proxy } from '../src/proxy/server.js';
import { createCa, caPaths } from '../src/proxy/ca.js';
import { parseScopeConfig } from '../src/core/scope.js';
import type { Exchange, HttpRequest } from '../src/core/message.js';
import {
  type Held,
  Interceptor,
  lengthMismatch,
  stripEditorNewline,
  withFixedLength,
} from '../src/proxy/intercept.js';
import { InterceptConsole } from '../src/cli/intercept-ui.js';
import { fromEditable, toEditable } from '../src/replay/replay.js';
import { get as getHeader } from '../src/core/headers.js';
import { makeRequest, makeResponse, tempDir } from './helpers.js';

interface Origin {
  readonly port: number;
  readonly hits: { url: string; headers: string[]; body: string }[];
  close: () => Promise<void>;
}

async function origin(body = '<html><body>origin</body></html>'): Promise<Origin> {
  const hits: Origin['hits'] = [];
  const server: Server = createHttpServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      hits.push({ url: req.url ?? '', headers: req.rawHeaders, body: Buffer.concat(chunks).toString() });
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(body);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  return {
    port: typeof addr === 'object' && addr !== null ? addr.port : 0,
    hits,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

function viaProxy(
  proxyPort: number,
  url: string,
  extra: [string, string][] = [],
): Promise<{ status: number; head: string; body: string }> {
  const u = new URL(url);
  const wire =
    `GET ${url} HTTP/1.1\r\nHost: ${u.host}\r\n` +
    extra.map(([k, v]) => `${k}: ${v}\r\n`).join('') +
    'Connection: close\r\n\r\n';
  return new Promise((resolve, reject) => {
    const socket = netConnect({ host: '127.0.0.1', port: proxyPort }, () => socket.write(wire));
    const chunks: Buffer[] = [];
    socket.on('data', (c: Buffer) => chunks.push(c));
    socket.on('close', () => {
      const raw = Buffer.concat(chunks).toString('latin1');
      const split = raw.indexOf('\r\n\r\n');
      resolve({
        status: Number(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(raw)?.[1] ?? 0),
        head: split < 0 ? raw : raw.slice(0, split),
        body: split < 0 ? '' : raw.slice(split + 4),
      });
    });
    socket.on('error', reject);
    socket.setTimeout(10_000, () => reject(new Error('viaProxy timed out')));
  });
}

function nextHeld(interceptor: Interceptor): Promise<Held> {
  return new Promise((resolve) => interceptor.once('held', resolve));
}

// ---------------------------------------------------------------------------

describe('the interceptor queue', () => {
  test('a held request waits until it is forwarded', async () => {
    const interceptor = new Interceptor();
    const request = makeRequest();
    let settled = false;
    const decision = interceptor.holdRequest(request).then((d) => {
      settled = true;
      return d;
    });
    await new Promise((r) => setImmediate(r));
    assert.equal(settled, false, 'nothing was decided, so nothing may move');
    assert.equal(interceptor.size, 1);
    const head = interceptor.head();
    assert.ok(head !== undefined);
    interceptor.forward(head.id);
    assert.deepEqual(await decision, { action: 'forward', by: 'operator' });
    assert.equal(interceptor.size, 0);
  });

  test('a forward carries the edit, and a drop carries none', async () => {
    const interceptor = new Interceptor();
    const first = interceptor.holdRequest(makeRequest());
    const second = interceptor.holdRequest(makeRequest());
    const [a, b] = interceptor.queue();
    assert.ok(a !== undefined && b !== undefined);
    const edited = makeRequest({ method: 'POST' });
    interceptor.forward(a.id, edited);
    interceptor.drop(b.id);
    assert.equal((await first).request, edited);
    assert.deepEqual(await second, { action: 'drop', by: 'operator' });
  });

  test('decisions are addressed by id, so a stale one changes nothing', async () => {
    const interceptor = new Interceptor();
    void interceptor.holdRequest(makeRequest());
    const id = interceptor.head()?.id ?? -1;
    assert.equal(interceptor.forward(id), true);
    assert.equal(interceptor.forward(id), false);
    assert.equal(interceptor.drop(id), false);
  });

  test('when interception is off, nothing waits', async () => {
    const interceptor = new Interceptor({ requests: false });
    assert.deepEqual(await interceptor.holdRequest(makeRequest()), { action: 'forward', by: 'released' });
    assert.equal(interceptor.size, 0);
  });

  test('switching interception off releases everything waiting, unedited', async () => {
    const interceptor = new Interceptor();
    const held = [interceptor.holdRequest(makeRequest()), interceptor.holdRequest(makeRequest())];
    interceptor.setRequests(false);
    for (const d of await Promise.all(held)) assert.deepEqual(d, { action: 'forward', by: 'released' });
  });

  test('responses are only held when asked for', async () => {
    const off = new Interceptor();
    assert.equal((await off.holdResponse(makeRequest(), makeResponse())).by, 'released');
    const on = new Interceptor({ responses: true });
    const pending = on.holdResponse(makeRequest(), makeResponse());
    assert.equal(on.head()?.kind, 'response');
    on.forward(on.head()?.id ?? -1);
    assert.equal((await pending).by, 'operator');
  });

  test('the filter decides what is held', async () => {
    const interceptor = new Interceptor({ filter: { url: /\/api\//, method: /^post$/i } });
    assert.equal((await interceptor.holdRequest(makeRequest({ url: 'https://target.example/api/x' }))).by, 'released');
    assert.equal(
      (await interceptor.holdRequest(makeRequest({ method: 'POST', url: 'https://target.example/home' }))).by,
      'released',
    );
    void interceptor.holdRequest(makeRequest({ method: 'POST', url: 'https://target.example/api/x' }));
    assert.equal(interceptor.size, 1);
    interceptor.releaseAll();
  });

  test('a deadline applies the fallback and says it was the deadline', async () => {
    const forwarding = new Interceptor({ timeoutMs: 20 });
    assert.deepEqual(await forwarding.holdRequest(makeRequest()), { action: 'forward', by: 'timeout' });
    const dropping = new Interceptor({ timeoutMs: 20, onTimeout: 'drop' });
    assert.deepEqual(await dropping.holdRequest(makeRequest()), { action: 'drop', by: 'timeout' });
  });

  test('a client hanging up takes its request out of the queue', async () => {
    const interceptor = new Interceptor();
    const controller = new AbortController();
    const pending = interceptor.holdRequest(makeRequest(), controller.signal);
    assert.equal(interceptor.size, 1);
    controller.abort();
    assert.deepEqual(await pending, { action: 'drop', by: 'abandoned' });
    assert.equal(interceptor.size, 0);
  });
});

describe('editing helpers', () => {
  test('the newline an editor appends is removed, once', () => {
    assert.equal(stripEditorNewline('abc', 'abc\n'), 'abc');
    assert.equal(stripEditorNewline('abc', 'abc\r\n'), 'abc');
    assert.equal(stripEditorNewline('abc', 'abc\n\n'), 'abc\n');
    assert.equal(stripEditorNewline('abc\n', 'abc\n'), 'abc\n', 'a newline that was written survives');
  });

  test('a length mismatch is reported, not fixed, unless fixing is asked for', () => {
    const request = makeRequest({
      method: 'POST',
      headers: [['Host', 'target.example'], ['Content-Length', '3']],
      body: Buffer.from('hello'),
    });
    assert.deepEqual(lengthMismatch(request), { declared: '3', actual: 5 });
    const fixed = withFixedLength(request);
    assert.equal(getHeader(fixed.headers, 'content-length'), '5');
    assert.equal(lengthMismatch(fixed), undefined);
    assert.equal(lengthMismatch(makeRequest()), undefined, 'no Content-Length, nothing to disagree with');
  });

  test('an edited body keeps the newlines it was saved with', () => {
    const original = makeRequest({
      method: 'POST',
      headers: [['Host', 'target.example'], ['Content-Type', 'application/json']],
      body: Buffer.from('{\n  "a": 1\n}'),
    });
    const back = fromEditable(toEditable(original), 'https://target.example');
    assert.equal(back.body.toString(), '{\n  "a": 1\n}', 'LF in a body must not become CRLF');
  });
});

describe('the intercept console', () => {
  function harness(saved: (written: string) => string | undefined): {
    interceptor: Interceptor;
    console_: InterceptConsole;
    output: string[];
    edits: string[];
  } {
    const interceptor = new Interceptor({ responses: true });
    const output: string[] = [];
    const edits: string[] = [];
    const console_ = new InterceptConsole(interceptor, {
      write: (t) => output.push(t),
      edit: async (text) => {
        edits.push(text);
        console_.log('a line that arrived mid-edit');
        assert.ok(!output.join('').includes('a line that arrived mid-edit'), 'the editor owns the screen');
        return saved(text);
      },
    });
    return { interceptor, console_, output, edits };
  }

  test('shows the held request, with credentials redacted', async () => {
    const { interceptor, output } = harness(() => undefined);
    const pending = interceptor.holdRequest(
      makeRequest({ headers: [['Host', 'target.example'], ['Cookie', 'session=a9f3c1e7b25d4086b1c4e7f2']] }),
    );
    const screen = output.join('');
    assert.match(screen, /GET \/ HTTP\/1\.1/);
    assert.match(screen, /\[f\]orward/);
    assert.ok(!screen.includes('a9f3c1e7b25d4086b1c4e7f2'), 'the session value must not be on screen');
    interceptor.releaseAll();
    await pending;
  });

  test('f forwards and d drops the message on screen', async () => {
    const { interceptor, console_ } = harness(() => undefined);
    const first = interceptor.holdRequest(makeRequest());
    const second = interceptor.holdRequest(makeRequest());
    await console_.key('f');
    assert.equal((await first).action, 'forward');
    await console_.key('d');
    assert.equal((await second).action, 'drop');
  });

  test('e sends the edit, and lines logged during it are printed afterwards', async () => {
    const { interceptor, console_, output } = harness((written) => written.replace('User-Agent: awb-test', 'User-Agent: edited'));
    const pending = interceptor.holdRequest(makeRequest());
    await console_.key('e');
    const decision = await pending;
    assert.equal(getHeader(decision.request?.headers ?? [], 'user-agent'), 'edited');
    assert.equal(decision.request?.body.length, 0);
    assert.ok(output.join('').includes('a line that arrived mid-edit'));
  });

  test('an edit that breaks Content-Length asks before sending', async () => {
    const original: HttpRequest = makeRequest({
      method: 'POST',
      headers: [['Host', 'target.example'], ['Content-Length', '2']],
      body: Buffer.from('ab'),
    });
    // Saved with the trailing newline an editor adds to a file that lacked one.
    const { interceptor, console_, output } = harness((written) => `${written.replace(/ab$/, 'abcdef')}\n`);
    const pending = interceptor.holdRequest(original);
    await console_.key('e');
    assert.match(output.join(''), /Content-Length says 2 and the body is 6 bytes/);
    assert.equal(interceptor.size, 1, 'nothing is sent until the operator answers');
    await console_.key('l');
    const decision = await pending;
    assert.equal(getHeader(decision.request?.headers ?? [], 'content-length'), '6');
  });

  test('forwarding the mismatch as edited keeps the wrong length', async () => {
    const { interceptor, console_ } = harness((written) => written.replace(/ab$/, 'abcdef'));
    const pending = interceptor.holdRequest(
      makeRequest({ method: 'POST', headers: [['Host', 'target.example'], ['Content-Length', '2']], body: Buffer.from('ab') }),
    );
    await console_.key('e');
    await console_.key('f');
    assert.equal(getHeader((await pending).request?.headers ?? [], 'content-length'), '2');
  });

  test('an abandoned edit leaves the original held', async () => {
    const { interceptor, console_ } = harness(() => undefined);
    const pending = interceptor.holdRequest(makeRequest());
    await console_.key('e');
    assert.equal(interceptor.size, 1);
    await console_.key('f');
    assert.equal((await pending).request, undefined);
  });

  test('a response is edited as decoded text', async () => {
    const { interceptor, console_ } = harness((written) => written.replace('ok', 'changed'));
    const pending = interceptor.holdResponse(makeRequest(), makeResponse());
    await console_.key('e');
    assert.equal((await pending).response?.body.toString(), '<html><body>changed</body></html>');
  });
});

describe('interception through the proxy', () => {
  let target: Origin;
  let elsewhere: Origin;
  let proxy: Proxy;
  let interceptor: Interceptor;
  const recorded: Exchange[] = [];

  before(async () => {
    const caDir = join(tempDir(), 'ca');
    createCa(caDir);
    target = await origin();
    elsewhere = await origin('<html>elsewhere</html>');
    interceptor = new Interceptor({ responses: true });
    proxy = new Proxy({
      port: 0,
      scope: parseScopeConfig({ include: [`http://127.0.0.1:${target.port}`] }),
      ca: caPaths(caDir),
      interceptor,
      onExchange: (e) => recorded.push(e),
    });
    await proxy.listen();
  });

  after(async () => {
    await proxy.close();
    await target.close();
    await elsewhere.close();
  });

  test('an edited request is what reaches the target, and is tagged', async () => {
    const before_ = target.hits.length;
    const held = nextHeld(interceptor);
    const reply = viaProxy(proxy.port, `http://127.0.0.1:${target.port}/a`);
    const h = await held;
    assert.equal(h.kind, 'request');
    if (h.kind !== 'request') return;
    interceptor.forward(h.id, { ...h.request, headers: [...h.request.headers, ['X-Edited', 'yes']] });
    const response = await nextHeld(interceptor);
    interceptor.forward(response.id);
    assert.equal((await reply).status, 200);
    const hit = target.hits[before_];
    assert.ok(hit !== undefined);
    assert.ok(hit.headers.includes('X-Edited'));
    assert.ok(recorded.at(-1)?.tags.includes('intercept:edited'));
  });

  test('a dropped request is never sent and never recorded', async () => {
    const before_ = target.hits.length;
    const recordedBefore = recorded.length;
    const held = nextHeld(interceptor);
    const reply = viaProxy(proxy.port, `http://127.0.0.1:${target.port}/b`);
    interceptor.drop((await held).id);
    const r = await reply;
    assert.equal(r.status, 502);
    assert.match(r.head, /x-awb-intercept: dropped/i);
    assert.equal(target.hits.length, before_);
    assert.equal(recorded.length, recordedBefore);
  });

  test('an edit that retargets out of scope is refused, and nothing reaches the other host', async () => {
    const held = nextHeld(interceptor);
    const reply = viaProxy(proxy.port, `http://127.0.0.1:${target.port}/c`);
    const h = await held;
    if (h.kind !== 'request') throw new Error('expected a request');
    interceptor.forward(h.id, {
      ...h.request,
      url: `http://127.0.0.1:${elsewhere.port}/c`,
      headers: [['Host', `127.0.0.1:${elsewhere.port}`]],
    });
    const r = await reply;
    assert.equal(r.status, 403);
    assert.match(r.body, /refused the edited request/);
    assert.equal(elsewhere.hits.length, 0);
  });

  test('an edited response reaches the browser; the record keeps what the target sent', async () => {
    const held = nextHeld(interceptor);
    const reply = viaProxy(proxy.port, `http://127.0.0.1:${target.port}/d`);
    interceptor.forward((await held).id);
    const response = await nextHeld(interceptor);
    if (response.kind !== 'response') throw new Error('expected a response');
    interceptor.forward(response.id, { ...response.response, body: Buffer.from('<html>edited</html>') });
    const r = await reply;
    assert.equal(r.body, '<html>edited</html>');
    const last = recorded.at(-1);
    assert.equal(last?.response?.body.toString(), '<html><body>origin</body></html>');
    assert.ok(last?.tags.includes('intercept:response-edited'));
  });

  test('out-of-scope traffic is never held', async () => {
    const sizeBefore = interceptor.size;
    const r = await viaProxy(proxy.port, `http://127.0.0.1:${elsewhere.port}/`);
    assert.equal(r.status, 403);
    assert.equal(interceptor.size, sizeBefore);
  });
});
