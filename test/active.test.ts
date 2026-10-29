import { strict as assert } from 'node:assert';
import { createServer, type Server } from 'node:http';
import test, { after, before, describe } from 'node:test';

import {
  ActiveSender,
  BudgetExhausted,
  type ActiveContext,
  type InjectionPoint,
  inject,
  injectionPoints,
  judgeTiming,
  median,
  spread,
} from '../src/scan/active/runner.js';
import {
  ACTIVE_CHECKS,
  activeCheckById,
  corsOriginCheck,
  estimateCost,
  hostHeaderCheck,
  methodTamperingCheck,
  openRedirectCheck,
  pathTraversalCheck,
  reflectionCheck,
  sqlInjectionCheck,
  templateInjectionCheck,
} from '../src/scan/active/checks.js';
import { parseScopeConfig, EMPTY_SCOPE } from '../src/core/scope.js';
import type { Authorisation } from '../src/core/authorization.js';
import type { Exchange, HttpRequest } from '../src/core/message.js';
import { makeRequest } from './helpers.js';

const AUTH: Authorisation = {
  engagement: 'appsec-workbench self-test',
  authorisedBy: 'the test suite, against its own loopback server',
  from: '2020-01-01',
  until: '2099-12-31',
  reference: 'test/active.test.ts',
};

/**
 * A deliberately broken application, on loopback.
 *
 * Every defect here is one of the checks' targets, and several endpoints are
 * the *correct* version of the same thing, because a check that cannot stay
 * quiet is worse than no check.
 */
async function vulnerableApp(): Promise<{ port: number; close: () => Promise<void>; seen: string[] }> {
  const seen: string[] = [];
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url ?? '/', 'http://localhost');
      const q = (name: string): string => url.searchParams.get(name) ?? '';
      seen.push(`${req.method} ${url.pathname}`);
      const method = req.method ?? 'GET';
      const html = (body: string, extra: Record<string, string> = {}): void => {
        res.writeHead(200, { 'content-type': 'text/html', ...extra });
        res.end(body);
      };

      switch (url.pathname) {
        // --- reflection ---------------------------------------------------
        case '/echo-raw':
          // Unescaped, in HTML text context.
          html(`<html><body><p>Hello ${q('name')}</p></body></html>`);
          return;
        case '/echo-escaped':
          html(
            `<html><body><p>Hello ${q('name')
              .replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#39;')}</p></body></html>`,
          );
          return;
        case '/echo-attr':
          // Reflected inside a double-quoted attribute, quote not escaped.
          html(`<html><body><input value="${q('name')}"></body></html>`);
          return;
        case '/no-echo':
          html('<html><body><p>nothing reflected here</p></body></html>');
          return;

        // --- sql ------------------------------------------------------------
        case '/sql-error': {
          const id = q('id');
          if (id.includes("'")) {
            res.writeHead(500, { 'content-type': 'text/html' });
            res.end(`<pre>You have an error in your SQL syntax near '${id}'</pre>`);
            return;
          }
          html('<html><body><p>record found</p></body></html>');
          return;
        }
        case '/sql-boolean': {
          const id = q('id');
          // Simulates a condition: the true variant behaves like the
          // unmodified request, the false variant returns nothing.
          const truthy = id === '1' || /AND '1'='1/.test(id);
          html(
            truthy
              ? '<html><body><h1>Record 1</h1><p>Alice Smith, alice@example.com, member since 2021</p></body></html>'
              : '<html><body><p>No matching record.</p></body></html>',
          );
          return;
        }
        case '/sql-safe': {
          // Rejects odd input identically whatever it is: not injectable, and
          // the boolean check must not fire on it.
          const id = q('id');
          if (!/^\d+$/.test(id)) {
            res.writeHead(400, { 'content-type': 'text/html' });
            res.end('<html><body><p>id must be a number</p></body></html>');
            return;
          }
          html('<html><body><h1>Record</h1></body></html>');
          return;
        }

        // --- template -------------------------------------------------------
        case '/template': {
          const greeting = q('greeting');
          const evaluated = greeting.replace(/\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}/g, (_w, a: string, b: string) =>
            String(Number(a) * Number(b)),
          );
          html(`<html><body><p>${evaluated}</p></body></html>`);
          return;
        }

        // --- redirect -------------------------------------------------------
        case '/login':
          res.writeHead(302, { location: q('next') || '/dashboard' });
          res.end();
          return;
        case '/login-safe': {
          const next = q('next');
          res.writeHead(302, { location: next.startsWith('/') && !next.startsWith('//') ? next : '/dashboard' });
          res.end();
          return;
        }

        // --- cors -----------------------------------------------------------
        case '/api/me': {
          const origin = req.headers.origin;
          res.writeHead(200, {
            'content-type': 'application/json',
            ...(origin === undefined
              ? {}
              : {
                  'access-control-allow-origin': String(origin),
                  'access-control-allow-credentials': 'true',
                  vary: 'Origin',
                }),
          });
          res.end('{"user":"alice"}');
          return;
        }
        case '/api/strict': {
          const origin = req.headers.origin;
          const allowed = ['https://app.target.example'];
          res.writeHead(200, {
            'content-type': 'application/json',
            ...(typeof origin === 'string' && allowed.includes(origin)
              ? { 'access-control-allow-origin': origin, vary: 'Origin' }
              : {}),
          });
          res.end('{"user":"alice"}');
          return;
        }
        case '/api/prefix-match': {
          // The classic broken check: startsWith against the allowed host.
          const origin = typeof req.headers.origin === 'string' ? req.headers.origin : '';
          res.writeHead(200, {
            'content-type': 'application/json',
            ...(origin.startsWith('https://127.0.0.1')
              ? { 'access-control-allow-origin': origin, 'access-control-allow-credentials': 'true' }
              : {}),
          });
          res.end('{"user":"alice"}');
          return;
        }

        // --- traversal ------------------------------------------------------
        case '/download': {
          const file = q('file');
          const decoded = (() => {
            try {
              return decodeURIComponent(file);
            } catch {
              return file;
            }
          })();
          if (decoded.replace(/\.\.\.\./g, '..').includes('../') && decoded.includes('etc/passwd')) {
            res.writeHead(200, { 'content-type': 'text/plain' });
            res.end('root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n');
            return;
          }
          res.writeHead(404, { 'content-type': 'text/plain' });
          res.end('not found');
          return;
        }

        // --- host header ----------------------------------------------------
        case '/reset': {
          const host = req.headers['x-forwarded-host'] ?? req.headers.host ?? '';
          html(`<html><body><a href="https://${String(host)}/reset?token=abc">Reset</a></body></html>`, {
            'cache-control': 'public, max-age=60',
          });
          return;
        }

        // --- method ---------------------------------------------------------
        case '/admin/users': {
          if (method === 'GET') {
            res.writeHead(403, { 'content-type': 'text/html' });
            res.end('<html><body><p>forbidden</p></body></html>');
            return;
          }
          // Authorised per method rather than per action: PUT gets through.
          html('<html><body><h1>User list</h1><p>alice, bob</p></body></html>');
          return;
        }
        case '/profile': {
          html('<html><body><h1>Profile</h1></body></html>');
          return;
        }

        default:
          res.writeHead(404, { 'content-type': 'text/html' });
          res.end('<html><body><p>not found</p></body></html>');
      }
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

describe('injection points are discovered where they are worth testing', () => {
  test('query parameters', () => {
    const points = injectionPoints(makeRequest({ url: 'https://t.example/a?id=1&q=hello' }));
    assert.deepEqual(
      points.filter((p) => p.kind === 'query').map((p) => p.name),
      ['id', 'q'],
    );
  });

  test('identifier-looking path segments, and not the route words', () => {
    const points = injectionPoints(
      makeRequest({ url: 'https://t.example/api/v1/users/4821/orders/9f2c8a1b4e6d' }),
    );
    const segments = points.filter((p) => p.kind === 'path-segment');
    assert.deepEqual(segments.map((p) => p.original), ['4821', '9f2c8a1b4e6d']);
  });

  test('a UUID path segment is found', () => {
    const points = injectionPoints(
      makeRequest({ url: 'https://t.example/o/123e4567-e89b-12d3-a456-426614174000' }),
    );
    assert.equal(points.filter((p) => p.kind === 'path-segment').length, 1);
  });

  test('form fields', () => {
    const points = injectionPoints(
      makeRequest({
        method: 'POST',
        headers: [['Content-Type', 'application/x-www-form-urlencoded']],
        body: Buffer.from('user=alice&role=member'),
      }),
    );
    assert.deepEqual(points.filter((p) => p.kind === 'form').map((p) => p.name), ['user', 'role']);
  });

  test('JSON leaves, by dotted path, including inside arrays', () => {
    const points = injectionPoints(
      makeRequest({
        method: 'POST',
        headers: [['Content-Type', 'application/json']],
        body: Buffer.from('{"user":{"id":7,"role":"member"},"items":[{"sku":"a"}]}'),
      }),
    );
    assert.deepEqual(
      points.filter((p) => p.kind === 'json').map((p) => p.name),
      ['user.id', 'user.role', 'items.0.sku'],
    );
  });

  test('cookies', () => {
    const points = injectionPoints(
      makeRequest({ headers: [['Host', 't.example'], ['Cookie', 'session=abc; theme=dark']] }),
    );
    assert.deepEqual(points.filter((p) => p.kind === 'cookie').map((p) => p.name), ['session', 'theme']);
  });

  test('ordinary headers are not enumerated, because the yield does not justify the traffic', () => {
    const points = injectionPoints(
      makeRequest({
        headers: [
          ['Host', 't.example'],
          ['User-Agent', 'x'],
          ['Accept', '*/*'],
          ['Accept-Language', 'en'],
        ],
      }),
    );
    assert.equal(points.filter((p) => p.kind === 'header').length, 0);
  });

  test('a malformed JSON body yields nothing rather than throwing', () => {
    assert.doesNotThrow(() =>
      injectionPoints(
        makeRequest({
          method: 'POST',
          headers: [['Content-Type', 'application/json']],
          body: Buffer.from('{not json'),
        }),
      ),
    );
  });
});

describe('injection replaces one value and leaves the rest alone', () => {
  const base = makeRequest({
    method: 'POST',
    url: 'https://t.example/a/42/b?id=1&keep=yes',
    headers: [
      ['Host', 't.example'],
      ['Content-Type', 'application/json'],
      ['Cookie', 'session=abc; theme=dark'],
    ],
    body: Buffer.from('{"user":{"role":"member"},"other":true}'),
  });
  const point = (kind: InjectionPoint['kind'], name: string): InjectionPoint =>
    injectionPoints(base).find((p) => p.kind === kind && p.name === name) as InjectionPoint;

  test('a query parameter', () => {
    const out = inject(base, point('query', 'id'), 'X');
    assert.equal(new URL(out.url).searchParams.get('id'), 'X');
    assert.equal(new URL(out.url).searchParams.get('keep'), 'yes');
  });

  test('a path segment, by position among the non-empty segments', () => {
    const out = inject(base, point('path-segment', '1'), 'X');
    assert.equal(new URL(out.url).pathname, '/a/X/b');
  });

  test('a JSON leaf', () => {
    const out = inject(base, point('json', 'user.role'), 'admin');
    assert.deepEqual(JSON.parse(out.body.toString()), { user: { role: 'admin' }, other: true });
  });

  test('a cookie, keeping the others', () => {
    const out = inject(base, point('cookie', 'session'), 'X');
    const jar = out.headers.find(([k]) => k.toLowerCase() === 'cookie')?.[1] ?? '';
    assert.ok(jar.includes('session=X'));
    assert.ok(jar.includes('theme=dark'));
  });
});

describe('the sender is the gate, and it cannot be bypassed', () => {
  const budget = { maxRequests: 3, minIntervalMs: 0 };

  test('an out-of-scope request is refused', async () => {
    const sender = new ActiveSender({ scope: EMPTY_SCOPE, authorisation: AUTH, budget });
    await assert.rejects(() => sender.send(makeRequest(), 'test'), /refusing to send a request/);
  });

  test('the budget is enforced and says how to raise it', async () => {
    const sender = new ActiveSender({
      scope: parseScopeConfig({ include: ['http://127.0.0.1:1'] }),
      authorisation: AUTH,
      budget: { maxRequests: 2, minIntervalMs: 0 },
      sendOptions: { timeoutMs: 1000 },
    });
    await sender.send(makeRequest({ url: 'http://127.0.0.1:1/' }), 't');
    await sender.send(makeRequest({ url: 'http://127.0.0.1:1/' }), 't');
    await assert.rejects(
      () => sender.send(makeRequest({ url: 'http://127.0.0.1:1/' }), 't'),
      BudgetExhausted,
    );
    assert.equal(sender.requestsLeft, 0);
  });

  test('every send is recorded, including the ones that failed', async () => {
    const recorded: Exchange[] = [];
    const sender = new ActiveSender({
      scope: parseScopeConfig({ include: ['http://127.0.0.1:1'] }),
      authorisation: AUTH,
      budget,
      sendOptions: { timeoutMs: 1000 },
      onExchange: (e) => recorded.push(e),
    });
    await sender.send(makeRequest({ url: 'http://127.0.0.1:1/x' }), 'tagged');
    assert.equal(recorded.length, 1);
    assert.equal(recorded[0]?.source, 'active-scan');
    assert.ok(recorded[0]?.tags.includes('check:tagged'));
    assert.ok((recorded[0]?.error ?? '').length > 0);
  });

  test('the authorisation citation travels with the sender', () => {
    const sender = new ActiveSender({ scope: EMPTY_SCOPE, authorisation: AUTH, budget });
    assert.match(sender.citation, /appsec-workbench self-test/);
    assert.match(sender.citation, /test\/active\.test\.ts/);
  });
});

describe('timing is judged against the baseline spread, not a fixed number', () => {
  const samples = (values: readonly number[]) => values.map((v) => ({ elapsedMs: v, status: 200 }));

  test('a clear delay on every sample is reported', () => {
    const verdict = judgeTiming(samples([100, 110, 95, 105]), samples([5100, 5200, 5150]), 5000);
    assert.ok(verdict.delayed);
    assert.match(verdict.reason, /every sample was slow/);
  });

  test('one slow sample among fast ones is not', () => {
    const verdict = judgeTiming(samples([100, 110, 95, 105]), samples([5100, 120, 110]), 5000);
    assert.equal(verdict.delayed, false);
  });

  test('a noisy baseline raises the bar, as it should', () => {
    // A service whose ordinary responses vary by seconds cannot support a
    // five-second timing claim.
    const verdict = judgeTiming(samples([100, 4000, 200, 3800]), samples([5100, 5200, 5000]), 5000);
    assert.equal(verdict.delayed, false);
    assert.match(verdict.reason, /not distinguishable from noise/);
  });

  test('a delay smaller than asked for is not accepted', () => {
    const verdict = judgeTiming(samples([100, 105, 95, 100]), samples([900, 950, 920]), 5000);
    assert.equal(verdict.delayed, false);
  });

  test('median and spread behave at the edges', () => {
    assert.equal(median([]), 0);
    assert.equal(median([5]), 5);
    assert.equal(median([1, 2, 3, 4]), 2.5);
    assert.equal(spread([5]), 0);
    assert.ok(spread([1, 2, 3, 4, 100]) > 0);
  });
});

describe('the checks against a deliberately broken application', () => {
  let app: Awaited<ReturnType<typeof vulnerableApp>>;
  let context: ActiveContext;
  let recorded: Exchange[];

  const request = (path: string, over: Partial<HttpRequest> = {}): HttpRequest =>
    makeRequest({
      url: `http://127.0.0.1:${app.port}${path}`,
      headers: [['Host', `127.0.0.1:${app.port}`]],
      ...over,
    });

  before(async () => {
    app = await vulnerableApp();
    recorded = [];
    context = {
      sender: new ActiveSender({
        scope: parseScopeConfig({ include: [`http://127.0.0.1:${app.port}`] }),
        authorisation: AUTH,
        budget: { maxRequests: 400, minIntervalMs: 0 },
        sendOptions: { timeoutMs: 8000 },
        onExchange: (e) => recorded.push(e),
      }),
    };
  });

  after(async () => {
    await app.close();
  });

  test('an unescaped reflection in HTML text is reported as exploitable', async () => {
    const req = request('/echo-raw?name=world');
    const findings = await reflectionCheck.run(req, injectionPoints(req), context);
    assert.equal(findings.length, 1);
    assert.match(findings[0]?.title ?? '', /Unescaped reflection/);
    assert.match(findings[0]?.title ?? '', /html-text/);
    assert.equal(findings[0]?.severity, 'medium');
    assert.match(findings[0]?.detail ?? '', /awb replay/);
  });

  test('an escaped reflection is reported as info, not as a vulnerability', async () => {
    const req = request('/echo-escaped?name=world');
    const findings = await reflectionCheck.run(req, injectionPoints(req), context);
    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.severity, 'info');
    assert.match(findings[0]?.detail ?? '', /output encoding is doing its job/);
  });

  test('a reflection in a quoted attribute names that context', async () => {
    const req = request('/echo-attr?name=world');
    const findings = await reflectionCheck.run(req, injectionPoints(req), context);
    assert.match(findings[0]?.title ?? '', /attribute-double/);
  });

  test('a parameter that is not reflected produces nothing', async () => {
    const req = request('/no-echo?name=world');
    assert.deepEqual(await reflectionCheck.run(req, injectionPoints(req), context), []);
  });

  test('a SQL error on a quote is reported as critical', async () => {
    const req = request('/sql-error?id=1');
    const findings = await sqlInjectionCheck.run(req, injectionPoints(req), context);
    const errorFinding = findings.find((f) => /MySQL error/.test(f.title));
    assert.ok(errorFinding, `expected an error-based finding, got ${JSON.stringify(findings.map((f) => f.title))}`);
    assert.equal(errorFinding.severity, 'critical');
    assert.equal(errorFinding.evidence.length, 2);
  });

  test('a boolean differential is detected without any error message', async () => {
    const req = request('/sql-boolean?id=1');
    const findings = await sqlInjectionCheck.run(req, injectionPoints(req), context);
    const boolFinding = findings.find((f) => /boolean differential/.test(f.title));
    assert.ok(boolFinding, `expected a boolean finding, got ${JSON.stringify(findings.map((f) => f.title))}`);
    assert.match(boolFinding.detail, /similarity/);
  });

  test('a parameter that rejects odd input identically is not reported', async () => {
    const req = request('/sql-safe?id=1');
    assert.deepEqual(await sqlInjectionCheck.run(req, injectionPoints(req), context), []);
  });

  test('template injection is confirmed by arithmetic', async () => {
    const req = request('/template?greeting=hi');
    const findings = await templateInjectionCheck.run(req, injectionPoints(req), context);
    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.severity, 'critical');
    assert.match(findings[0]?.detail ?? '', /733103/);
  });

  test('a template-free endpoint is not reported', async () => {
    const req = request('/echo-raw?name=hi');
    assert.deepEqual(await templateInjectionCheck.run(req, injectionPoints(req), context), []);
  });

  test('an open redirect is confirmed from the Location header', async () => {
    const req = request('/login?next=/dashboard');
    const findings = await openRedirectCheck.run(req, injectionPoints(req), context);
    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.confidence, 'certain');
    assert.match(findings[0]?.detail ?? '', /awb-open-redirect\.invalid/);
  });

  test('a redirect that validates its destination is not reported', async () => {
    const req = request('/login-safe?next=/dashboard');
    assert.deepEqual(await openRedirectCheck.run(req, injectionPoints(req), context), []);
  });

  test('unconditional CORS reflection with credentials is critical', async () => {
    const req = request('/api/me');
    const findings = await corsOriginCheck.run(req, [], context);
    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.severity, 'critical');
    assert.match(findings[0]?.detail ?? '', /\.invalid TLD/);
  });

  test('an allow-list is not reported', async () => {
    const req = request('/api/strict');
    assert.deepEqual(await corsOriginCheck.run(req, [], context), []);
  });

  test('a prefix-matching origin check is caught by the crafted hostname', async () => {
    const req = request('/api/prefix-match');
    const findings = await corsOriginCheck.run(req, [], context);
    assert.equal(findings.length, 1);
    assert.match(findings[0]?.title ?? '', /crafted hostname/);
    assert.match(findings[0]?.detail ?? '', /prefix of the attacker/);
  });

  test('path traversal is confirmed by the content of the file', async () => {
    const req = request('/download?file=report.pdf');
    const findings = await pathTraversalCheck.run(req, injectionPoints(req), context);
    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.severity, 'critical');
    assert.match(findings[0]?.detail ?? '', /etc\/passwd/);
  });

  test('a reflected X-Forwarded-Host in a cacheable page is high', async () => {
    const req = request('/reset');
    const findings = await hostHeaderCheck.run(req, [], context);
    const hit = findings.find((f) => /X-Forwarded-Host/.test(f.title));
    assert.ok(hit, `expected an X-Forwarded-Host finding, got ${JSON.stringify(findings.map((f) => f.title))}`);
    assert.equal(hit.severity, 'high');
    assert.match(hit.detail, /cache poisoning primitive/);
  });

  test('a route refused for GET but allowed for PUT is reported', async () => {
    const req = request('/admin/users');
    const findings = await methodTamperingCheck.run(req, [], context);
    assert.equal(findings.length, 1);
    assert.match(findings[0]?.title ?? '', /GET is refused but (?:POST|PUT|PATCH|DELETE) is allowed/);
    assert.equal(findings[0]?.severity, 'high');
  });

  test('a route that answers both ways with 200 is not reported as a method bypass', async () => {
    const req = request('/profile');
    const findings = await methodTamperingCheck.run(req, [], context);
    assert.deepEqual(findings, []);
  });

  test('every request the checks made was recorded', () => {
    assert.ok(recorded.length > 20, `expected a full record, saw ${recorded.length} exchanges`);
    for (const exchange of recorded) {
      assert.equal(exchange.source, 'active-scan');
      assert.ok(exchange.tags.some((t) => t.startsWith('check:')));
    }
  });
});

describe('the active registry', () => {
  test('ids are unique and well formed', () => {
    const seen = new Set<string>();
    for (const check of ACTIVE_CHECKS) {
      assert.match(check.id, /^AWB-A\d{3}$/);
      assert.ok(!seen.has(check.id), `${check.id} twice`);
      seen.add(check.id);
      assert.ok(check.costPerPoint >= 1, `${check.id} must declare its cost`);
      assert.ok(check.description.length > 60, `${check.id} needs a real description`);
    }
  });

  test('lookup is case-insensitive', () => {
    assert.equal(activeCheckById('awb-a001')?.id, 'AWB-A001');
    assert.equal(activeCheckById('nope'), undefined);
  });

  test('the cost of a run can be estimated before it starts', () => {
    const cost = estimateCost([reflectionCheck, sqlInjectionCheck], 3);
    assert.equal(cost, reflectionCheck.costPerPoint * 3 + sqlInjectionCheck.costPerPoint * 3);
  });

  test('the check that needs an out-of-band listener declares it', () => {
    assert.ok(ACTIVE_CHECKS.some((c) => c.needsOob === true));
  });
});
