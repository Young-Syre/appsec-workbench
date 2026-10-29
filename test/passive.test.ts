import { strict as assert } from 'node:assert';
import test, { describe } from 'node:test';

import { PASSIVE_CHECKS, scanAll, scanExchange } from '../src/scan/passive/index.js';
import { entropy } from '../src/scan/passive/disclosure.js';
import type { Exchange } from '../src/core/message.js';
import type { Severity } from '../src/core/store.js';
import { makeExchange, makeRequest, makeResponse } from './helpers.js';

/**
 * A fabricated credential, assembled rather than written out.
 *
 * The secret-detection check needs a value that matches a real token shape and
 * clears the entropy floor, so a low-entropy placeholder will not do -- the
 * check correctly refuses those, which is the behaviour the next test asserts.
 * Writing it as one literal would put a token-shaped string in the repository,
 * which hosted secret scanners match on and which is alarming to find in a
 * diff whatever the comment beside it says. So it is concatenated here, and
 * there is no contiguous token-shaped literal in any tracked file.
 *
 * It was never valid for any account anywhere.
 */
const FABRICATED_TOKEN = 'ghp' + '_' + 'A7xK2mV9bN4z' + 'Q1pL8rT6yW3s' + 'D5fG0hJ2cK4n';

/** Build an exchange with just enough shape for a check to have an opinion. */
function ex(over: {
  url?: string;
  method?: string;
  requestHeaders?: [string, string][];
  status?: number;
  responseHeaders?: [string, string][];
  body?: string;
}): Exchange {
  return makeExchange({
    request: makeRequest({
      url: over.url ?? 'https://target.example/',
      method: over.method ?? 'GET',
      headers: over.requestHeaders ?? [['Host', 'target.example']],
    }),
    response: makeResponse({
      status: over.status ?? 200,
      headers: over.responseHeaders ?? [['Content-Type', 'text/html']],
      body: Buffer.from(over.body ?? '<html><body>page</body></html>'),
    }),
  });
}

function ids(exchange: Exchange, only?: string[]): string[] {
  return scanExchange(exchange, only === undefined ? {} : { only }).map((f) => f.title);
}

function severityOf(exchange: Exchange, check: string): Severity | undefined {
  return scanExchange(exchange, { only: [check] })[0]?.severity;
}

describe('the registry is coherent', () => {
  test('every check has a unique id in the AWB-P namespace', () => {
    const seen = new Set<string>();
    for (const check of PASSIVE_CHECKS) {
      assert.match(check.id, /^AWB-P\d{3}$/, `${check.id} is not a well-formed id`);
      assert.ok(!seen.has(check.id), `${check.id} is registered twice`);
      seen.add(check.id);
    }
  });

  test('every check explains itself in a sentence a report can quote', () => {
    for (const check of PASSIVE_CHECKS) {
      assert.ok(check.description.length > 60, `${check.id} needs a real description`);
      assert.ok(check.title.length > 10, `${check.id} needs a real title`);
    }
  });

  test('an exchange with no response produces nothing rather than throwing', () => {
    const { response: _dropped, ...withoutResponse } = makeExchange();
    assert.deepEqual(scanExchange({ ...withoutResponse, error: 'ECONNREFUSED' }), []);
  });

  test('every finding carries at least one piece of evidence', () => {
    const findings = scanExchange(
      ex({ responseHeaders: [['Content-Type', 'text/html'], ['Server', 'nginx/1.24.0']] }),
    );
    assert.ok(findings.length > 0);
    for (const f of findings) assert.ok(f.evidence.length >= 1 && f.evidence[0]?.length === 16);
  });

  test('only and skip select checks', () => {
    const exchange = ex({ responseHeaders: [['Content-Type', 'text/html'], ['Server', 'nginx/1.24.0']] });
    assert.ok(scanExchange(exchange, { only: ['AWB-P007'] }).every((f) => f.check === 'AWB-P007'));
    assert.ok(scanExchange(exchange, { skip: ['AWB-P007'] }).every((f) => f.check !== 'AWB-P007'));
  });
});

describe('browser-protection headers are judged against what the response is', () => {
  test('a JSON API response is not reported for a missing CSP or X-Frame-Options', () => {
    const json = ex({
      responseHeaders: [['Content-Type', 'application/json']],
      body: '{"items":[]}',
    });
    const titles = ids(json, ['AWB-P002', 'AWB-P003']);
    assert.deepEqual(titles, [], `expected silence on a JSON response, got ${JSON.stringify(titles)}`);
  });

  test('an HTML document without a CSP is reported', () => {
    assert.ok(ids(ex({}), ['AWB-P002']).some((t) => /without Content-Security-Policy/.test(t)));
  });

  test('a report-only CSP is called out as not enforcing', () => {
    const titles = ids(
      ex({
        responseHeaders: [
          ['Content-Type', 'text/html'],
          ['Content-Security-Policy-Report-Only', "default-src 'self'"],
        ],
      }),
      ['AWB-P002'],
    );
    assert.ok(titles.some((t) => /report-only/.test(t)));
  });

  test("unsafe-inline is reported, and not reported when a nonce is present too", () => {
    const withUnsafe = ex({
      responseHeaders: [
        ['Content-Type', 'text/html'],
        ['Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'"],
      ],
    });
    assert.ok(ids(withUnsafe, ['AWB-P002']).some((t) => /unsafe-inline/.test(t)));

    const withNonce = ex({
      responseHeaders: [
        ['Content-Type', 'text/html'],
        ['Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-abc123'"],
      ],
    });
    assert.ok(
      !ids(withNonce, ['AWB-P002']).some((t) => /unsafe-inline/.test(t)),
      "a nonce makes 'unsafe-inline' inert, so reporting it would be wrong",
    );
  });

  test('a scheme-wide script source is reported', () => {
    const titles = ids(
      ex({
        responseHeaders: [
          ['Content-Type', 'text/html'],
          ['Content-Security-Policy', "script-src https:; frame-ancestors 'self'; object-src 'none'"],
        ],
      }),
      ['AWB-P002'],
    );
    assert.ok(titles.some((t) => /any origin/.test(t)));
  });

  test('framing is graded by whether the page has anything to click', () => {
    const withForm = ex({ body: '<html><form action="/pay"><button>Pay</button></form></html>' });
    const without = ex({ body: '<html><body><p>just text</p></body></html>' });
    assert.equal(severityOf(withForm, 'AWB-P003'), 'low');
    assert.equal(severityOf(without, 'AWB-P003'), 'info');
  });

  test('frame-ancestors in a CSP satisfies the framing check', () => {
    const covered = ex({
      responseHeaders: [
        ['Content-Type', 'text/html'],
        ['Content-Security-Policy', "frame-ancestors 'self'"],
      ],
      body: '<html><form><button>x</button></form></html>',
    });
    assert.deepEqual(ids(covered, ['AWB-P003']), []);
  });

  test('HSTS is only asked about on HTTPS documents', () => {
    assert.deepEqual(ids(ex({ url: 'http://target.example/' }), ['AWB-P001']), []);
    assert.ok(ids(ex({}), ['AWB-P001']).length > 0);
  });

  test('a short HSTS max-age is reported as info, a missing one as low', () => {
    assert.equal(
      severityOf(
        ex({
          responseHeaders: [['Content-Type', 'text/html'], ['Strict-Transport-Security', 'max-age=600']],
        }),
        'AWB-P001',
      ),
      'info',
    );
    assert.equal(severityOf(ex({}), 'AWB-P001'), 'low');
  });

  test('a long HSTS max-age is accepted silently', () => {
    assert.deepEqual(
      ids(
        ex({
          responseHeaders: [
            ['Content-Type', 'text/html'],
            ['Strict-Transport-Security', 'max-age=31536000; includeSubDomains'],
          ],
        }),
        ['AWB-P001'],
      ),
      [],
    );
  });
});

describe('caching of authenticated responses', () => {
  const authed = (responseHeaders: [string, string][]): Exchange =>
    ex({
      requestHeaders: [['Host', 'target.example'], ['Cookie', 'session=abc']],
      responseHeaders,
    });

  test('no Cache-Control at all on an authenticated response is reported', () => {
    assert.ok(ids(authed([['Content-Type', 'text/html']]), ['AWB-P004']).length > 0);
  });

  test('no-store satisfies it', () => {
    assert.deepEqual(
      ids(authed([['Content-Type', 'text/html'], ['Cache-Control', 'no-store']]), ['AWB-P004']),
      [],
    );
  });

  test('private plus no-cache satisfies it', () => {
    assert.deepEqual(
      ids(authed([['Content-Type', 'text/html'], ['Cache-Control', 'private, no-cache']]), ['AWB-P004']),
      [],
    );
  });

  test('public with max-age is the serious case, worse when it sets a cookie', () => {
    assert.equal(
      severityOf(authed([['Content-Type', 'text/html'], ['Cache-Control', 'public, max-age=3600']]), 'AWB-P004'),
      'medium',
    );
    assert.equal(
      severityOf(
        authed([
          ['Content-Type', 'text/html'],
          ['Cache-Control', 'public, max-age=3600'],
          ['Set-Cookie', 'session=abc'],
        ]),
        'AWB-P004',
      ),
      'high',
    );
  });

  test('an unauthenticated response is not asked about', () => {
    assert.deepEqual(ids(ex({ responseHeaders: [['Content-Type', 'text/html']] }), ['AWB-P004']), []);
  });

  test('a cacheable response that varies by cookie but does not say so is high', () => {
    const titles = ids(
      ex({
        requestHeaders: [['Host', 'target.example'], ['Cookie', 'session=abc']],
        responseHeaders: [['Content-Type', 'text/html'], ['Cache-Control', 'public, max-age=60']],
      }),
      ['AWB-P005'],
    );
    assert.ok(titles.some((t) => /does not Vary on the credential/.test(t)));
  });

  test('a cacheable CORS response without Vary: Origin is reported', () => {
    const titles = ids(
      ex({
        responseHeaders: [
          ['Content-Type', 'application/json'],
          ['Cache-Control', 'public, max-age=60'],
          ['Access-Control-Allow-Origin', 'https://app.example'],
        ],
      }),
      ['AWB-P005'],
    );
    assert.ok(titles.some((t) => /Vary on Origin/.test(t)));
  });
});

describe('cookie attributes are graded by what the cookie looks like', () => {
  const setCookie = (value: string, url = 'https://target.example/'): Exchange =>
    ex({ url, responseHeaders: [['Content-Type', 'text/html'], ['Set-Cookie', value]] });

  test('a session cookie without HttpOnly is medium', () => {
    assert.ok(
      ids(setCookie('session=abc; Secure; SameSite=Lax'), ['AWB-P010']).some((t) =>
        /without HttpOnly/.test(t),
      ),
    );
  });

  test('a preferences cookie without HttpOnly is not reported for it', () => {
    assert.ok(
      !ids(setCookie('theme=dark; Secure; SameSite=Lax'), ['AWB-P010']).some((t) =>
        /without HttpOnly/.test(t),
      ),
    );
  });

  test('a session cookie without Secure is worse than a preferences one', () => {
    const session = scanExchange(setCookie('session=abc; HttpOnly; SameSite=Lax'), { only: ['AWB-P010'] })
      .find((f) => /without Secure/.test(f.title));
    const theme = scanExchange(setCookie('theme=dark; HttpOnly; SameSite=Lax'), { only: ['AWB-P010'] })
      .find((f) => /without Secure/.test(f.title));
    assert.equal(session?.severity, 'medium');
    assert.equal(theme?.severity, 'low');
  });

  test('SameSite=None without Secure is reported as the rejection it causes', () => {
    assert.ok(
      ids(setCookie('session=abc; HttpOnly; SameSite=None'), ['AWB-P010']).some((t) =>
        /SameSite=None without Secure/.test(t),
      ),
    );
  });

  test('a cookie deletion is not reported for missing flags', () => {
    assert.deepEqual(ids(setCookie('session=; Max-Age=0'), ['AWB-P010']), []);
    assert.deepEqual(
      ids(setCookie('session=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT'), ['AWB-P010']),
      [],
      'an expiry in the past is a logout, not a misconfiguration',
    );
  });

  test('a parent-domain cookie is reported', () => {
    const titles = ids(
      ex({
        url: 'https://app.target.example/',
        requestHeaders: [['Host', 'app.target.example']],
        responseHeaders: [
          ['Content-Type', 'text/html'],
          ['Set-Cookie', 'session=abc; Domain=.target.example; Secure; HttpOnly; SameSite=Lax'],
        ],
      }),
      ['AWB-P010'],
    );
    assert.ok(titles.some((t) => /scoped to a parent domain/.test(t)));
  });

  test('a host-only cookie is not', () => {
    assert.ok(
      !ids(setCookie('session=abc; Secure; HttpOnly; SameSite=Lax'), ['AWB-P010']).some((t) =>
        /parent domain/.test(t),
      ),
    );
  });

  test('the __Host- prefix is checked against its requirements', () => {
    assert.ok(
      ids(setCookie('__Host-session=abc; Secure; Domain=target.example; Path=/'), ['AWB-P011']).some((t) =>
        /does not qualify/.test(t),
      ),
    );
    assert.deepEqual(ids(setCookie('__Host-session=abc; Secure; Path=/'), ['AWB-P011']), []);
  });

  test('the __Secure- prefix without Secure is reported', () => {
    assert.ok(ids(setCookie('__Secure-x=1; Path=/'), ['AWB-P011']).length > 0);
  });
});

describe('CORS severity reflects whether the read can actually happen', () => {
  const cors = (headers: [string, string][], requestOrigin?: string, authed = false): Exchange =>
    ex({
      requestHeaders: [
        ['Host', 'target.example'],
        ...(requestOrigin === undefined ? [] : ([['Origin', requestOrigin]] as [string, string][])),
        ...(authed ? ([['Cookie', 'session=abc']] as [string, string][]) : []),
      ],
      responseHeaders: [['Content-Type', 'application/json'], ...headers],
      body: '{"ok":true}',
    });

  test('a bare wildcard is info, not high', () => {
    assert.equal(severityOf(cors([['Access-Control-Allow-Origin', '*']]), 'AWB-P020'), 'info');
  });

  test('a wildcard with credentials is low and says browsers reject it', () => {
    const finding = scanExchange(
      cors([
        ['Access-Control-Allow-Origin', '*'],
        ['Access-Control-Allow-Credentials', 'true'],
      ]),
      { only: ['AWB-P020'] },
    )[0];
    assert.equal(finding?.severity, 'low');
    assert.match(finding?.detail ?? '', /cannot be combined/);
  });

  test('a reflected origin with credentials on an authenticated request is critical', () => {
    const finding = scanExchange(
      cors(
        [
          ['Access-Control-Allow-Origin', 'https://attacker.example'],
          ['Access-Control-Allow-Credentials', 'true'],
          ['Vary', 'Origin'],
        ],
        'https://attacker.example',
        true,
      ),
      { only: ['AWB-P020'] },
    )[0];
    assert.equal(finding?.severity, 'critical');
    assert.match(finding?.detail ?? '', /awb replay/);
  });

  test('a reflected origin without credentials is only low', () => {
    assert.equal(
      severityOf(
        cors([['Access-Control-Allow-Origin', 'https://attacker.example'], ['Vary', 'Origin']], 'https://attacker.example'),
        'AWB-P020',
      ),
      'low',
    );
  });

  test('the null origin is reported with the sandbox mechanism explained', () => {
    const finding = scanExchange(
      cors([
        ['Access-Control-Allow-Origin', 'null'],
        ['Access-Control-Allow-Credentials', 'true'],
      ]),
      { only: ['AWB-P020'] },
    )[0];
    assert.equal(finding?.severity, 'high');
    assert.match(finding?.detail ?? '', /sandboxed iframe/);
  });

  test('a reflected origin with no Vary gets a second finding about caching', () => {
    const titles = ids(
      cors(
        [['Access-Control-Allow-Origin', 'https://attacker.example'], ['Access-Control-Allow-Credentials', 'true']],
        'https://attacker.example',
      ),
      ['AWB-P020'],
    );
    assert.ok(titles.some((t) => /without Vary: Origin/.test(t)));
  });

  test('no CORS headers means no CORS findings', () => {
    assert.deepEqual(ids(cors([]), ['AWB-P020', 'AWB-P021']), []);
  });
});

describe('disclosure checks', () => {
  test('a Python traceback is recognised', () => {
    const titles = ids(
      ex({
        status: 500,
        body: 'Traceback (most recent call last):\n  File "/app/views.py", line 42, in get\n',
      }),
      ['AWB-P030'],
    );
    assert.ok(titles.some((t) => /Python/.test(t)));
  });

  test('a database error is reported as evidence of unhandled input', () => {
    const finding = scanExchange(
      ex({ status: 500, body: "You have an error in your SQL syntax near ''" }),
      { only: ['AWB-P030'] },
    ).find((f) => /MySQL/.test(f.title));
    assert.equal(finding?.severity, 'medium');
    assert.match(finding?.detail ?? '', /condition injection testing looks for/);
  });

  test('a framework debug page is worse than a plain trace', () => {
    const finding = scanExchange(
      ex({ status: 500, body: 'Werkzeug Debugger: the debugger caught an exception' }),
      { only: ['AWB-P030'] },
    )[0];
    assert.equal(finding?.severity, 'medium');
  });

  test('an ordinary validation message is not a stack trace', () => {
    assert.deepEqual(ids(ex({ status: 400, body: '{"error":"email is required"}' }), ['AWB-P030']), []);
  });

  test('a served source map with sourcesContent is reported', () => {
    const titles = ids(
      ex({
        url: 'https://target.example/static/app.js.map',
        responseHeaders: [['Content-Type', 'application/json']],
        body: '{"version":3,"sources":["src/App.tsx"],"sourcesContent":["const a = 1"]}',
      }),
      ['AWB-P031'],
    );
    assert.ok(titles.some((t) => /Source map is served/.test(t)));
  });

  test('a sourceMappingURL comment is noted separately and more mildly', () => {
    const finding = scanExchange(
      ex({
        url: 'https://target.example/static/app.js',
        responseHeaders: [['Content-Type', 'application/javascript']],
        body: 'var a=1;\n//# sourceMappingURL=app.js.map',
      }),
      { only: ['AWB-P031'] },
    )[0];
    assert.equal(finding?.severity, 'info');
    assert.match(finding?.title ?? '', /references a source map/);
  });

  test('a high-entropy credential in a body is reported without quoting the value', () => {
    const secret = FABRICATED_TOKEN;
    const finding = scanExchange(
      ex({ responseHeaders: [['Content-Type', 'application/json']], body: `{"token":"${secret}"}` }),
      { only: ['AWB-P032'] },
    )[0];
    assert.ok(finding !== undefined, 'the token should have been detected');
    assert.equal(finding.severity, 'critical');
    assert.ok(!finding.detail.includes(secret), 'the finding must not reproduce the credential');
    assert.match(finding.detail, /unsafe-show-secrets/);
  });

  test('a documentation placeholder is not reported', () => {
    assert.deepEqual(
      ids(
        ex({ responseHeaders: [['Content-Type', 'text/html']], body: 'Use AKIAIOSFODNN7EXAMPLE as your key' }),
        ['AWB-P032'],
      ),
      [],
    );
  });

  test('a low-entropy value of the right shape is not reported', () => {
    assert.deepEqual(
      ids(
        ex({
          responseHeaders: [['Content-Type', 'text/html']],
          body: 'key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        }),
        ['AWB-P032'],
      ),
      [],
    );
  });

  test('a token endpoint returning a token is not a finding', () => {
    assert.deepEqual(
      ids(
        ex({
          url: 'https://target.example/oauth2/token',
          responseHeaders: [['Content-Type', 'application/json']],
          body: `{"access_token":"${FABRICATED_TOKEN}"}`,
        }),
        ['AWB-P032'],
      ),
      [],
    );
  });

  test('entropy is computed correctly at the edges', () => {
    assert.equal(entropy(''), 0);
    assert.equal(entropy('aaaa'), 0);
    assert.ok(Math.abs(entropy('ab') - 1) < 1e-9);
    assert.ok(entropy('abcdefghijklmnop') > 3.9);
  });

  test('a cloud metadata address in a response is called out', () => {
    const finding = scanExchange(
      ex({ body: '<p>upstream 169.254.169.254 timed out</p>' }),
      { only: ['AWB-P033'] },
    )[0];
    assert.match(finding?.detail ?? '', /instance metadata/);
  });

  test('a directory listing is recognised', () => {
    const titles = ids(
      ex({ body: '<html><head><title>Index of /backup</title></head><body><h1>Index of /backup</h1><a href="db.sql">db.sql</a></body></html>' }),
      ['AWB-P034'],
    );
    assert.ok(titles.some((t) => /Directory listing/.test(t)));
  });
});

describe('content and request checks', () => {
  test('a token in the query string is reported', () => {
    assert.ok(
      ids(ex({ url: 'https://target.example/cb?access_token=abcdef123456' }), ['AWB-P040']).length > 0,
    );
  });

  test('an OAuth code is graded down, because that is the specified design', () => {
    assert.equal(
      severityOf(ex({ url: 'https://target.example/cb?code=abc123&state=xyz' }), 'AWB-P040'),
      'info',
    );
  });

  test('a code parameter that is not an OAuth callback is left alone', () => {
    // Country codes, promo codes and error codes are most of the web.
    assert.deepEqual(ids(ex({ url: 'https://target.example/shop?code=SUMMER20' }), ['AWB-P040']), []);
  });

  test('an ordinary parameter is not reported', () => {
    assert.deepEqual(ids(ex({ url: 'https://target.example/search?q=hello&page=2' }), ['AWB-P040']), []);
  });

  test('a third-party script without integrity is reported', () => {
    const titles = ids(
      ex({ body: '<html><script src="https://cdn.other.example/lib.js"></script></html>' }),
      ['AWB-P042'],
    );
    assert.ok(titles.length > 0);
  });

  test('a same-origin script, and a third-party one with integrity, are not', () => {
    assert.deepEqual(
      ids(ex({ body: '<html><script src="https://target.example/app.js"></script></html>' }), ['AWB-P042']),
      [],
    );
    assert.deepEqual(
      ids(
        ex({
          body: '<html><script src="https://cdn.other.example/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script></html>',
        }),
        ['AWB-P042'],
      ),
      [],
    );
  });

  test('active and passive mixed content are separate findings', () => {
    const titles = ids(
      ex({
        body: '<html><script src="http://cdn.example/a.js"></script><img src="http://cdn.example/b.png"></html>',
      }),
      ['AWB-P043'],
    );
    assert.ok(titles.some((t) => /Active mixed content/.test(t)));
    assert.ok(titles.some((t) => /Passive mixed content/.test(t)));
  });

  test('an absolute redirect taken from a parameter is reported with a replay command', () => {
    const finding = scanExchange(
      ex({
        url: 'https://target.example/login?next=https://evil.example/',
        status: 302,
        responseHeaders: [['Location', 'https://evil.example/']],
        body: '',
      }),
      { only: ['AWB-P044'] },
    )[0];
    assert.equal(finding?.severity, 'medium');
    assert.match(finding?.detail ?? '', /awb replay/);
  });

  test('a relative redirect from a parameter is weaker and marked tentative', () => {
    const finding = scanExchange(
      ex({
        url: 'https://target.example/login?next=/dashboard',
        status: 302,
        responseHeaders: [['Location', '/dashboard']],
        body: '',
      }),
      { only: ['AWB-P044'] },
    )[0];
    assert.equal(finding?.confidence, 'tentative');
  });

  test('a redirect unrelated to any parameter is not reported', () => {
    assert.deepEqual(
      ids(
        ex({
          url: 'https://target.example/old?page=2',
          status: 301,
          responseHeaders: [['Location', '/new']],
          body: '',
        }),
        ['AWB-P044'],
      ),
      [],
    );
  });

  test('GraphQL introspection output is recognised, but a refusal is not', () => {
    assert.ok(
      ids(
        ex({
          url: 'https://target.example/graphql',
          responseHeaders: [['Content-Type', 'application/json']],
          body: '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"kind":"OBJECT","name":"User"}]}}}',
        }),
        ['AWB-P045'],
      ).length > 0,
    );
    assert.deepEqual(
      ids(
        ex({
          url: 'https://target.example/graphql',
          responseHeaders: [['Content-Type', 'application/json']],
          body: '{"errors":[{"message":"GraphQL introspection is not allowed, but the query contained __schema"}]}',
        }),
        ['AWB-P045'],
      ),
      [],
    );
  });

  test('ambiguous request framing is reported', () => {
    const duplicated = ids(
      ex({
        requestHeaders: [
          ['Host', 'target.example'],
          ['Content-Length', '5'],
          ['Content-Length', '12'],
        ],
      }),
      ['AWB-P046'],
    );
    assert.ok(duplicated.some((t) => /more than one Content-Length/.test(t)));

    const both = ids(
      ex({
        requestHeaders: [
          ['Host', 'target.example'],
          ['Content-Length', '5'],
          ['Transfer-Encoding', 'chunked'],
        ],
      }),
      ['AWB-P046'],
    );
    assert.ok(both.some((t) => /both Transfer-Encoding and Content-Length/.test(t)));
  });

  test('a newline in a header value is high severity', () => {
    const finding = scanExchange(
      ex({ requestHeaders: [['Host', 'target.example'], ['X-Forwarded-For', '1.1.1.1\r\nX-Admin: 1']] }),
      { only: ['AWB-P046'] },
    )[0];
    assert.equal(finding?.severity, 'high');
  });

  test('credentials over plaintext HTTP are high, and loopback is exempt', () => {
    assert.equal(
      severityOf(
        ex({ url: 'http://target.example/', requestHeaders: [['Host', 'target.example'], ['Cookie', 'session=abc']] }),
        'AWB-P047',
      ),
      'high',
    );
    assert.deepEqual(
      ids(
        ex({ url: 'http://127.0.0.1:3000/', requestHeaders: [['Host', '127.0.0.1:3000'], ['Cookie', 'session=abc']] }),
        ['AWB-P047'],
      ),
      [],
    );
  });
});

describe('scanning a whole capture', () => {
  test('every exchange is scanned and the findings carry their own evidence', () => {
    const exchanges = [
      ex({ url: 'https://target.example/a' }),
      ex({ url: 'https://target.example/b', responseHeaders: [['Content-Type', 'text/html'], ['Server', 'nginx/1.24.0']] }),
    ];
    const findings = scanAll(exchanges);
    assert.ok(findings.length > 0);
    const evidenceIds = new Set(findings.flatMap((f) => f.evidence));
    for (const id of evidenceIds) {
      assert.ok(exchanges.some((e) => e.id === id), `${id} must be an exchange in the capture`);
    }
  });

  test('a clean, well-configured response produces no findings at all', () => {
    const clean = ex({
      url: 'https://target.example/app',
      requestHeaders: [['Host', 'target.example']],
      responseHeaders: [
        ['Content-Type', 'text/html; charset=utf-8'],
        ['Strict-Transport-Security', 'max-age=31536000; includeSubDomains'],
        [
          'Content-Security-Policy',
          "default-src 'self'; script-src 'self' 'nonce-r4nd0m'; object-src 'none'; frame-ancestors 'none'",
        ],
        ['X-Content-Type-Options', 'nosniff'],
        ['Referrer-Policy', 'strict-origin-when-cross-origin'],
        ['Cache-Control', 'no-store'],
      ],
      body: '<html><body><h1>Dashboard</h1></body></html>',
    });
    const findings = scanAll([clean]);
    assert.deepEqual(
      findings.map((f) => `${f.check} ${f.title}`),
      [],
      'a correctly configured response must be silent, or the tool is noise',
    );
  });
});
