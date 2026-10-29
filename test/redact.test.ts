import { strict as assert } from 'node:assert';
import test, { describe } from 'node:test';

import {
  observedSecrets,
  redactHeaders,
  redactText,
  redactUrl,
  redactValue,
} from '../src/core/redact.js';
import type { HeaderList } from '../src/core/headers.js';

const SESSION = 'a9f3c1e7b25d4086b1c4e7f20a5d8311';
// The jwt.io example token: the most published JWT there is, signed with the
// documented example secret. Not a credential for anything.
const JWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkEifQ.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk';

const HEADERS: HeaderList = [
  ['Host', 'target.example'],
  ['Authorization', `Bearer ${JWT}`],
  ['Cookie', `session=${SESSION}; theme=dark`],
  ['Accept', 'application/json'],
];

describe('credential headers lose their values and keep their shape', () => {
  const out = redactHeaders(HEADERS);

  test('Authorization is redacted', () => {
    const v = out.find(([k]) => k === 'Authorization')?.[1] ?? '';
    assert.ok(!v.includes(JWT));
    assert.match(v, /\[redacted:/);
  });

  test('cookie names survive because which cookies exist is the finding', () => {
    const v = out.find(([k]) => k === 'Cookie')?.[1] ?? '';
    assert.ok(v.includes('session='));
    assert.ok(v.includes('theme='));
    assert.ok(!v.includes(SESSION));
  });

  test('non-credential headers are untouched', () => {
    assert.equal(out.find(([k]) => k === 'Accept')?.[1], 'application/json');
    assert.equal(out.find(([k]) => k === 'Host')?.[1], 'target.example');
  });

  test('Set-Cookie keeps its attributes, which are what you are assessing', () => {
    const [pair] = redactHeaders([
      ['Set-Cookie', `sid=${SESSION}; Path=/; HttpOnly; SameSite=Lax`],
    ]);
    const v = pair?.[1] ?? '';
    assert.ok(v.startsWith('sid='));
    assert.ok(v.includes('HttpOnly'));
    assert.ok(v.includes('SameSite=Lax'));
    assert.ok(!v.includes(SESSION));
  });

  test('showSecrets returns the list unchanged, by identity', () => {
    assert.equal(redactHeaders(HEADERS, { showSecrets: true }), HEADERS);
  });
});

describe('equal values redact to equal markers', () => {
  test('so a transcript can still answer "did the session change"', () => {
    assert.equal(redactValue(SESSION), redactValue(SESSION));
  });

  test('and different values do not collide', () => {
    assert.notEqual(redactValue(SESSION), redactValue(SESSION.replace('a9', 'b8')));
  });

  test('the marker records the length, which is itself a signal', () => {
    assert.match(redactValue('x'.repeat(40)), /:40b:/);
  });

  test('an empty value stays empty rather than becoming a marker', () => {
    assert.equal(redactValue(''), '');
  });
});

describe('bodies are scrubbed by shape, not only where a header named them', () => {
  test('a JWT anywhere in a body', () => {
    const out = redactText(`{"id_token":"${JWT}"}`);
    assert.ok(!out.includes(JWT));
  });

  test('an AWS access key id', () => {
    const out = redactText('AKIAIOSFODNN7EXAMPLE is in here');
    assert.ok(!out.includes('AKIAIOSFODNN7EXAMPLE'));
  });

  test('a private key block, all of it', () => {
    const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj3\n-----END RSA PRIVATE KEY-----';
    const out = redactText(`key: ${pem}`);
    assert.ok(!out.includes('MIIBOgIBAAJBAKj3'));
  });

  test('a credential-named JSON field', () => {
    const out = redactText('{"password":"hunter2","username":"alice"}');
    assert.ok(!out.includes('hunter2'));
    assert.ok(out.includes('alice'), 'the username is not a credential and must survive');
  });

  test('a credential-named form field', () => {
    const out = redactText('user=alice&client_secret=s3cr3tvalue&next=/home');
    assert.ok(!out.includes('s3cr3tvalue'));
    assert.ok(out.includes('user=alice'));
    assert.ok(out.includes('next=/home'));
  });

  test('field matching tolerates separators and suffixes', () => {
    for (const key of ['api_key', 'apiKey', 'x-api-key', 'refresh_token']) {
      const out = redactText(`${key}=abcdefghijklmnop`);
      assert.ok(!out.includes('abcdefghijklmnop'), `${key} should have been redacted`);
    }
  });

  test('extra literal values are scrubbed wherever they appear', () => {
    const out = redactText(`the value ${SESSION} shows up in prose`, {
      extraValues: [SESSION],
    });
    assert.ok(!out.includes(SESSION));
  });

  test('a short extra value is not scrubbed, because it would hit everything', () => {
    const out = redactText('id=7', { extraValues: ['7'] });
    assert.equal(out, 'id=7');
  });

  test('ordinary text is left alone', () => {
    const text = '<html><body><h1>Dashboard</h1><p>Welcome back, alice.</p></body></html>';
    assert.equal(redactText(text), text);
  });
});

describe('URLs lose credential-bearing parameters and keep the rest', () => {
  test('a token in the query goes', () => {
    const out = redactUrl(`https://a.example/cb?code=abc&access_token=${JWT}&state=xyz`);
    assert.ok(!out.includes(JWT));
    assert.ok(out.includes('state=xyz'));
  });

  test('ordinary parameters survive', () => {
    const url = 'https://a.example/search?q=hello&page=2';
    assert.equal(redactUrl(url), url);
  });

  test('a JWT in the path is caught even though no parameter named it', () => {
    const out = redactUrl(`https://a.example/reset/${JWT}`);
    assert.ok(!out.includes(JWT));
  });

  test('a non-URL falls back to text redaction rather than throwing', () => {
    const out = redactUrl(`token=${JWT}`);
    assert.ok(!out.includes(JWT));
  });
});

describe('observedSecrets collects the literal values to scrub elsewhere', () => {
  test('it strips the Bearer prefix so the token itself can be matched', () => {
    const found = observedSecrets(HEADERS);
    assert.ok(found.includes(JWT));
    assert.ok(!found.includes(`Bearer ${JWT}`));
  });

  test('every cookie value, individually', () => {
    const found = observedSecrets([['Cookie', `session=${SESSION}; csrf=abcdefghijkl`]]);
    assert.ok(found.includes(SESSION));
    assert.ok(found.includes('abcdefghijkl'));
  });

  test('a Set-Cookie value without its attributes', () => {
    const found = observedSecrets([['Set-Cookie', `sid=${SESSION}; Path=/; HttpOnly`]]);
    assert.ok(found.includes(SESSION));
    assert.ok(!found.some((v) => v.includes('HttpOnly')));
  });

  test('values too short to be credentials are dropped', () => {
    assert.deepEqual(observedSecrets([['Cookie', 'a=1; b=2']]), []);
  });

  test('a response body can then be scrubbed of the request credentials', () => {
    const body = `{"echo":"${SESSION}"}`;
    const out = redactText(body, { extraValues: observedSecrets(HEADERS) });
    assert.ok(!out.includes(SESSION));
  });
});
