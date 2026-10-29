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
    // Not a key: the PEM header and footer with sixteen characters of the
    // published 512-bit documentation key between them. It is here because the
    // redactor has to remove the whole block rather than only the header, and
    // there is no key material to remove.
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

describe('a credential inside a URL', () => {
  // The key/value pass matched with key `https` and a value running to the
  // next `&`, declined it because `https` is not a credential field, and had
  // already consumed the `access_token` that followed -- so it never got a
  // match of its own. Every credential carried in a URL survived redaction,
  // in header values, in bodies, and anywhere else redactText is what runs.
  const TOKEN = 'abcdef0123456789abcdef0123456789';

  test('is redacted wherever in the URL it sits', () => {
    for (const url of [
      `https://app.example.test/cb?access_token=${TOKEN}`,
      `https://app.example.test/cb?code=${TOKEN}&state=xyz`,
      `https://app.example.test/l?password=${TOKEN}`,
      `http://app.example.test/l?page=2&api_key=${TOKEN}&sort=asc`,
      `Referer: https://app.example.test/cb?access_token=${TOKEN}`,
    ]) {
      assert.ok(!redactText(url).includes(TOKEN), url);
    }
  });

  test('is redacted more than once in the same URL', () => {
    const out = redactText(`https://a.example.test/cb?code=${TOKEN}&access_token=${TOKEN}`);
    assert.ok(!out.includes(TOKEN));
    assert.equal(out.match(/\[redacted:/g)?.length, 2);
  });

  test('leaves the rest of the URL alone', () => {
    const out = redactText(`https://a.example.test/x?page=2&utm_source=mail&token=${TOKEN}`);
    assert.ok(out.startsWith('https://a.example.test/x?page=2&utm_source=mail&token='));
    assert.ok(!out.includes(TOKEN));
  });

  test('does not redact a field whose name merely ends in a credential word', () => {
    // `code` is matched whole, not as a suffix: a status code is something a
    // report has to be able to show.
    for (const text of [
      '{"status_code":404}',
      '{"error_code":"E_LIMIT"}',
      '{"country_code":"GB"}',
      'https://a.example.test/x?page=2&utm_source=mail',
    ]) {
      assert.equal(redactText(text), text);
    }
  });

  test('covers the credential names that had no entry', () => {
    for (const field of ['passphrase', 'nonce', 'code', 'code_verifier']) {
      const text = `{"${field}":"${TOKEN}"}`;
      assert.ok(!redactText(text).includes(TOKEN), field);
    }
  });
});

describe('a credential inside a multipart body', () => {
  // multipart/form-data puts the field name in a Content-Disposition header
  // and the value on its own line, so the key/value pass cannot reach it:
  // there is no credential name in front of the value. A password typed into
  // an ordinary HTML login form arrives this way.
  const BOUNDARY = '----WebKitFormBoundaryAbC123';
  const part = (name: string, value: string): string =>
    `--${BOUNDARY}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`;
  const body = part('username', 'alice') + part('password', 'hunter2') + part('csrf_token', 'tok-9f8e7d6c5b4a') + `--${BOUNDARY}--\r\n`;

  test('redacts the credential-named parts', () => {
    const out = redactText(body);
    assert.ok(!out.includes('hunter2'));
    assert.ok(!out.includes('tok-9f8e7d6c5b4a'));
  });

  test('leaves every other part, boundary and part header byte for byte', () => {
    const out = redactText(body);
    assert.ok(out.includes('alice'), 'a part that is not a credential survives');
    assert.equal(out.split(`--${BOUNDARY}`).length, body.split(`--${BOUNDARY}`).length);
    assert.ok(out.includes('Content-Disposition: form-data; name="password"'));
    assert.ok(out.trimEnd().endsWith(`--${BOUNDARY}--`));
  });

  test('leaves a body that is not multipart alone', () => {
    assert.equal(redactText('just some text\r\nwith lines\r\n'), 'just some text\r\nwith lines\r\n');
  });
});

describe('a credential that arrived only in a URL', () => {
  // observedSecrets read credential *headers* only, so a token delivered as
  // `?access_token=...` never entered the literal set -- and the literal set
  // is what catches a value echoed back under a name no field list contains.
  const TOKEN = 'a9f3c1e7b25d4086b1c4e7f20a5d8311';

  test('is harvested from the request URL', () => {
    const found = observedSecrets([['Host', 'target.example.test']], `https://target.example.test/api?access_token=${TOKEN}`);
    assert.ok(found.includes(TOKEN));
  });

  test('is harvested from a URL carried in a header, query or fragment', () => {
    for (const header of [
      ['Referer', `https://target.example.test/cb?code=${TOKEN}`],
      ['Location', `https://target.example.test/cb#access_token=${TOKEN}`],
      ['Content-Location', `https://target.example.test/r?api_key=${TOKEN}`],
    ] as const) {
      const found = observedSecrets([header], 'https://target.example.test/api');
      assert.ok(found.includes(TOKEN), header[0]);
    }
  });

  test('is not harvested from an ordinary query parameter', () => {
    const found = observedSecrets([['Host', 'target.example.test']], 'https://target.example.test/api?page=2&utm_source=mail');
    assert.deepEqual(found, []);
  });

  test('is harvested in its decoded form as well as its raw one', () => {
    const raw = 'abc%2Fdef%2Bghi%3D%3D0123456789';
    const found = observedSecrets([['Host', 'h.example.test']], `https://h.example.test/a?token=${raw}`);
    assert.ok(found.includes(raw));
    assert.ok(found.includes(decodeURIComponent(raw)));
  });
});
