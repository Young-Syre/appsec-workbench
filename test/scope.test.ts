import { strict as assert } from 'node:assert';
import test, { describe } from 'node:test';

import {
  EMPTY_SCOPE,
  ScopeViolation,
  assertAllowed,
  decide,
  formatRule,
  hostMatches,
  isAllowed,
  lintScope,
  parseRule,
  parseScopeConfig,
} from '../src/core/scope.js';

describe('scope is deny by default', () => {
  test('an unconfigured scope allows nothing at all', () => {
    const d = decide(EMPTY_SCOPE, 'https://target.example/');
    assert.equal(d.verdict, 'not-covered');
    assert.match(d.reason, /deny by default/);
    assert.equal(isAllowed(EMPTY_SCOPE, 'https://target.example/'), false);
  });

  test('assertAllowed throws a ScopeViolation naming the URL', () => {
    try {
      assertAllowed(EMPTY_SCOPE, 'https://target.example/a');
      assert.fail('expected a throw');
    } catch (err) {
      assert.ok(err instanceof ScopeViolation);
      assert.match(err.message, /refusing to send a request to https:\/\/target\.example\/a/);
      assert.match(err.message, /awb scope add/);
    }
  });

  test('an unparseable URL is not covered rather than allowed', () => {
    const scope = parseScopeConfig({ include: ['*'] });
    assert.equal(decide(scope, 'not a url').verdict, 'not-covered');
  });
});

describe('rule shorthand parses the way people type it', () => {
  test('a bare host means any scheme, port and path', () => {
    assert.deepEqual(parseRule('example.com'), {
      scheme: '*',
      host: 'example.com',
      port: '*',
      path: '*',
    });
  });

  test('a scheme pins the scheme', () => {
    assert.equal(parseRule('https://example.com').scheme, 'https');
  });

  test('a port pins the port', () => {
    assert.equal(parseRule('http://10.0.0.5:8080').port, '8080');
  });

  test('a path becomes a prefix', () => {
    assert.equal(parseRule('*.example.com/api').path, '/api');
  });

  test('IPv6 literals keep their brackets and their port is still found', () => {
    assert.deepEqual(parseRule('http://[2001:db8::1]:8443/x'), {
      scheme: 'http',
      host: '[2001:db8::1]',
      port: '8443',
      path: '/x',
    });
  });

  test('an IPv6 literal with no port is not mistaken for one', () => {
    assert.equal(parseRule('[2001:db8::1]').port, '*');
  });

  test('hosts are lowercased', () => {
    assert.equal(parseRule('HTTPS://Example.COM').host, 'example.com');
  });

  test('a non-numeric port is rejected rather than ignored', () => {
    assert.throws(() => parseRule('example.com:https'), /port must be a number/);
  });

  test('an empty rule is rejected', () => {
    assert.throws(() => parseRule('   '), /empty scope rule/);
  });

  test('formatRule round-trips the shorthand', () => {
    for (const text of ['example.com', 'https://example.com', 'http://a.example:8080/api', '*.example.com/api']) {
      assert.equal(formatRule(parseRule(text)), text);
    }
  });
});

describe('wildcard hosts match labels to the left and never the apex', () => {
  test('one or more labels match', () => {
    assert.ok(hostMatches('*.example.com', 'api.example.com'));
    assert.ok(hostMatches('*.example.com', 'a.b.example.com'));
  });

  test('the apex does not', () => {
    assert.equal(hostMatches('*.example.com', 'example.com'), false);
  });

  test('a suffix that is not a label boundary does not', () => {
    assert.equal(hostMatches('*.example.com', 'notexample.com'), false);
    assert.equal(hostMatches('*.example.com', 'evilexample.com'), false);
  });

  test('bare * matches anything', () => {
    assert.ok(hostMatches('*', 'anything.at.all'));
  });
});

describe('exclusion beats inclusion, always', () => {
  const scope = parseScopeConfig({
    include: ['*.target.example'],
    exclude: ['https://admin.target.example'],
  });

  test('an included subdomain is in scope', () => {
    assert.equal(decide(scope, 'https://api.target.example/v1').verdict, 'in-scope');
  });

  test('an excluded one is out, and the decision names the rule', () => {
    const d = decide(scope, 'https://admin.target.example/');
    assert.equal(d.verdict, 'out-of-scope');
    assert.equal(formatRule(d.rule!), 'https://admin.target.example');
    assert.match(d.reason, /excluded by/);
  });

  test('order of the include list does not change the exclusion', () => {
    const flipped = parseScopeConfig({
      include: ['admin.target.example', '*.target.example'],
      exclude: ['https://admin.target.example'],
    });
    assert.equal(decide(flipped, 'https://admin.target.example/').verdict, 'out-of-scope');
  });

  test('a host nobody mentioned is not covered', () => {
    assert.equal(decide(scope, 'https://unrelated.example/').verdict, 'not-covered');
  });
});

describe('ports resolve against the scheme default', () => {
  const scope = parseScopeConfig({ include: ['https://a.example:443'] });

  test('an implicit 443 matches an explicit one', () => {
    assert.equal(decide(scope, 'https://a.example/x').verdict, 'in-scope');
  });

  test('an explicit non-default port does not', () => {
    assert.equal(decide(scope, 'https://a.example:8443/x').verdict, 'not-covered');
  });

  test('http on 80 is distinct from https on 443', () => {
    const http = parseScopeConfig({ include: ['http://a.example:80'] });
    assert.equal(decide(http, 'http://a.example/x').verdict, 'in-scope');
    assert.equal(decide(http, 'https://a.example/x').verdict, 'not-covered');
  });
});

describe('path prefixes stop at a segment boundary', () => {
  const scope = parseScopeConfig({ include: ['a.example/api'] });

  test('the prefix itself matches', () => {
    assert.equal(decide(scope, 'https://a.example/api').verdict, 'in-scope');
  });

  test('a child path matches', () => {
    assert.equal(decide(scope, 'https://a.example/api/v1/users').verdict, 'in-scope');
  });

  test('a sibling that merely shares the prefix string does not', () => {
    assert.equal(decide(scope, 'https://a.example/apikeys').verdict, 'not-covered');
  });

  test('a query on the prefix matches', () => {
    assert.equal(decide(scope, 'https://a.example/api?x=1').verdict, 'in-scope');
  });
});

describe('a scope file can be checked for contradicting itself', () => {
  test('a rule both included and excluded is reported', () => {
    const problems = lintScope(
      parseScopeConfig({ include: ['a.example'], exclude: ['a.example'] }),
    );
    assert.ok(problems.some((p) => p.kind === 'shadowed-include'));
  });

  test('a duplicated rule is reported', () => {
    const problems = lintScope(parseScopeConfig({ include: ['a.example', 'a.example'] }));
    assert.ok(problems.some((p) => p.kind === 'duplicate'));
  });

  test('an exclusion no inclusion reaches is reported', () => {
    const problems = lintScope(
      parseScopeConfig({ include: ['a.example'], exclude: ['unrelated.example'] }),
    );
    assert.ok(problems.some((p) => p.kind === 'unreachable-exclude'));
  });

  test('an exclusion under a wildcard inclusion is reachable and not reported', () => {
    const problems = lintScope(
      parseScopeConfig({ include: ['*.a.example'], exclude: ['admin.a.example'] }),
    );
    assert.deepEqual(problems, []);
  });

  test('a coherent scope has no problems', () => {
    const problems = lintScope(
      parseScopeConfig({ include: ['https://a.example', '*.b.example'], exclude: ['https://a.example/logout'] }),
    );
    assert.deepEqual(problems, []);
  });
});
