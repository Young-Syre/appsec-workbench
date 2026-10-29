import { strict as assert } from 'node:assert';
import test, { describe } from 'node:test';

import {
  counts,
  parseFormat,
  parseSeverity,
  render,
  renderJson,
  renderMarkdown,
  renderSarif,
  renderText,
} from '../src/report/index.js';
import { PASSIVE_CHECKS } from '../src/scan/passive/index.js';
import { ACTIVE_CHECKS } from '../src/scan/active/checks.js';
import type { Finding } from '../src/core/store.js';
import type { Exchange } from '../src/core/message.js';
import { makeExchange, makeRequest, makeResponse } from './helpers.js';

const SESSION = 'a9f3c1e7b25d4086b1c4e7f20a5d8311';

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: 'f-1',
    check: 'AWB-P020',
    title: 'Access-Control-Allow-Origin reflects the request Origin with credentials allowed',
    severity: 'critical',
    confidence: 'firm',
    evidence: ['aaaabbbbccccdddd'],
    detail: 'The response echoes the Origin it was sent.',
    remediation: 'Compare Origin against an allow-list.',
    url: 'https://target.example/api/me',
    at: 1,
    ...over,
  };
}

const SPREAD: Finding[] = [
  finding({ id: 'a', severity: 'info', check: 'AWB-P007', title: 'Server header' }),
  finding({ id: 'b', severity: 'critical', check: 'AWB-P020' }),
  finding({ id: 'c', severity: 'medium', check: 'AWB-P010', title: 'Cookie without HttpOnly' }),
  finding({ id: 'd', severity: 'high', check: 'AWB-A002', title: 'SQL injection' }),
];

describe('ordering and filtering', () => {
  test('findings come out worst first', () => {
    const out = renderJson(SPREAD);
    const order = (JSON.parse(out) as { findings: { severity: string }[] }).findings.map(
      (f) => f.severity,
    );
    assert.deepEqual(order, ['critical', 'high', 'medium', 'info']);
  });

  test('minSeverity excludes everything below it', () => {
    const parsed = JSON.parse(renderJson(SPREAD, { minSeverity: 'high' })) as {
      findings: unknown[];
    };
    assert.equal(parsed.findings.length, 2);
  });

  test('counts tallies by severity', () => {
    assert.deepEqual(counts(SPREAD), { critical: 1, high: 1, medium: 1, low: 0, info: 1 });
  });

  test('an empty report says so rather than printing an empty table', () => {
    assert.match(renderText([]), /no findings at or above/);
    assert.match(renderMarkdown([]), /No findings at or above/);
  });
});

describe('redaction applies on the way out of every format', () => {
  const leaky = finding({
    url: `https://target.example/api/me?session=${SESSION}`,
    detail: `The cookie session=${SESSION} was accepted.`,
  });

  for (const format of ['text', 'json', 'markdown', 'sarif'] as const) {
    test(`${format} does not carry the credential`, () => {
      const out = render(format, [leaky]);
      assert.ok(!out.includes(SESSION), `${format} leaked the session value`);
    });
  }

  test('showSecrets is the only way to include it', () => {
    assert.ok(render('text', [leaky], { showSecrets: true }).includes(SESSION));
  });

  test('a quoted exchange is redacted too', () => {
    const exchange: Exchange = makeExchange({
      request: makeRequest({
        headers: [
          ['Host', 'target.example'],
          ['Cookie', `session=${SESSION}`],
        ],
      }),
      response: makeResponse({ body: Buffer.from(`{"echo":"${SESSION}"}`) }),
    });
    const out = renderMarkdown([finding({ evidence: [exchange.id] })], {
      exchanges: new Map([[exchange.id, exchange]]),
    });
    assert.ok(out.includes('<details>'), 'the exchange should be quoted');
    assert.ok(!out.includes(SESSION), 'including the body, which no header named');
  });
});

describe('text output', () => {
  test('carries the severity, check, url, confidence and evidence', () => {
    const out = renderText([finding()]);
    assert.match(out, /CRIT\s+AWB-P020/);
    assert.match(out, /https:\/\/target\.example\/api\/me/);
    assert.match(out, /confidence: firm/);
    assert.match(out, /evidence: aaaabbbbccccdddd/);
    assert.match(out, /fix: Compare Origin/);
  });

  test('a long detail is wrapped rather than printed as one line', () => {
    const out = renderText([finding({ detail: 'word '.repeat(80) })]);
    const longest = Math.max(...out.split('\n').map((l) => l.length));
    assert.ok(longest < 100, `expected wrapping, longest line was ${longest}`);
  });

  test('paragraph breaks in a detail survive wrapping', () => {
    const out = renderText([finding({ detail: 'first para\n\nsecond para' })]);
    assert.ok(out.includes('first para'));
    assert.ok(out.includes('second para'));
  });

  test('the authorisation is printed when there was one', () => {
    assert.match(renderText([], { authorisation: 'Example Programme (ref T-1)' }), /authorised: Example Programme/);
  });

  test('a model assessment is labelled as one', () => {
    const out = renderText([
      finding({
        aiAssessment: {
          model: 'claude-sonnet-5-5',
          verdict: 'exploitable',
          reasoning: 'The Origin was echoed.',
          at: 1,
        },
      }),
    ]);
    assert.match(out, /model \(claude-sonnet-5-5\): exploitable/);
  });
});

describe('json output is stable', () => {
  test('two renders of the same findings are byte-identical', () => {
    assert.equal(renderJson(SPREAD), renderJson(SPREAD));
  });

  test('keys are sorted, so a diff shows content changes only', () => {
    const parsed = JSON.parse(renderJson([finding()])) as { findings: Record<string, unknown>[] };
    const keys = Object.keys(parsed.findings[0] ?? {});
    assert.deepEqual(keys, [...keys].sort());
  });

  test('the envelope carries the tool, counts and findings', () => {
    const parsed = JSON.parse(renderJson(SPREAD, { toolVersion: '0.1.0' })) as Record<string, unknown>;
    assert.equal(parsed['tool'], 'appsec-workbench');
    assert.equal(parsed['version'], '0.1.0');
    assert.ok(parsed['counts'] !== undefined);
    assert.equal((parsed['findings'] as unknown[]).length, 4);
  });
});

describe('markdown output', () => {
  test('has a summary table and a section per finding', () => {
    const out = renderMarkdown(SPREAD);
    assert.match(out, /\| Severity \| Count \|/);
    assert.match(out, /## AWB-P020: Access-Control-Allow-Origin/);
    assert.equal((out.match(/^## /gm) ?? []).length, 4);
  });

  test('a pipe in a title does not break the table', () => {
    const out = renderMarkdown([finding({ title: 'a | b' })]);
    const row = out.split('\n').find((l) => l.includes('a \\| b'));
    assert.ok(row !== undefined, 'the pipe should be escaped');
  });

  test('the model assessment is marked as not a substitute for verification', () => {
    const out = renderMarkdown([
      finding({
        aiAssessment: { model: 'claude-sonnet-5-5', verdict: 'likely', reasoning: 'r', at: 1 },
      }),
    ]);
    assert.match(out, /not a substitute for verification/);
  });
});

describe('SARIF is valid in the ways that matter to a viewer', () => {
  const parsed = (findings: readonly Finding[]): Record<string, unknown> =>
    JSON.parse(renderSarif(findings, { toolVersion: '0.1.0' })) as Record<string, unknown>;

  test('the version and schema are declared', () => {
    const doc = parsed(SPREAD);
    assert.equal(doc['version'], '2.1.0');
    assert.match(String(doc['$schema']), /sarif-2\.1\/schema/);
  });

  test('every rule a result references is declared in the driver', () => {
    const doc = parsed(SPREAD) as unknown as {
      runs: { tool: { driver: { rules: { id: string }[] } }; results: { ruleId: string }[] }[];
    };
    const declared = new Set(doc.runs[0]?.tool.driver.rules.map((r) => r.id));
    for (const result of doc.runs[0]?.results ?? []) {
      assert.ok(declared.has(result.ruleId), `${result.ruleId} is referenced but not declared`);
    }
    assert.equal(declared.size, 4);
  });

  test('ruleIndex points at the right rule', () => {
    const doc = parsed(SPREAD) as unknown as {
      runs: { tool: { driver: { rules: { id: string }[] } }; results: { ruleId: string; ruleIndex: number }[] }[];
    };
    const rules = doc.runs[0]?.tool.driver.rules ?? [];
    for (const result of doc.runs[0]?.results ?? []) {
      assert.equal(rules[result.ruleIndex]?.id, result.ruleId);
    }
  });

  test('every result has a physical location, or a viewer shows nothing', () => {
    const doc = parsed(SPREAD) as unknown as {
      runs: { results: { locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }[] }[];
    };
    for (const result of doc.runs[0]?.results ?? []) {
      assert.equal(result.locations.length, 1);
      assert.ok((result.locations[0]?.physicalLocation.artifactLocation.uri ?? '').length > 0);
    }
  });

  test('severity maps to a level and to a numeric security-severity', () => {
    const doc = parsed([
      finding({ severity: 'critical' }),
      finding({ id: 'x', severity: 'medium' }),
      finding({ id: 'y', severity: 'info' }),
    ]) as unknown as {
      runs: { results: { level: string; properties: Record<string, string> }[] }[];
    };
    const results = doc.runs[0]?.results ?? [];
    assert.deepEqual(results.map((r) => r.level), ['error', 'warning', 'note']);
    assert.equal(results[0]?.properties['security-severity'], '9.5');
  });

  test('rule names are schema-safe identifiers', () => {
    const doc = parsed(SPREAD) as unknown as {
      runs: { tool: { driver: { rules: { name: string }[] } } }[];
    };
    for (const rule of doc.runs[0]?.tool.driver.rules ?? []) {
      assert.match(rule.name, /^[A-Za-z0-9]+$/);
    }
  });

  test('a fingerprint is emitted so a dashboard can deduplicate across runs', () => {
    const doc = parsed([finding()]) as unknown as {
      runs: { results: { partialFingerprints: Record<string, string> }[] }[];
    };
    assert.equal(doc.runs[0]?.results[0]?.partialFingerprints['awbFindingId'], 'f-1');
  });

  test('every registered check has a description, so no rule renders empty', () => {
    const all = [...PASSIVE_CHECKS, ...ACTIVE_CHECKS];
    const findings = all.map((c, i) => finding({ id: `g${i}`, check: c.id }));
    const doc = parsed(findings) as unknown as {
      runs: { tool: { driver: { rules: { id: string; fullDescription: { text: string } }[] } } }[];
    };
    for (const rule of doc.runs[0]?.tool.driver.rules ?? []) {
      assert.ok(
        !rule.fullDescription.text.includes('No description is registered'),
        `${rule.id} is not in the registry`,
      );
    }
  });

  test('an empty finding list still produces a valid document', () => {
    const doc = parsed([]) as unknown as { runs: { results: unknown[]; tool: { driver: { rules: unknown[] } } }[] };
    assert.deepEqual(doc.runs[0]?.results, []);
    assert.deepEqual(doc.runs[0]?.tool.driver.rules, []);
  });
});

describe('format and severity parsing', () => {
  test('known formats, including the md alias', () => {
    assert.equal(parseFormat('TEXT'), 'text');
    assert.equal(parseFormat('md'), 'markdown');
    assert.equal(parseFormat('sarif'), 'sarif');
  });

  test('an unknown format lists the known ones', () => {
    assert.throws(() => parseFormat('pdf'), /Known: text, json, markdown, sarif/);
  });

  test('severities parse and list themselves on error', () => {
    assert.equal(parseSeverity('HIGH'), 'high');
    assert.throws(() => parseSeverity('urgent'), /Known: critical, high, medium, low, info/);
  });
});
