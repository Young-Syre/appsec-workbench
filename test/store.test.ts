import { strict as assert } from 'node:assert';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test, { describe } from 'node:test';

import { Project, severityRank, type Finding } from '../src/core/store.js';
import { parseScopeConfig } from '../src/core/scope.js';
import { makeExchange, makeRequest, makeResponse, withProject, tempDir } from './helpers.js';

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: 'f1',
    check: 'PASSIVE-COOKIE',
    title: 'Session cookie without HttpOnly',
    severity: 'medium',
    confidence: 'certain',
    evidence: ['aaaa'],
    detail: 'detail',
    remediation: 'set HttpOnly',
    url: 'https://target.example/login',
    at: 1,
    ...over,
  };
}

describe('a project is a directory, created explicitly', () => {
  test('create lays out the files a reader can inspect', () => {
    withProject((_project, dir) => {
      for (const f of ['meta.json', 'exchanges.jsonl', 'frames.jsonl', 'findings.jsonl']) {
        assert.ok(existsSync(join(dir, f)), `${f} should exist`);
      }
      assert.ok(existsSync(join(dir, 'blobs')));
    });
  });

  test('creating over an existing project refuses rather than overwriting evidence', () => {
    withProject((_p, dir) => {
      assert.throws(() => Project.create(dir), /already exists/);
    });
  });

  test('opening a directory that is not a project says how to make one', () => {
    assert.throws(() => Project.open(join(tempDir(), 'nope.awb')), /awb init/);
  });

  test('an unknown project version is refused, not guessed at', () => {
    const dir = join(tempDir(), 'v9.awb');
    Project.create(dir);
    writeFileSync(join(dir, 'meta.json'), JSON.stringify({ version: 9 }));
    assert.throws(() => Project.open(dir), /unsupported project version 9/);
  });

  test('openOrCreate is idempotent', () => {
    const dir = join(tempDir(), 'x.awb');
    Project.openOrCreate(dir).append(makeExchange());
    assert.equal(Project.openOrCreate(dir).count(), 1);
  });
});

describe('the exchange log is append-only and round-trips exactly', () => {
  test('what goes in comes out, bodies included', () => {
    withProject((project) => {
      const original = makeExchange({
        request: makeRequest({
          method: 'POST',
          body: Buffer.from('{"a":1}'),
          headers: [
            ['Host', 'target.example'],
            ['Cookie', 'a=1'],
            ['Cookie', 'b=2'],
          ],
        }),
      });
      project.append(original);
      const [read] = [...project.exchanges()];
      assert.ok(read);
      assert.equal(read.request.method, 'POST');
      assert.equal(read.request.body.toString(), '{"a":1}');
      assert.deepEqual(read.request.headers, original.request.headers);
      assert.equal(read.response?.body.toString(), original.response?.body.toString());
    });
  });

  test('order is capture order', () => {
    withProject((project) => {
      for (const path of ['/a', '/b', '/c']) {
        project.append(makeExchange({ request: makeRequest({ url: `https://target.example${path}` }) }));
      }
      assert.deepEqual(
        [...project.exchanges()].map((e) => new URL(e.request.url).pathname),
        ['/a', '/b', '/c'],
      );
    });
  });

  test('each append is one line, so another process can tail it', () => {
    withProject((project, dir) => {
      project.append(makeExchange());
      project.append(makeExchange());
      const lines = readFileSync(join(dir, 'exchanges.jsonl'), 'utf8')
        .split('\n')
        .filter((l) => l.length > 0);
      assert.equal(lines.length, 2);
      for (const line of lines) JSON.parse(line);
    });
  });

  test('an exchange with no response survives, with its error', () => {
    withProject((project) => {
      const { response: _dropped, ...withoutResponse } = makeExchange();
      project.append({ ...withoutResponse, error: 'ECONNREFUSED' });
      const [read] = [...project.exchanges()];
      assert.equal(read?.response, undefined);
      assert.equal(read?.error, 'ECONNREFUSED');
    });
  });

  test('streaming yields the same records as the synchronous read', async () => {
    const dir = join(tempDir(), 's.awb');
    const project = Project.create(dir);
    for (let i = 0; i < 5; i += 1) {
      project.append(makeExchange({ request: makeRequest({ url: `https://target.example/${i}` }) }));
    }
    const streamed: string[] = [];
    for await (const ex of project.stream()) streamed.push(ex.request.url);
    assert.deepEqual(streamed, [...project.exchanges()].map((e) => e.request.url));
  });
});

describe('bodies are content-addressed, so a repeated bundle is stored once', () => {
  test('identical bodies share one blob', () => {
    withProject((project) => {
      const body = Buffer.from('x'.repeat(4096));
      for (let i = 0; i < 10; i += 1) {
        project.append(
          makeExchange({
            request: makeRequest({ url: `https://target.example/page/${i}` }),
            response: makeResponse({ body }),
          }),
        );
      }
      // One blob for the shared response body, one for the empty request body.
      assert.equal(project.blobCount(), 2);
      assert.equal(project.count(), 10);
    });
  });

  test('a differing body gets its own blob', () => {
    withProject((project) => {
      project.append(makeExchange({ response: makeResponse({ body: Buffer.from('a') }) }));
      project.append(makeExchange({ response: makeResponse({ body: Buffer.from('b') }) }));
      assert.equal(project.blobCount(), 3);
    });
  });

  test('an empty body needs no blob file of its own', () => {
    withProject((project) => {
      project.append(
        makeExchange({ response: makeResponse({ body: Buffer.alloc(0) }) }),
      );
      const [read] = [...project.exchanges()];
      assert.equal(read?.response?.body.length, 0);
    });
  });

  test('a missing blob is a loud error, not an empty body', () => {
    withProject((project) => {
      assert.throws(() => project.getBlob('0'.repeat(64)), /is missing from/);
    });
  });
});

describe('lookup accepts an id prefix, the way a human types one', () => {
  test('a prefix resolves', () => {
    withProject((project) => {
      const ex = makeExchange();
      project.append(ex);
      assert.equal(project.get(ex.id.slice(0, 6))?.id, ex.id);
    });
  });

  test('an unknown id is undefined rather than a throw', () => {
    withProject((project) => {
      assert.equal(project.get('deadbeef'), undefined);
    });
  });
});

describe('scope and authorisation live in the project, not in the shell history', () => {
  test('scope survives a round trip through the file', () => {
    withProject((project, dir) => {
      project.setScope(parseScopeConfig({ include: ['*.target.example'], exclude: ['https://admin.target.example'] }));
      const reopened = Project.open(dir);
      assert.deepEqual(reopened.scope().include.map((r) => r.host), ['*.target.example']);
      assert.deepEqual(reopened.scope().exclude.map((r) => r.host), ['admin.target.example']);
    });
  });

  test('an authorisation record survives a round trip', () => {
    withProject((project, dir) => {
      project.setAuthorisation({
        engagement: 'Example Programme',
        authorisedBy: 'security@example.com',
        from: '2026-01-01',
        until: '2026-12-31',
        reference: 'TICKET-1',
      });
      assert.equal(Project.open(dir).authorisation()?.engagement, 'Example Programme');
    });
  });

  test('a malformed stored authorisation fails on open rather than being ignored', () => {
    withProject((project, dir) => {
      const meta = JSON.parse(readFileSync(join(dir, 'meta.json'), 'utf8')) as Record<string, unknown>;
      meta['authorisation'] = { engagement: 'x' };
      writeFileSync(join(dir, 'meta.json'), JSON.stringify(meta));
      assert.throws(() => Project.open(dir), /missing a non-empty authorisedBy/);
      void project;
    });
  });
});

describe('findings collapse on read and keep the raw log complete', () => {
  test('the same check on one origin is one finding with pooled evidence', () => {
    withProject((project) => {
      project.appendFinding(finding({ evidence: ['a1'], url: 'https://target.example/one' }));
      project.appendFinding(finding({ evidence: ['a2'], url: 'https://target.example/two' }));
      assert.equal([...project.findings()].length, 2, 'the log keeps both');
      const deduped = project.dedupedFindings();
      assert.equal(deduped.length, 1);
      assert.deepEqual(deduped[0]?.evidence, ['a1', 'a2']);
    });
  });

  test('the worst severity and strongest confidence win', () => {
    withProject((project) => {
      project.appendFinding(finding({ severity: 'low', confidence: 'tentative' }));
      project.appendFinding(finding({ severity: 'high', confidence: 'certain' }));
      const [only] = project.dedupedFindings();
      assert.equal(only?.severity, 'high');
      assert.equal(only?.confidence, 'certain');
    });
  });

  test('different origins stay separate', () => {
    withProject((project) => {
      project.appendFinding(finding({ url: 'https://a.target.example/x' }));
      project.appendFinding(finding({ url: 'https://b.target.example/x' }));
      assert.equal(project.dedupedFindings().length, 2);
    });
  });

  test('output is ordered worst-first', () => {
    withProject((project) => {
      project.appendFinding(finding({ check: 'C', severity: 'low' }));
      project.appendFinding(finding({ check: 'A', severity: 'critical' }));
      project.appendFinding(finding({ check: 'B', severity: 'medium' }));
      assert.deepEqual(project.dedupedFindings().map((f) => f.severity), [
        'critical',
        'medium',
        'low',
      ]);
    });
  });

  test('severityRank orders the scale the way a report should', () => {
    assert.ok(severityRank('critical') < severityRank('high'));
    assert.ok(severityRank('high') < severityRank('medium'));
    assert.ok(severityRank('low') < severityRank('info'));
  });
});

describe('websocket frames are stored beside the exchange that opened them', () => {
  test('frames round-trip with direction and opcode', () => {
    withProject((project) => {
      project.appendFrame({
        exchangeId: 'abc',
        direction: 'sent',
        opcode: 'text',
        payload: Buffer.from('{"op":"subscribe"}'),
        at: 1,
      });
      const [frame] = [...project.frames()];
      assert.equal(frame?.direction, 'sent');
      assert.equal(frame?.opcode, 'text');
      assert.equal(frame?.payload.toString(), '{"op":"subscribe"}');
    });
  });

  test('frame payloads are deduplicated like bodies', () => {
    withProject((project) => {
      const payload = Buffer.from('ping'.repeat(100));
      for (let i = 0; i < 20; i += 1) {
        project.appendFrame({ exchangeId: 'abc', direction: 'sent', opcode: 'text', payload, at: i });
      }
      assert.equal(project.blobCount(), 1);
      assert.equal([...project.frames()].length, 20);
    });
  });
});
