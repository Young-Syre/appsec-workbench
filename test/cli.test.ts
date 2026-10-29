import { strict as assert } from 'node:assert';
import { spawn, spawnSync } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { connect as netConnect } from 'node:net';
import { join } from 'node:path';
import test, { after, before, describe } from 'node:test';

import { COMMANDS, helpText } from '../src/cli/main.js';
import { tempDir } from './helpers.js';

const CLI = join(process.cwd(), 'dist', 'src', 'cli', 'main.js');

interface Run {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

/**
 * Run the CLI as a child process.
 *
 * Asynchronous on purpose. spawnSync blocks this process's event loop, and
 * the fixture application under test is served *from* this process -- so a
 * synchronous spawn means the child's request is accepted by the kernel and
 * never answered, and every command that talks to the fixture times out. That
 * cost an hour to find, so it is written down here.
 */
async function awb(
  args: readonly string[],
  options: { cwd?: string; env?: Record<string, string> } = {},
): Promise<Run> {
  return new Promise<Run>((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      cwd: options.cwd ?? process.cwd(),
      env: { ...process.env, ...(options.env ?? {}) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk: string) => {
      stderr += chunk;
    });
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`awb ${args.join(' ')} did not finish within 120s`));
    }, 120_000);
    timer.unref();
    child.on('error', reject);
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ status: code ?? -1, stdout, stderr });
    });
  });
}

/** The application the CLI is pointed at. Broken in a couple of known ways. */
async function app(): Promise<{ port: number; close: () => Promise<void> }> {
  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname === '/login' && url.searchParams.has('next')) {
      res.writeHead(302, { location: url.searchParams.get('next') ?? '/' });
      res.end();
      return;
    }
    if (url.pathname === '/api/me') {
      res.writeHead(200, {
        'content-type': 'application/json',
        'access-control-allow-origin': req.headers.origin ?? '*',
        'access-control-allow-credentials': 'true',
      });
      res.end('{"user":"alice"}');
      return;
    }
    if (url.pathname === '/record') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(`record ${url.searchParams.get('id') ?? ''}`);
      return;
    }
    res.writeHead(200, {
      'content-type': 'text/html',
      'set-cookie': 'session=abc123def456; Path=/',
      server: 'test-server/1.2.3',
    });
    res.end('<html><body><h1>Fixture</h1><form action="/login"><button>Go</button></form></body></html>');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  return {
    port: typeof addr === 'object' && addr !== null ? addr.port : 0,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

/** Make a request through the proxy, the way a configured client would. */
async function throughProxy(proxyPort: number, absoluteUrl: string, headers: [string, string][] = []): Promise<number> {
  const u = new URL(absoluteUrl);
  const all: [string, string][] = [['Host', u.host], ...headers, ['Connection', 'close']];
  const wire =
    `GET ${absoluteUrl} HTTP/1.1\r\n${all.map(([k, v]) => `${k}: ${v}`).join('\r\n')}\r\n\r\n`;
  return new Promise((resolve, reject) => {
    const socket = netConnect({ host: '127.0.0.1', port: proxyPort }, () => socket.write(wire));
    const chunks: Buffer[] = [];
    socket.on('data', (c: Buffer) => chunks.push(c));
    socket.on('end', () => {
      const raw = Buffer.concat(chunks).toString('latin1');
      resolve(Number(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(raw)?.[1] ?? 0));
    });
    socket.on('error', reject);
    socket.setTimeout(10_000, () => reject(new Error('proxy request timed out')));
  });
}

describe('help and version', () => {
  test('bare invocation prints help and exits 2, because nothing was asked for', async () => {
    const run = await awb([]);
    assert.equal(run.status, 2);
    assert.match(run.stdout, /usage: awb <command>/);
  });

  test('--help exits 0', async () => {
    assert.equal((await awb(['--help'])).status, 0);
  });

  test('--version prints just the version', async () => {
    const run = await awb(['--version']);
    assert.equal(run.status, 0);
    assert.match(run.stdout.trim(), /^\d+\.\d+\.\d+$/);
  });

  test('the version matches package.json, so the two cannot drift', async () => {
    const pkg = JSON.parse(readFileSync('package.json', 'utf8')) as { version: string };
    assert.equal((await awb(['--version'])).stdout.trim(), pkg.version);
  });

  test('every command is listed in help and has its own help page', async () => {
    const text = helpText();
    for (const command of COMMANDS) {
      assert.ok(text.includes(command.name), `${command.name} is missing from help`);
      const run = await awb([command.name, '--help']);
      assert.equal(run.status, 0, `awb ${command.name} --help failed`);
      assert.match(run.stdout, /usage:/);
      assert.ok(run.stdout.includes(command.summary.slice(0, 20)));
    }
  });

  test('an unknown command exits 2 and prints the list', async () => {
    const run = await awb(['nonsense']);
    assert.equal(run.status, 2);
    assert.match(run.stderr, /unknown command/);
    assert.match(run.stderr, /usage: awb/);
  });

  test('an unknown option is rejected with a suggestion rather than ignored', async () => {
    const run = await awb(['ls', '--limti', '5']);
    assert.equal(run.status, 2);
    assert.match(run.stderr, /unknown option --limti/);
    assert.match(run.stderr, /Did you mean --limit\?/);
  });

  test('an option missing its value is rejected', async () => {
    const run = await awb(['ls', '--grep']);
    assert.equal(run.status, 2);
    assert.match(run.stderr, /--grep needs a value/);
  });

  test('the authorised-testing notice is in the top-level help', async () => {
    assert.match((await awb(['--help'])).stdout, /Authorised testing only/);
  });
});

describe('project, scope and authorisation', { concurrency: 1 }, () => {
  let dir: string;

  before(async () => {
    dir = join(tempDir(), 'p.awb');
  });

  test('init creates the project and warns that scope is empty', async () => {
    const run = await awb(['init', dir]);
    assert.equal(run.status, 0);
    assert.ok(existsSync(join(dir, 'meta.json')));
    assert.match(run.stdout, /deny by default/);
  });

  test('init refuses to overwrite an existing project', async () => {
    const run = await awb(['init', dir]);
    assert.equal(run.status, 3);
    assert.match(run.stderr, /already exists/);
  });

  test('scope add then list round-trips', async () => {
    assert.equal((await awb(['scope', 'add', 'target.example', '-p', dir])).status, 0);
    assert.match((await awb(['scope', 'list', '-p', dir])).stdout, /in scope:\s+target\.example/);
  });

  test('scope check answers for a URL and signals the verdict in its exit code', async () => {
    const inScope = await awb(['scope', 'check', 'https://target.example/a', '-p', dir]);
    assert.equal(inScope.status, 0);
    assert.match(inScope.stdout, /in-scope/);

    const out = await awb(['scope', 'check', 'https://elsewhere.example/', '-p', dir]);
    assert.equal(out.status, 1);
    assert.match(out.stdout, /not-covered/);
  });

  test('scope lint reports a contradiction and exits 1', async () => {
    assert.equal((await awb(['scope', 'exclude', 'target.example', '-p', dir])).status, 0);
    const lint = await awb(['scope', 'lint', '-p', dir]);
    assert.equal(lint.status, 1);
    assert.match(lint.stdout, /both included and excluded/);
    await awb(['scope', 'rm', 'target.example', '-p', dir]);
    await awb(['scope', 'add', 'target.example', '-p', dir]);
    assert.equal((await awb(['scope', 'lint', '-p', dir])).status, 0);
  });

  test('auth show refuses before a record exists, with exit 4', async () => {
    const run = await awb(['auth', 'show', '-p', dir]);
    assert.equal(run.status, 4);
    assert.match(run.stdout, /not authorised/);
  });

  test('auth set records it, and show then confirms', async () => {
    const set = await awb([
      'auth', 'set',
      '--engagement', 'CLI test',
      '--by', 'the test suite',
      '--until', '2099-12-31',
      '--ref', 'test/cli.test.ts',
      '-p', dir,
    ]);
    assert.equal(set.status, 0);
    const show = await awb(['auth', 'show', '-p', dir]);
    assert.equal(show.status, 0);
    assert.match(show.stdout, /authorised: {2}CLI test/);
  });

  test('an expired record fails closed rather than warning', async () => {
    const expiredDir = join(tempDir(), 'expired.awb');
    await awb(['init', expiredDir]);
    await awb([
      'auth', 'set',
      '--engagement', 'Over',
      '--by', 'someone',
      '--from', '2020-01-01',
      '--until', '2020-01-02',
      '--ref', 'r',
      '-p', expiredDir,
    ]);
    const show = await awb(['auth', 'show', '-p', expiredDir]);
    assert.equal(show.status, 4);
    assert.match(show.stdout, /expired on 2020-01-02/);
  });

  test('an authorisation that expires before it starts is rejected', async () => {
    const run = await awb([
      'auth', 'set',
      '--engagement', 'Backwards',
      '--by', 'x',
      '--from', '2026-06-01',
      '--until', '2026-01-01',
      '--ref', 'r',
      '-p', dir,
    ]);
    assert.equal(run.status, 3);
    assert.match(run.stderr, /expires .* before it starts/);
  });

  test('doctor reports the environment and the project', async () => {
    const run = await awb(['doctor', '-p', dir]);
    assert.equal(run.status, 0, run.stdout + run.stderr);
    assert.match(run.stdout, /ok {4}node/);
    assert.match(run.stdout, /ok {4}openssl/);
    assert.match(run.stdout, /ok {4}scope/);
  });

  test('doctor fails when the scope is empty, because nothing would be sent', async () => {
    const emptyDir = join(tempDir(), 'empty.awb');
    await awb(['init', emptyDir]);
    const run = await awb(['doctor', '-p', emptyDir]);
    assert.equal(run.status, 3);
    assert.match(run.stdout, /FAIL {2}scope/);
  });
});

describe('the certificate authority', () => {
  test('ca show creates it and prints a fingerprint', async () => {
    const dir = join(tempDir(), 'ca.awb');
    await awb(['init', dir]);
    const run = await awb(['ca', 'show', '-p', dir]);
    assert.equal(run.status, 0);
    assert.match(run.stdout, /fingerprint: {2}[0-9A-F:]{59}/);
    assert.match(run.stdout, /created now/);
    assert.ok(existsSync(join(dir, 'ca', 'ca.crt')));
  });

  test('ca trust explains the risk before it explains the procedure', async () => {
    const dir = join(tempDir(), 'ca2.awb');
    await awb(['init', dir]);
    const run = await awb(['ca', 'trust', '-p', dir]);
    assert.equal(run.status, 0);
    const risk = run.stdout.indexOf('impersonate any');
    const procedure = run.stdout.indexOf('update-ca-certificates');
    assert.ok(risk >= 0 && procedure > risk, 'the warning must come first');
    assert.match(run.stdout, /curl --proxy/);
  });

  test('the CA private key is not world-readable', async () => {
    const dir = join(tempDir(), 'ca3.awb');
    await awb(['init', dir]);
    await awb(['ca', 'show', '-p', dir]);
    const mode = spawnSync('stat', ['-c', '%a', join(dir, 'ca', 'ca.key')], { encoding: 'utf8' });
    assert.equal(mode.stdout.trim(), '600');
  });
});

/**
 * Sequential on purpose.
 *
 * Node's test runner will happily run the subtests of a suite concurrently,
 * and these steps are a pipeline: capture, then list, then replay what was
 * listed. Running them in parallel produced a failure that looked like a bug
 * in `replay` and was a bug in the test.
 */
describe('an end-to-end run against a local application', { concurrency: 1 }, () => {
  let fixture: Awaited<ReturnType<typeof app>>;
  let dir: string;
  let proxy: ReturnType<typeof spawn>;
  let proxyPort = 0;

  before(async () => {
    fixture = await app();
    dir = join(tempDir(), 'e2e.awb');

    assert.equal((await awb(['init', dir])).status, 0);
    assert.equal((await awb(['scope', 'add', `http://127.0.0.1:${fixture.port}`, '-p', dir])).status, 0);

    proxy = spawn(process.execPath, [CLI, 'proxy', '--port', '0', '-p', dir], {
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    proxyPort = await new Promise<number>((resolve, reject) => {
      let buffer = '';
      const timer = setTimeout(() => reject(new Error(`proxy did not start: ${buffer}`)), 20_000);
      timer.unref();
      proxy.stderr?.on('data', (chunk: Buffer) => {
        buffer += chunk.toString();
        const match = /proxy listening on 127\.0\.0\.1:(\d+)/.exec(buffer);
        if (match !== null) {
          clearTimeout(timer);
          resolve(Number(match[1]));
        }
      });
      proxy.on('error', reject);
    });

    // The traffic every step below depends on. Generated in the hook rather
    // than in the first test, so no step can run before it exists.
    assert.equal(await throughProxy(proxyPort, `http://127.0.0.1:${fixture.port}/`), 200);
    assert.equal(await throughProxy(proxyPort, `http://127.0.0.1:${fixture.port}/record?id=1`), 200);
    assert.equal(
      await throughProxy(proxyPort, `http://127.0.0.1:${fixture.port}/api/me`, [
        ['Origin', 'https://attacker.example'],
        ['Cookie', 'session=abc123def456'],
      ]),
      200,
    );
    assert.equal(
      await throughProxy(proxyPort, `http://127.0.0.1:${fixture.port}/login?next=https://evil.example/`),
      302,
    );
    await new Promise((resolve) => setTimeout(resolve, 500));
  });

  after(async () => {
    proxy.kill('SIGTERM');
    await new Promise<void>((resolve) => {
      proxy.on('exit', () => resolve());
      setTimeout(() => {
        proxy.kill('SIGKILL');
        resolve();
      }, 4000).unref();
    });
    await fixture.close();
  });

  test('the traffic generated in setup is in the project', async () => {
    const ls = await awb(['ls', '-p', dir]);
    assert.equal(ls.status, 0);
    assert.ok(ls.stdout.split('\n').filter((l) => l.trim().length > 0).length >= 4, ls.stdout);
  });

  test('an out-of-scope request through the proxy is refused with 403', async () => {
    const status = await throughProxy(proxyPort, 'http://elsewhere.example/');
    assert.equal(status, 403);
  });

  test('ls filters by status and by regex', async () => {
    assert.match((await awb(['ls', '--status', '302', '-p', dir])).stdout, /\/login/);
    const filtered = (await awb(['ls', '--grep', 'record', '-p', dir])).stdout;
    assert.match(filtered, /record/);
    assert.ok(!filtered.includes('/api/me'));
  });

  test('show prints the exchange with the session cookie redacted', async () => {
    const id = /^(\w{16})/m.exec((await awb(['ls', '--grep', 'api/me', '-p', dir])).stdout)?.[1];
    assert.ok(id !== undefined, 'expected to find the api/me exchange');
    const run = await awb(['show', id, '-p', dir]);
    assert.equal(run.status, 0);
    assert.match(run.stdout, /Cookie: session=\[redacted/);
    assert.ok(!run.stdout.includes('abc123def456'));
  });

  test('--unsafe-show-secrets is the only way to see it', async () => {
    const id = /^(\w{16})/m.exec((await awb(['ls', '--grep', 'api/me', '-p', dir])).stdout)?.[1];
    const run = await awb(['show', id as string, '--unsafe-show-secrets', '-p', dir]);
    assert.ok(run.stdout.includes('abc123def456'));
  });

  test('show on an unknown id exits 3 and says how to list them', async () => {
    const run = await awb(['show', 'deadbeefdeadbeef', '-p', dir]);
    assert.equal(run.status, 3);
    assert.match(run.stderr, /awb ls/);
  });

  test('replay --dry-run prints the mutated request without sending it', async () => {
    const id = /^(\w{16})/m.exec((await awb(['ls', '--grep', 'record', '-p', dir])).stdout)?.[1];
    const run = await awb(['replay', id as string, '--set', 'query:id=99', '--dry-run', '-p', dir]);
    assert.equal(run.status, 0);
    assert.match(run.stdout, /GET \/record\?id=99/);
  });

  test('replay sends it and --diff compares against the original', async () => {
    const id = /^(\w{16})/m.exec((await awb(['ls', '--grep', 'record', '-p', dir])).stdout)?.[1];
    const run = await awb(['replay', id as string, '--set', 'query:id=42', '--diff', '-p', dir]);
    assert.equal(run.status, 0, `${run.stderr}${run.stdout}`);
    assert.match(run.stdout, /200 OK/);
    assert.match(run.stdout, /diff vs/);
  });

  test('replay refuses a mutation that would leave scope', async () => {
    const id = /^(\w{16})/m.exec((await awb(['ls', '--grep', 'record', '-p', dir])).stdout)?.[1];
    const rawPath = join(tempDir(), 'raw.http');
    writeFileSync(rawPath, 'GET http://elsewhere.example/ HTTP/1.1\r\nHost: elsewhere.example\r\n\r\n');
    const run = await awb(['replay', id as string, '--raw', rawPath, '-p', dir]);
    assert.equal(run.status, 4);
    assert.match(run.stderr, /refusing to send a request/);
  });

  test('fuzz --dry-run reports the plan without sending anything', async () => {
    const id = /^(\w{16})/m.exec((await awb(['ls', '--grep', 'record', '-p', dir])).stdout)?.[1];
    const run = await awb([
      'fuzz', id as string,
      '--auto-mark',
      '--payload', 'numbers:1-5',
      '--dry-run',
      '-p', dir,
    ]);
    assert.equal(run.status, 0);
    assert.match(run.stdout, /sniper: 1 position\(s\), 5 request\(s\)/);
  });

  test('fuzz refuses an attack above the cap, with the number', async () => {
    const id = /^(\w{16})/m.exec((await awb(['ls', '--grep', 'record', '-p', dir])).stdout)?.[1];
    const run = await awb([
      'fuzz', id as string,
      '--auto-mark',
      '--payload', 'numbers:1-500',
      '--max-requests', '10',
      '-p', dir,
    ]);
    assert.equal(run.status, 3);
    assert.match(run.stderr, /500 requests, above the cap of 10/);
  });

  test('fuzz runs and reports the grouped results', async () => {
    const id = /^(\w{16})/m.exec((await awb(['ls', '--grep', 'record', '-p', dir])).stdout)?.[1];
    const run = await awb([
      'fuzz', id as string,
      '--auto-mark',
      '--payload', 'numbers:1-6',
      '--concurrency', '2',
      '-p', dir,
    ]);
    assert.ok(run.status === 0 || run.status === 1, `${run.status}: ${run.stderr}`);
    assert.match(run.stdout, /status {3}length {2}count {2}payloads/);
  });

  test('fuzz --sets documents the built-in payload sets', async () => {
    const run = await awb(['fuzz', '--sets', '-p', dir]);
    assert.equal(run.status, 0);
    assert.match(run.stdout, /quote-probe/);
    assert.match(run.stdout, /traversal-probe/);
  });

  test('scan finds the passive defects this fixture actually has', async () => {
    const run = await awb(['scan', '-p', dir]);
    assert.equal(run.status, 1, 'findings mean exit 1');
    assert.match(run.stdout, /AWB-P020/, 'the reflected CORS origin');
    assert.match(run.stdout, /AWB-P007/, 'the Server version header');
    assert.match(run.stdout, /AWB-P010/, 'the cookie without flags');
  });

  test('scan --fail-on critical passes when nothing is critical', async () => {
    const cleanDir = join(tempDir(), 'clean.awb');
    await awb(['init', cleanDir]);
    await awb(['scope', 'add', 'target.example', '-p', cleanDir]);
    assert.equal((await awb(['scan', '--fail-on', 'critical', '-p', cleanDir])).status, 0);
  });

  test('scan --active refuses without an authorisation record', async () => {
    const run = await awb(['scan', '--active', '-p', dir]);
    assert.equal(run.status, 4);
    assert.match(run.stderr, /refusing to run active checks/);
    assert.match(run.stderr, /awb auth set/);
  });

  test('scan --active runs once authorised, and records every request it made', async () => {
    await awb([
      'auth', 'set',
      '--engagement', 'CLI end-to-end test against its own fixture',
      '--by', 'the test suite',
      '--until', '2099-12-31',
      '--ref', 'test/cli.test.ts',
      '-p', dir,
    ]);
    const before = (await awb(['ls', '--all', '-p', dir])).stdout.split('\n').length;
    const run = await awb([
      'scan', '--active',
      '--only', 'AWB-A004',
      '--max-requests', '40',
      '-p', dir,
    ]);
    assert.ok(run.status === 0 || run.status === 1, `${run.status}: ${run.stderr}`);
    assert.match(run.stderr, /active: \d+ request\(s\) sent/);
    const after = (await awb(['ls', '--all', '-p', dir])).stdout.split('\n').length;
    assert.ok(after > before, 'the active requests must be in the capture');
    assert.match((await awb(['ls', '--all', '-p', dir])).stdout, /active-scan/);
  });

  test('the open redirect is found by the active check', async () => {
    const run = await awb(['report', '-p', dir]);
    assert.match(run.stdout, /AWB-A004/);
    assert.match(run.stdout, /Open redirect/);
  });

  test('report emits valid SARIF with every rule declared', async () => {
    const output = join(tempDir(), 'out.sarif');
    const run = await awb(['report', '--format', 'sarif', '-o', output, '-p', dir]);
    assert.equal(run.status, 0);
    const doc = JSON.parse(readFileSync(output, 'utf8')) as {
      version: string;
      runs: { tool: { driver: { rules: { id: string }[] } }; results: { ruleId: string; locations: unknown[] }[] }[];
    };
    assert.equal(doc.version, '2.1.0');
    const declared = new Set(doc.runs[0]?.tool.driver.rules.map((r) => r.id));
    assert.ok((doc.runs[0]?.results.length ?? 0) > 0);
    for (const result of doc.runs[0]?.results ?? []) {
      assert.ok(declared.has(result.ruleId), `${result.ruleId} not declared`);
      assert.equal(result.locations.length, 1);
    }
  });

  test('report --format markdown produces a table and sections', async () => {
    const run = await awb(['report', '--format', 'markdown', '-p', dir]);
    assert.equal(run.status, 0);
    assert.match(run.stdout, /\| Severity \| Count \|/);
    assert.match(run.stdout, /^## AWB-/m);
  });

  test('no report format leaks the session cookie', async () => {
    for (const format of ['text', 'json', 'markdown', 'sarif']) {
      const run = await awb(['report', '--format', format, '-p', dir]);
      assert.ok(!run.stdout.includes('abc123def456'), `${format} leaked the cookie value`);
    }
  });

  test('an unknown format is a usage error listing the known ones', async () => {
    const run = await awb(['report', '--format', 'pdf', '-p', dir]);
    assert.equal(run.status, 3);
    assert.match(run.stderr, /Known: text, json, markdown, sarif/);
  });

  test('checks lists both families with their descriptions', async () => {
    const run = await awb(['checks']);
    assert.equal(run.status, 0);
    assert.match(run.stdout, /passive -- a pure function of traffic/);
    assert.match(run.stdout, /active -- sends requests/);
    assert.match(run.stdout, /needs --oob-domain/);
  });

  test('ai --dry-run prints the prompt and sends nothing, with no API key needed', async () => {
    const run = await awb(['ai', 'summarise', '--dry-run', '-p', dir], {
      env: { ANTHROPIC_API_KEY: '' },
    });
    // Exits non-zero because a dry run is not a completed call, by design.
    assert.ok(run.stdout.includes('summarise_surface'), run.stdout.slice(0, 300));
    assert.ok(run.stdout.includes('no authority'), 'the data-not-instructions framing must be in it');
    assert.ok(!run.stdout.includes('abc123def456'), 'the prompt must not carry the session cookie');
  });
});

describe('the proxy refuses to start without scope', () => {
  test('and says what to do about it', async () => {
    const dir = join(tempDir(), 'noscope.awb');
    await awb(['init', dir]);
    const run = await awb(['proxy', '--port', '0', '-p', dir]);
    assert.equal(run.status, 4);
    assert.match(run.stderr, /awb scope add/);
  });
});
