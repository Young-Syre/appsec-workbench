#!/usr/bin/env node
/**
 * The command line.
 *
 * Shape of the thing: a project directory holds the capture, the scope and the
 * authorisation record, and every command operates on one. That is what makes
 * the commands composable -- `awb proxy` fills the project, `awb scan` reads
 * it, `awb replay` adds to it -- and it is what makes a run auditable
 * afterwards, because the project contains every byte that was sent.
 *
 * Exit codes are a contract, documented in the README and asserted in CI:
 *
 *   0  ran to completion, nothing at or above the fail threshold
 *   1  findings at or above the threshold
 *   2  usage error
 *   3  input or environment error
 *   4  refused: out of scope, unauthorised, or over budget
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import {
  type Specs,
  UsageError,
  bool,
  list,
  num,
  parse,
  renderOptions,
  str,
} from './args.js';
import { Project, type Finding, severityRank } from '../core/store.js';
import {
  ScopeViolation,
  decide,
  formatRule,
  lintScope,
  parseRule,
  parseScopeConfig,
} from '../core/scope.js';
import { NotAuthorised, checkAuthorisation, parseAuthorisation } from '../core/authorization.js';
import { Proxy } from '../proxy/server.js';
import { caExists, caFingerprint, caPaths, caSubject, caValidTo, ensureCa, opensslVersion, trustInstructions } from '../proxy/ca.js';
import { validateRules, type Rule } from '../proxy/rules.js';
import { Interceptor } from '../proxy/intercept.js';
import { InterceptConsole, attachToTerminal, systemEditor } from './intercept-ui.js';
import { serialiseRequest, serialiseResponse } from '../core/message.js';
import { redactHeaders, redactText, redactUrl, observedSecrets } from '../core/redact.js';
import { buildReplayRequest, parseMutation, replay, toEditable } from '../replay/replay.js';
import { diffResponses } from '../replay/diff.js';
import { autoMarkQuery, fuzz, groupResults } from '../fuzz/engine.js';
import { BUILTIN_SETS, parsePayloadSpec, parseProcessor } from '../fuzz/payloads.js';
import { PASSIVE_CHECKS, scanAll } from '../scan/passive/index.js';
import { ACTIVE_CHECKS, estimateCost } from '../scan/active/checks.js';
import { ActiveSender, injectionPoints, type ActiveContext } from '../scan/active/runner.js';
import { OobListener } from '../oob/listener.js';
import { AiClient, estimateCostUsd, MODELS } from '../ai/client.js';
import { buildSummaryRequest, triage, validateSummary } from '../ai/tasks.js';
import { parseFormat, parseSeverity, render } from '../report/index.js';
import { VERSION } from '../version.js';

const EXIT_OK = 0;
const EXIT_FINDINGS = 1;
const EXIT_USAGE = 2;
const EXIT_INPUT = 3;
const EXIT_REFUSED = 4;

/** Options every command shares. */
const COMMON: Specs = {
  project: { type: 'string', short: 'p', describe: 'Project directory (default: ./workbench.awb)', placeholder: 'dir' },
  'unsafe-show-secrets': { type: 'boolean', describe: 'Print credentials verbatim. Think first.' },
  quiet: { type: 'boolean', short: 'q', describe: 'Only errors and results' },
};

interface Command {
  readonly name: string;
  readonly summary: string;
  readonly usage: string;
  readonly specs: Specs;
  readonly detail?: string;
  run(argv: readonly string[]): Promise<number>;
}

function projectDir(argv: readonly string[], specs: Specs): string {
  return resolve(str(parse(argv, specs), 'project') ?? 'workbench.awb');
}

function openProject(argv: readonly string[], specs: Specs): Project {
  return Project.open(projectDir(argv, specs));
}

function log(parsed: ReturnType<typeof parse>, message: string): void {
  if (!bool(parsed, 'quiet')) process.stderr.write(`${message}\n`);
}

function out(text: string): void {
  process.stdout.write(text.endsWith('\n') ? text : `${text}\n`);
}

// ---------------------------------------------------------------------------

const initCommand: Command = {
  name: 'init',
  summary: 'Create a project directory',
  usage: 'awb init [dir] [--scope <rule>]...',
  specs: {
    ...COMMON,
    scope: { type: 'string', multiple: true, describe: 'In-scope rule, repeatable', placeholder: 'rule' },
    exclude: { type: 'string', multiple: true, describe: 'Out-of-scope rule, repeatable', placeholder: 'rule' },
  },
  async run(argv) {
    const parsed = parse(argv, this.specs);
    const dir = resolve(parsed.positionals[0] ?? str(parsed, 'project') ?? 'workbench.awb');
    const project = Project.create(dir);
    const scope = parseScopeConfig({ include: list(parsed, 'scope'), exclude: list(parsed, 'exclude') });
    if (scope.include.length > 0 || scope.exclude.length > 0) project.setScope(scope);

    out(`created ${dir}`);
    if (scope.include.length === 0) {
      out('');
      out('Scope is empty, and scope is deny by default: nothing will be sent anywhere until');
      out('you add a rule. If you are authorised to test target.example:');
      out('');
      out(`  awb scope add 'target.example' --project ${dir}`);
    }
    return EXIT_OK;
  },
};

const scopeCommand: Command = {
  name: 'scope',
  summary: 'Show, change and check the scope',
  usage: 'awb scope <list|add|exclude|rm|lint|check> [rule|url]',
  specs: COMMON,
  detail: [
    'Scope is deny by default. Every outbound request in every command asks it',
    'first, and a host it has not cleared is not contacted.',
    '',
    'Rule shorthand:',
    '  target.example            any scheme, port and path',
    '  https://target.example    that scheme only',
    '  *.target.example          one or more labels to the left, never the apex',
    '  target.example:8443/api   that port, paths under /api',
  ].join('\n'),
  async run(argv) {
    const parsed = parse(argv, this.specs);
    const action = parsed.positionals[0] ?? 'list';
    const project = openProject(argv, this.specs);
    const scope = project.scope();

    switch (action) {
      case 'list': {
        if (scope.include.length === 0) out('in scope:  (nothing -- deny by default)');
        for (const rule of scope.include) out(`in scope:  ${formatRule(rule)}`);
        for (const rule of scope.exclude) out(`excluded:  ${formatRule(rule)}`);
        return EXIT_OK;
      }
      case 'add':
      case 'exclude': {
        const rules = parsed.positionals.slice(1);
        if (rules.length === 0) throw new UsageError(`awb scope ${action} needs at least one rule`);
        const parsedRules = rules.map(parseRule);
        const next =
          action === 'add'
            ? { include: [...scope.include, ...parsedRules], exclude: scope.exclude }
            : { include: scope.include, exclude: [...scope.exclude, ...parsedRules] };
        project.setScope(next);
        for (const rule of parsedRules) out(`${action === 'add' ? 'in scope' : 'excluded'}:  ${formatRule(rule)}`);
        return EXIT_OK;
      }
      case 'rm': {
        const targets = new Set(parsed.positionals.slice(1).map((t) => formatRule(parseRule(t))));
        project.setScope({
          include: scope.include.filter((r) => !targets.has(formatRule(r))),
          exclude: scope.exclude.filter((r) => !targets.has(formatRule(r))),
        });
        out(`removed ${targets.size} rule(s)`);
        return EXIT_OK;
      }
      case 'lint': {
        const problems = lintScope(scope);
        if (problems.length === 0) {
          out('the scope is coherent');
          return EXIT_OK;
        }
        for (const problem of problems) out(`${problem.kind}: ${problem.detail}`);
        return EXIT_FINDINGS;
      }
      case 'check': {
        const url = parsed.positionals[1];
        if (url === undefined) throw new UsageError('awb scope check needs a URL');
        const decision = decide(scope, url);
        out(`${decision.verdict}: ${decision.url}`);
        out(`  ${decision.reason}`);
        return decision.verdict === 'in-scope' ? EXIT_OK : EXIT_FINDINGS;
      }
      default:
        throw new UsageError(`unknown scope action ${JSON.stringify(action)}`);
    }
  },
};

const authCommand: Command = {
  name: 'auth',
  summary: 'Record or show the authorisation the active checks run under',
  usage: 'awb auth <show|set> [--engagement ...] [--by ...] [--from ...] [--until ...] [--ref ...]',
  specs: {
    ...COMMON,
    engagement: { type: 'string', describe: 'What is being tested', placeholder: 'name' },
    by: { type: 'string', describe: 'Who authorised it, with a contact', placeholder: 'who' },
    from: { type: 'string', describe: 'Start date, YYYY-MM-DD', placeholder: 'date' },
    until: { type: 'string', describe: 'Expiry date, YYYY-MM-DD', placeholder: 'date' },
    ref: { type: 'string', describe: 'Where the paper lives: URL, ticket, filename', placeholder: 'ref' },
    constraint: { type: 'string', multiple: true, describe: 'A restriction the engagement imposes', placeholder: 'text' },
  },
  detail: [
    'Active checks send requests nobody asked for. This record is what makes',
    '"was that authorised, and by whom" answerable from the project file months',
    'later, and an expired record fails closed rather than warning.',
  ].join('\n'),
  async run(argv) {
    const parsed = parse(argv, this.specs);
    const action = parsed.positionals[0] ?? 'show';
    const project = openProject(argv, this.specs);

    if (action === 'show') {
      const status = checkAuthorisation(project.authorisation());
      // The reason already reads as a sentence; prefixing it with the verdict
      // produced "authorised: authorised for ...".
      out(status.ok ? status.reason.replace(/^authorised for/, 'authorised: ') : `not authorised: ${status.reason}`);
      return status.ok ? EXIT_OK : EXIT_REFUSED;
    }
    if (action !== 'set') throw new UsageError(`unknown auth action ${JSON.stringify(action)}`);

    const constraints = list(parsed, 'constraint');
    const record = parseAuthorisation({
      engagement: str(parsed, 'engagement'),
      authorisedBy: str(parsed, 'by'),
      from: str(parsed, 'from') ?? new Date().toISOString().slice(0, 10),
      until: str(parsed, 'until'),
      reference: str(parsed, 'ref'),
      ...(constraints.length === 0 ? {} : { constraints }),
    });
    project.setAuthorisation(record);
    out(`recorded: ${record.engagement}, authorised by ${record.authorisedBy} until ${record.until}`);
    return EXIT_OK;
  },
};

const caCommand: Command = {
  name: 'ca',
  summary: 'Create the local certificate authority, or explain how to trust it',
  usage: 'awb ca <show|trust|path>',
  specs: { ...COMMON, dir: { type: 'string', describe: 'Where the CA lives (default: <project>/ca)', placeholder: 'dir' } },
  async run(argv) {
    const parsed = parse(argv, this.specs);
    const action = parsed.positionals[0] ?? 'show';
    const dir = str(parsed, 'dir') ?? join(projectDir(argv, this.specs), 'ca');

    if (action === 'path') {
      ensureCa(dir);
      out(caPaths(dir).caCert);
      return EXIT_OK;
    }

    const created = !caExists(dir);
    ensureCa(dir);
    if (action === 'show') {
      out(`openssl:      ${opensslVersion()}`);
      out(`certificate:  ${caPaths(dir).caCert}${created ? '  (created now)' : ''}`);
      out(`subject:      ${caSubject(dir)}`);
      out(`valid until:  ${caValidTo(dir)}`);
      out(`fingerprint:  ${caFingerprint(dir)}`);
      return EXIT_OK;
    }
    if (action === 'trust') {
      out(trustInstructions(caPaths(dir).caCert));
      out('');
      out(`fingerprint to compare afterwards: ${caFingerprint(dir)}`);
      return EXIT_OK;
    }
    throw new UsageError(`unknown ca action ${JSON.stringify(action)}`);
  },
};

const proxyCommand: Command = {
  name: 'proxy',
  summary: 'Run the intercepting proxy',
  usage: 'awb proxy [--port 8080] [--rules rules.json] [--intercept]',
  specs: {
    ...COMMON,
    port: { type: 'number', describe: 'Listen port (default 8080)', placeholder: 'n' },
    host: { type: 'string', describe: 'Listen address (default 127.0.0.1)', placeholder: 'addr' },
    rules: { type: 'string', describe: 'Match-and-replace rules, as JSON', placeholder: 'file' },
    'insecure-upstream': { type: 'boolean', describe: 'Do not verify the target\'s TLS certificate' },
    intercept: { type: 'boolean', describe: 'Hold each in-scope request to forward, edit or drop' },
    'intercept-responses': { type: 'boolean', describe: 'Hold responses as well (implies --intercept)' },
    'intercept-url': { type: 'string', describe: 'Only hold URLs matching this regex', placeholder: 're' },
    'intercept-method': { type: 'string', describe: 'Only hold methods matching this regex', placeholder: 're' },
    'intercept-timeout': { type: 'number', describe: 'Seconds a held message waits (default 120)', placeholder: 's' },
    'intercept-on-timeout': { type: 'string', describe: 'forward (default) or drop, when a hold times out', placeholder: 'act' },
  },
  detail: [
    'Out-of-scope CONNECTs are tunnelled without interception: no certificate is',
    'minted for them, their TLS is never terminated, and nothing about them is',
    'recorded. That is the difference between a capture you can hand over and one',
    'that contains your own webmail.',
    '',
    'Listens on loopback. Binding elsewhere offers a man in the middle to anyone',
    'who can reach the port.',
    '',
    '--intercept holds each in-scope request until you decide: f forward, e edit',
    'in $EDITOR, d drop, i interception on/off, r responses on/off. Out-of-scope',
    'traffic is never held. An edited request is scope-checked again before it',
    'is sent, and nothing in it is recomputed unless you choose to correct a',
    'Content-Length the edit made wrong. Needs a terminal.',
  ].join('\n'),
  async run(argv) {
    const parsed = parse(argv, this.specs);
    const dir = projectDir(argv, this.specs);
    const project = Project.openOrCreate(dir);
    const scope = project.scope();

    if (scope.include.length === 0) {
      process.stderr.write(
        'the project has no scope, and scope is deny by default -- every request would be\n' +
          'refused. Add one first:\n\n  awb scope add target.example\n',
      );
      return EXIT_REFUSED;
    }

    let rules: readonly Rule[] = [];
    const rulesPath = str(parsed, 'rules');
    if (rulesPath !== undefined) {
      rules = JSON.parse(readFileSync(rulesPath, 'utf8')) as Rule[];
      const problems = validateRules(rules);
      if (problems.length > 0) {
        for (const problem of problems) process.stderr.write(`rule error: ${problem}\n`);
        return EXIT_INPUT;
      }
    }

    const interceptor = buildInterceptor(parsed);
    if (interceptor !== undefined && !process.stdin.isTTY) {
      process.stderr.write(
        '--intercept needs a terminal to take keystrokes from, and stdin is not one.\n' +
          'For unattended changes to traffic, use --rules.\n',
      );
      return EXIT_INPUT;
    }
    const console_ =
      interceptor === undefined
        ? undefined
        : new InterceptConsole(
            interceptor,
            { write: (text) => process.stderr.write(text), edit: systemEditor() },
            { showSecrets: bool(parsed, 'unsafe-show-secrets') },
          );
    const say = (line: string): void => {
      if (console_ === undefined) process.stderr.write(`${line}\n`);
      else console_.log(line);
    };

    const caDir = join(dir, 'ca');
    const ca = ensureCa(caDir);
    const proxy = new Proxy({
      port: num(parsed, 'port', 8080),
      host: str(parsed, 'host') ?? '127.0.0.1',
      scope,
      ca,
      rules,
      ...(bool(parsed, 'insecure-upstream') ? { insecureUpstream: true } : {}),
      ...(interceptor === undefined ? {} : { interceptor }),
      onExchange: (exchange) => {
        project.append(exchange);
        if (!bool(parsed, 'quiet')) {
          const status = exchange.response?.status ?? 'ERR';
          const url = bool(parsed, 'unsafe-show-secrets')
            ? exchange.request.url
            : redactUrl(exchange.request.url);
          const edited = exchange.tags.some((t) => t.startsWith('intercept:') && t.endsWith('edited'));
          say(
            `${exchange.id}  ${String(status).padEnd(4)} ${exchange.request.method.padEnd(6)} ${url}` +
              (edited ? '  (edited at the intercept)' : ''),
          );
        }
      },
      onFrame: (frame) => project.appendFrame(frame),
      onTunnel: (host, reason) => {
        if (!bool(parsed, 'quiet')) {
          say(`tunnelled without interception: ${host} (${reason})`);
        }
      },
    });

    const port = await proxy.listen();
    log(parsed, `proxy listening on ${str(parsed, 'host') ?? '127.0.0.1'}:${port}`);
    log(parsed, `project ${dir}`);
    log(parsed, `CA ${ca.caCert} -- \`awb ca trust\` explains how to install it`);
    log(parsed, 'in scope:');
    for (const rule of scope.include) log(parsed, `  ${formatRule(rule)}`);
    if (interceptor !== undefined) {
      log(
        parsed,
        `intercepting requests${interceptor.interceptingResponses ? ' and responses' : ''}: ` +
          'f forward, e edit, d drop, i on/off, r responses, ? keys',
      );
    }
    log(parsed, 'press ctrl-c to stop');

    await new Promise<void>((resolveWait) => {
      let detach: (() => void) | undefined;
      const stop = (): void => {
        detach?.();
        log(parsed, '');
        log(
          parsed,
          `recorded ${proxy.stats.recorded} exchanges, ${proxy.stats.frames} websocket messages, ` +
            `tunnelled ${proxy.stats.tunnelled}, refused ${proxy.stats.blocked}, failed ${proxy.stats.failed}` +
            (interceptor === undefined ? '' : `, dropped ${proxy.stats.dropped}`),
        );
        void proxy.close().then(resolveWait);
      };
      process.once('SIGINT', stop);
      process.once('SIGTERM', stop);
      // In raw mode ctrl-c arrives as a keystroke rather than a signal.
      if (console_ !== undefined) detach = attachToTerminal(console_, process.stdin, stop);
    });
    return EXIT_OK;
  },
};

/** The interceptor the proxy options ask for, or none. */
function buildInterceptor(parsed: ReturnType<typeof parse>): Interceptor | undefined {
  const responses = bool(parsed, 'intercept-responses');
  if (!bool(parsed, 'intercept') && !responses) {
    for (const name of ['intercept-url', 'intercept-method', 'intercept-timeout', 'intercept-on-timeout']) {
      if (parsed.options[name] !== undefined) {
        throw new UsageError(`--${name} only means something with --intercept`);
      }
    }
    return undefined;
  }
  const regex = (name: string): RegExp | undefined => {
    const raw = str(parsed, name);
    if (raw === undefined) return undefined;
    try {
      return new RegExp(raw, name === 'intercept-method' ? 'i' : '');
    } catch (err) {
      throw new UsageError(`--${name} is not a regular expression: ${(err as Error).message}`);
    }
  };
  const onTimeout = str(parsed, 'intercept-on-timeout') ?? 'forward';
  if (onTimeout !== 'forward' && onTimeout !== 'drop') {
    throw new UsageError(`--intercept-on-timeout is forward or drop, not ${JSON.stringify(onTimeout)}`);
  }
  const seconds = num(parsed, 'intercept-timeout', 120);
  if (!(seconds > 0)) throw new UsageError('--intercept-timeout must be a positive number of seconds');
  const url = regex('intercept-url');
  const method = regex('intercept-method');
  return new Interceptor({
    requests: true,
    responses,
    timeoutMs: seconds * 1000,
    onTimeout,
    filter: { ...(url === undefined ? {} : { url }), ...(method === undefined ? {} : { method }) },
  });
}

const lsCommand: Command = {
  name: 'ls',
  summary: 'List captured exchanges',
  usage: 'awb ls [--grep <regex>] [--status 500] [--limit 50]',
  specs: {
    ...COMMON,
    grep: { type: 'string', describe: 'Only URLs matching this regex', placeholder: 'regex' },
    status: { type: 'number', describe: 'Only this status code', placeholder: 'n' },
    method: { type: 'string', describe: 'Only this method', placeholder: 'verb' },
    limit: { type: 'number', describe: 'Most recent N (default 50)', placeholder: 'n' },
    all: { type: 'boolean', describe: 'No limit' },
  },
  async run(argv) {
    const parsed = parse(argv, this.specs);
    const project = openProject(argv, this.specs);
    const grep = str(parsed, 'grep');
    const pattern = grep === undefined ? undefined : new RegExp(grep);
    const wantStatus = parsed.options['status'] === undefined ? undefined : num(parsed, 'status', 0);
    const wantMethod = str(parsed, 'method')?.toUpperCase();

    const rows: string[] = [];
    for (const exchange of project.exchanges()) {
      if (pattern !== undefined && !pattern.test(exchange.request.url)) continue;
      if (wantStatus !== undefined && exchange.response?.status !== wantStatus) continue;
      if (wantMethod !== undefined && exchange.request.method.toUpperCase() !== wantMethod) continue;
      const status = exchange.response?.status ?? 'ERR';
      const size = exchange.response?.body.length ?? 0;
      const url = bool(parsed, 'unsafe-show-secrets')
        ? exchange.request.url
        : redactUrl(exchange.request.url);
      rows.push(
        `${exchange.id}  ${String(status).padEnd(4)} ${exchange.request.method.padEnd(6)} ` +
          `${String(size).padStart(8)}b  ${exchange.source.padEnd(11)} ${url}`,
      );
    }

    const limit = bool(parsed, 'all') ? rows.length : num(parsed, 'limit', 50);
    for (const row of rows.slice(-limit)) out(row);
    if (rows.length > limit) {
      log(parsed, `${rows.length - limit} earlier exchange(s) not shown; --all for everything`);
    }
    if (rows.length === 0) log(parsed, 'nothing matched');
    return EXIT_OK;
  },
};

const showCommand: Command = {
  name: 'show',
  summary: 'Print one exchange',
  usage: 'awb show <id> [--request-only] [--response-only]',
  specs: {
    ...COMMON,
    'request-only': { type: 'boolean', describe: 'Just the request' },
    'response-only': { type: 'boolean', describe: 'Just the response' },
  },
  async run(argv) {
    const parsed = parse(argv, this.specs);
    const id = parsed.positionals[0];
    if (id === undefined) throw new UsageError('awb show needs an exchange id');
    const project = openProject(argv, this.specs);
    const exchange = project.get(id);
    if (exchange === undefined) {
      process.stderr.write(`no exchange matching ${id}. \`awb ls\` lists them.\n`);
      return EXIT_INPUT;
    }

    const show = bool(parsed, 'unsafe-show-secrets');
    const secrets = show ? [] : observedSecrets(exchange.request.headers);
    const scrub = (text: string): string => (show ? text : redactText(text, { extraValues: secrets }));

    if (!bool(parsed, 'response-only')) {
      out(
        scrub(
          serialiseRequest({
            ...exchange.request,
            headers: show ? exchange.request.headers : redactHeaders(exchange.request.headers),
          }),
        ),
      );
    }
    if (!bool(parsed, 'request-only')) {
      out('');
      if (exchange.response === undefined) {
        out(`(no response: ${exchange.error ?? 'unknown'})`);
      } else {
        out(
          scrub(
            serialiseResponse({
              ...exchange.response,
              headers: show ? exchange.response.headers : redactHeaders(exchange.response.headers),
            }),
          ),
        );
      }
    }
    return EXIT_OK;
  },
};

const replayCommand: Command = {
  name: 'replay',
  summary: 'Send a captured request again, changed',
  usage: 'awb replay <id> [--set query:id=2]... [--diff] [--dry-run]',
  specs: {
    ...COMMON,
    set: { type: 'string', multiple: true, describe: 'A mutation; see below', placeholder: 'mutation' },
    'dry-run': { type: 'boolean', describe: 'Print the request instead of sending it' },
    diff: { type: 'boolean', describe: 'Diff the response against the original' },
    raw: { type: 'string', describe: 'Read the whole request from a file', placeholder: 'file' },
    edit: { type: 'boolean', describe: 'Print the editable form and exit' },
    'fix-length': { type: 'boolean', describe: 'Recompute Content-Length before sending' },
    insecure: { type: 'boolean', describe: 'Do not verify the target\'s TLS certificate' },
  },
  detail: [
    'Mutations:',
    '  header:Name=value     set a header, replacing any existing one',
    '  +header:Name=value    add alongside an existing one',
    '  -header:Name          remove every occurrence',
    '  method=POST           change the method',
    '  path=/admin           change the path, keeping the query',
    '  query:id=2            set one query parameter',
    '  -query:page           remove one',
    '  form:role=admin       set one urlencoded body field',
    '  json:user.role=admin  set one JSON field by dotted path',
    '  cookie:session=x      set one cookie, keeping the rest of the jar',
    '  body=<text>           replace the body',
    '',
    'Content-Length is not recomputed unless you pass --fix-length. A length that',
    'disagrees with the body is frequently the test.',
  ].join('\n'),
  async run(argv) {
    const parsed = parse(argv, this.specs);
    const id = parsed.positionals[0];
    if (id === undefined) throw new UsageError('awb replay needs an exchange id');
    const project = openProject(argv, this.specs);
    const original = project.get(id);
    if (original === undefined) {
      process.stderr.write(`no exchange matching ${id}\n`);
      return EXIT_INPUT;
    }

    if (bool(parsed, 'edit')) {
      out(toEditable(original.request));
      return EXIT_OK;
    }

    const mutations = list(parsed, 'set').map(parseMutation);
    const rawPath = str(parsed, 'raw');
    const options = {
      scope: project.scope(),
      mutations,
      ...(rawPath === undefined ? {} : { raw: readFileSync(rawPath, 'utf8') }),
      ...(bool(parsed, 'fix-length') ? { fixContentLength: true } : {}),
      ...(bool(parsed, 'insecure') ? { insecure: true } : {}),
    };

    if (bool(parsed, 'dry-run')) {
      const { request, applied } = buildReplayRequest(original.request, options);
      for (const a of applied) log(parsed, `applied: ${a}`);
      const show = bool(parsed, 'unsafe-show-secrets');
      out(
        show
          ? serialiseRequest(request)
          : redactText(
              serialiseRequest({ ...request, headers: redactHeaders(request.headers) }),
            ),
      );
      return EXIT_OK;
    }

    const result = await replay(original.request, options, original.id);
    project.append(result.exchange);
    for (const a of result.applied) log(parsed, `applied: ${a}`);
    for (const note of result.notes) log(parsed, `note: ${note}`);

    const response = result.exchange.response;
    if (response === undefined) {
      process.stderr.write(`failed: ${result.exchange.error ?? 'unknown'}\n`);
      return EXIT_INPUT;
    }

    out(`${result.exchange.id}  ${response.status} ${response.statusText}  ${response.body.length}b  ${response.elapsedMs}ms`);

    if (bool(parsed, 'diff') && original.response !== undefined) {
      const diff = diffResponses(original.response, response);
      out('');
      out(`diff vs ${original.id}: ${diff.summary}`);
      for (const header of diff.headers) {
        out(`  ${header.kind.padEnd(8)} ${header.name}: ${(header.after ?? header.before ?? []).join(', ')}`);
      }
      for (const line of diff.addedLines.slice(0, 10)) out(`  + ${line.slice(0, 120)}`);
      for (const line of diff.removedLines.slice(0, 10)) out(`  - ${line.slice(0, 120)}`);
    }
    return EXIT_OK;
  },
};

const diffCommand: Command = {
  name: 'diff',
  summary: 'Compare two captured responses',
  usage: 'awb diff <idA> <idB> [--exact]',
  specs: { ...COMMON, exact: { type: 'boolean', describe: 'Do not normalise volatile content' } },
  async run(argv) {
    const parsed = parse(argv, this.specs);
    const [a, b] = parsed.positionals;
    if (a === undefined || b === undefined) throw new UsageError('awb diff needs two exchange ids');
    const project = openProject(argv, this.specs);
    const left = project.get(a);
    const right = project.get(b);
    if (left?.response === undefined || right?.response === undefined) {
      process.stderr.write('both exchanges must exist and have responses\n');
      return EXIT_INPUT;
    }
    const diff = diffResponses(left.response, right.response, { exact: bool(parsed, 'exact') });
    out(`${left.id} -> ${right.id}: ${diff.summary}`);
    out(`  status      ${diff.statusBefore} -> ${diff.statusAfter}`);
    out(`  length      ${diff.lengthBefore} -> ${diff.lengthAfter}`);
    out(`  similarity  ${diff.similarity.toFixed(4)}`);
    out(`  time        ${diff.elapsedBefore}ms -> ${diff.elapsedAfter}ms`);
    for (const header of diff.headers) {
      out(`  ${header.kind.padEnd(8)} ${header.name}`);
      if (header.before !== undefined) out(`           - ${header.before.join(', ').slice(0, 120)}`);
      if (header.after !== undefined) out(`           + ${header.after.join(', ').slice(0, 120)}`);
    }
    for (const line of diff.addedLines) out(`  + ${line.slice(0, 140)}`);
    for (const line of diff.removedLines) out(`  - ${line.slice(0, 140)}`);
    return diff.similarity === 1 && diff.headers.length === 0 ? EXIT_OK : EXIT_FINDINGS;
  },
};

const fuzzCommand: Command = {
  name: 'fuzz',
  summary: 'Send many variants of one request',
  usage: 'awb fuzz <id> --payload set:quote-probe [--shape sniper]',
  specs: {
    ...COMMON,
    payload: { type: 'string', multiple: true, describe: 'Payload source; repeatable', placeholder: 'spec' },
    shape: { type: 'string', describe: 'sniper | battering-ram | pitchfork | cluster-bomb', placeholder: 'shape' },
    process: { type: 'string', multiple: true, describe: 'Transform each payload', placeholder: 'name' },
    marker: { type: 'string', describe: 'Position marker (default §)', placeholder: 'char' },
    'auto-mark': { type: 'boolean', describe: 'Mark every query parameter value' },
    grep: { type: 'string', multiple: true, describe: 'Report responses matching this regex', placeholder: 'regex' },
    concurrency: { type: 'number', describe: 'Simultaneous requests (default 4)', placeholder: 'n' },
    'min-interval': { type: 'number', describe: 'Milliseconds between request starts', placeholder: 'ms' },
    'max-requests': { type: 'number', describe: 'Refuse to start above this (default 10000)', placeholder: 'n' },
    'no-baseline': { type: 'boolean', describe: 'Skip the unfuzzed baseline request' },
    'dry-run': { type: 'boolean', describe: 'Report the plan and send nothing' },
    raw: { type: 'string', describe: 'Read the marked request from a file', placeholder: 'file' },
    sets: { type: 'boolean', describe: 'List the built-in payload sets and exit' },
  },
  detail: [
    'Mark positions with § in the raw request, or use --auto-mark to mark every',
    'query parameter value. --payload takes:',
    '',
    '  set:quote-probe     a built-in set (--sets lists them)',
    '  list:a,b,c          literal values',
    '  numbers:1-100       a range, optionally numbers:0-1000:10',
    '  brute:abc:3         every string of length 3 over that charset',
    '  case:select         every case permutation',
    '  file:words.txt      one per line, # for comments',
    '',
    'The request count is computed before the first request and refused if it is',
    'over --max-requests. A cluster bomb over two wordlists is a larger number',
    'than people expect.',
  ].join('\n'),
  async run(argv) {
    const parsed = parse(argv, this.specs);

    if (bool(parsed, 'sets')) {
      for (const set of BUILTIN_SETS) {
        out(`${set.id}  (${set.values.length} values)`);
        out(`    ${set.description}`);
        out('');
      }
      return EXIT_OK;
    }

    const id = parsed.positionals[0];
    if (id === undefined) throw new UsageError('awb fuzz needs an exchange id');
    const project = openProject(argv, this.specs);
    const original = project.get(id);
    if (original === undefined) {
      process.stderr.write(`no exchange matching ${id}\n`);
      return EXIT_INPUT;
    }

    const rawPath = str(parsed, 'raw');
    const template =
      rawPath !== undefined
        ? readFileSync(rawPath, 'utf8')
        : bool(parsed, 'auto-mark')
          ? autoMarkQuery(original.request, str(parsed, 'marker') ?? '§')
          : serialiseRequest(original.request);

    const specs = list(parsed, 'payload');
    if (specs.length === 0) {
      throw new UsageError('awb fuzz needs at least one --payload (try --sets)');
    }
    const sources = specs.map((spec) => parsePayloadSpec(spec, (path) => readFileSync(path, 'utf8')));
    const processors = list(parsed, 'process').map(parseProcessor);
    const origin = new URL(original.request.url).origin;

    const options = {
      scope: project.scope(),
      shape: (str(parsed, 'shape') ?? 'sniper') as 'sniper',
      sources,
      processors,
      marker: str(parsed, 'marker') ?? '§',
      concurrency: num(parsed, 'concurrency', 4),
      minIntervalMs: num(parsed, 'min-interval', 0),
      maxRequests: num(parsed, 'max-requests', 10_000),
      grep: list(parsed, 'grep'),
      baseline: !bool(parsed, 'no-baseline'),
      tags: ['fuzz'],
    };

    if (bool(parsed, 'dry-run')) {
      const { planAttack, parseTemplate } = await import('../fuzz/engine.js');
      const parsedTemplate = parseTemplate(template, options.marker);
      const plan = planAttack(options.shape, parsedTemplate.positions.length, sources);
      out(`${plan.shape}: ${plan.positions} position(s), ${plan.requests} request(s)`);
      let shown = 0;
      for (const tuple of plan.tuples()) {
        out(`  ${tuple.map((t) => JSON.stringify(t)).join(' ')}`);
        shown += 1;
        if (shown >= 10) break;
      }
      if (plan.requests > shown) out(`  ... and ${plan.requests - shown} more`);
      return EXIT_OK;
    }

    const summary = await fuzz(template, origin, {
      ...options,
      onResult: (result) => project.append(result.exchange),
      onProgress: (done, total) => {
        if (!bool(parsed, 'quiet') && done % 25 === 0) {
          process.stderr.write(`\r${done}/${total}`);
        }
      },
    });
    if (summary.baseline !== undefined) project.append(summary.baseline);
    if (!bool(parsed, 'quiet')) process.stderr.write('\r');

    log(parsed, `${summary.sent} sent, ${summary.failed} failed, ${summary.elapsedMs}ms`);
    if (summary.stoppedBecause !== undefined) {
      process.stderr.write(`stopped: ${summary.stoppedBecause}\n`);
    }

    out('');
    out('  status   length  count  payloads');
    for (const group of groupResults(summary.results)) {
      const example = group.examples[0];
      const payloads = (example?.payloads ?? []).map((p) => JSON.stringify(p.slice(0, 40))).join(' ');
      // The payload shown is one of the group's, not all of them: a row with a
      // count of 500 and one payload beside it reads as a contradiction
      // otherwise.
      const suffix = group.count > 1 ? ` (+${group.count - 1} more)` : '';
      out(
        `  ${group.material ? '*' : ' '} ${String(group.status ?? 'ERR').padEnd(5)} ` +
          `${String(group.length ?? 0).padStart(7)}  ${String(group.count).padStart(5)}  ${payloads}${suffix}`,
      );
    }
    const interesting = summary.results.filter((r) => r.material || r.reflected.length > 0 || r.matched.length > 0);
    if (interesting.length > 0) {
      out('');
      out('worth a look:');
      for (const result of interesting.slice(0, 20)) {
        const notes = [
          ...(result.reflected.length > 0 ? [`reflected: ${result.reflected.join(', ')}`] : []),
          ...(result.matched.length > 0 ? [`matched: ${result.matched.join(', ')}`] : []),
          ...(result.diff === undefined ? [] : [result.diff.summary]),
        ];
        out(`  ${result.exchange.id}  ${result.payloads.map((p) => JSON.stringify(p)).join(' ')}  ${notes.join('; ')}`);
      }
    }
    return interesting.length > 0 ? EXIT_FINDINGS : EXIT_OK;
  },
};

const scanCommand: Command = {
  name: 'scan',
  summary: 'Run the checks over the capture, or against the target',
  usage: 'awb scan [--active] [--only AWB-P020]... [--fail-on high]',
  specs: {
    ...COMMON,
    active: { type: 'boolean', describe: 'Also run the active checks (needs an authorisation record)' },
    only: { type: 'string', multiple: true, describe: 'Only these check ids', placeholder: 'id' },
    skip: { type: 'string', multiple: true, describe: 'Skip these check ids', placeholder: 'id' },
    target: { type: 'string', describe: 'Exchange id to run the active checks against', placeholder: 'id' },
    'max-requests': { type: 'number', describe: 'Active request budget (default 500)', placeholder: 'n' },
    'min-interval': { type: 'number', describe: 'Milliseconds between active requests', placeholder: 'ms' },
    'fail-on': { type: 'string', describe: 'Exit 1 at or above this severity (default low)', placeholder: 'severity' },
    'oob-domain': { type: 'string', describe: 'Domain for out-of-band canaries', placeholder: 'domain' },
    format: { type: 'string', short: 'f', describe: 'text | json | markdown | sarif', placeholder: 'fmt' },
    output: { type: 'string', short: 'o', describe: 'Write to a file instead of stdout', placeholder: 'file' },
  },
  detail: [
    'Passive checks are a pure function of traffic you already have: nothing is',
    'sent and the target is not touched.',
    '',
    'Active checks send requests. They require an authorisation record in the',
    'project (`awb auth set`), they are scope-checked per request, they are',
    'bounded by --max-requests, and every request is recorded.',
  ].join('\n'),
  async run(argv) {
    const parsed = parse(argv, this.specs);
    const project = openProject(argv, this.specs);
    const exchanges = [...project.exchanges()];
    const findings: Finding[] = [];

    const passive = scanAll(exchanges, { only: list(parsed, 'only'), skip: list(parsed, 'skip') });
    findings.push(...passive);
    log(parsed, `passive: ${passive.length} finding(s) over ${exchanges.length} exchange(s)`);

    if (bool(parsed, 'active')) {
      const authorisation = project.authorisation();
      const status = checkAuthorisation(authorisation);
      if (!status.ok || authorisation === undefined) {
        process.stderr.write(`refusing to run active checks: ${status.reason}\n`);
        return EXIT_REFUSED;
      }

      const targetId = str(parsed, 'target');
      const targets =
        targetId === undefined
          ? exchanges.filter((e) => e.source === 'proxy' || e.source === 'browser')
          : [project.get(targetId)].filter((e): e is NonNullable<typeof e> => e !== undefined);
      if (targets.length === 0) {
        process.stderr.write('no exchange to test. Capture some traffic first, or pass --target.\n');
        return EXIT_INPUT;
      }

      const only = new Set(list(parsed, 'only').map((id) => id.toUpperCase()));
      const skip = new Set(list(parsed, 'skip').map((id) => id.toUpperCase()));
      let checks = ACTIVE_CHECKS.filter((c) => (only.size === 0 || only.has(c.id)) && !skip.has(c.id));

      const oobDomain = str(parsed, 'oob-domain');
      let listener: OobListener | undefined;
      if (oobDomain !== undefined) {
        listener = new OobListener({ domain: oobDomain, host: '0.0.0.0' });
        const ports = await listener.listen();
        log(parsed, `out-of-band listener: http on ${ports.httpPort}, dns on ${ports.dnsPort}`);
      } else {
        const needing = checks.filter((c) => c.needsOob === true);
        if (needing.length > 0) {
          log(
            parsed,
            `skipping ${needing.map((c) => c.id).join(', ')}: they need --oob-domain and a ` +
              'listener reachable from the target',
          );
          checks = checks.filter((c) => c.needsOob !== true);
        }
      }

      const budget = {
        maxRequests: num(parsed, 'max-requests', 500),
        minIntervalMs: num(parsed, 'min-interval', 0),
      };
      const sender = new ActiveSender({
        scope: project.scope(),
        authorisation,
        budget,
        onExchange: (exchange) => project.append(exchange),
      });
      const context: ActiveContext = { sender, ...(listener === undefined ? {} : { oob: listener }) };

      const estimate = estimateCost(checks, 3) * targets.length;
      log(
        parsed,
        `active: ${checks.length} check(s) over ${targets.length} exchange(s), ` +
          `roughly ${estimate} requests, budget ${budget.maxRequests}`,
      );

      try {
        for (const target of targets) {
          const points = injectionPoints(target.request);
          for (const check of checks) {
            const produced = await check.run(target.request, points, context);
            for (const draft of produced) {
              findings.push({
                id: `${draft.check}-${target.id}-${findings.length}`,
                check: draft.check,
                title: draft.title,
                severity: draft.severity,
                confidence: draft.confidence,
                evidence: draft.evidence,
                detail: draft.detail,
                remediation: draft.remediation,
                url: draft.url,
                authorisation: sender.citation,
                at: Date.now(),
              });
            }
          }
        }
      } catch (err) {
        if (err instanceof ScopeViolation || err instanceof NotAuthorised) {
          process.stderr.write(`stopped: ${(err as Error).message}\n`);
          return EXIT_REFUSED;
        }
        if ((err as Error).name === 'BudgetExhausted') {
          log(parsed, (err as Error).message);
        } else {
          throw err;
        }
      } finally {
        await listener?.close();
      }
      log(parsed, `active: ${sender.requestsSpent} request(s) sent`);
    }

    for (const finding of findings) project.appendFinding(finding);

    const engagement = project.authorisation()?.engagement;
    const format = parseFormat(str(parsed, 'format') ?? 'text');
    const text = render(format, project.dedupedFindings(), {
      showSecrets: bool(parsed, 'unsafe-show-secrets'),
      toolVersion: VERSION,
      projectName: project.dir,
      exchanges: new Map(exchanges.map((e) => [e.id, e])),
      ...(engagement === undefined ? {} : { authorisation: engagement }),
    });

    const output = str(parsed, 'output');
    if (output === undefined) out(text);
    else {
      writeFileSync(output, text);
      log(parsed, `wrote ${output}`);
    }

    const floor = parseSeverity(str(parsed, 'fail-on') ?? 'low');
    const worst = project.dedupedFindings().some((f) => severityRank(f.severity) <= severityRank(floor));
    return worst ? EXIT_FINDINGS : EXIT_OK;
  },
};

const reportCommand: Command = {
  name: 'report',
  summary: 'Render the findings already in the project',
  usage: 'awb report [--format sarif] [--min-severity medium] [-o out.sarif]',
  specs: {
    ...COMMON,
    format: { type: 'string', short: 'f', describe: 'text | json | markdown | sarif', placeholder: 'fmt' },
    'min-severity': { type: 'string', describe: 'Lowest severity to include', placeholder: 'severity' },
    output: { type: 'string', short: 'o', describe: 'Write to a file', placeholder: 'file' },
    'fail-on': { type: 'string', describe: 'Exit 1 at or above this severity', placeholder: 'severity' },
  },
  async run(argv) {
    const parsed = parse(argv, this.specs);
    const project = openProject(argv, this.specs);
    const findings = project.dedupedFindings();
    const minSeverity = str(parsed, 'min-severity');
    const engagement = project.authorisation()?.engagement;

    const text = render(parseFormat(str(parsed, 'format') ?? 'text'), findings, {
      showSecrets: bool(parsed, 'unsafe-show-secrets'),
      toolVersion: VERSION,
      projectName: project.dir,
      exchanges: new Map([...project.exchanges()].map((e) => [e.id, e])),
      ...(minSeverity === undefined ? {} : { minSeverity: parseSeverity(minSeverity) }),
      ...(engagement === undefined ? {} : { authorisation: engagement }),
    });

    const output = str(parsed, 'output');
    if (output === undefined) out(text);
    else {
      writeFileSync(output, text);
      log(parsed, `wrote ${output}`);
    }

    const failOn = str(parsed, 'fail-on');
    if (failOn === undefined) return EXIT_OK;
    const floor = parseSeverity(failOn);
    return findings.some((f) => severityRank(f.severity) <= severityRank(floor)) ? EXIT_FINDINGS : EXIT_OK;
  },
};

const browseCommand: Command = {
  name: 'browse',
  summary: 'Drive a real browser through the proxy',
  usage: 'awb browse <url> [--max-pages 10] [--headful]',
  specs: {
    ...COMMON,
    'max-pages': { type: 'number', describe: 'Pages to visit (default 10)', placeholder: 'n' },
    headful: { type: 'boolean', describe: 'Show the browser window' },
    'proxy-port': { type: 'number', describe: 'Use an already-running proxy on this port', placeholder: 'n' },
    'browser-path': { type: 'string', describe: 'A Chrome or Chromium binary to use', placeholder: 'path' },
    settle: { type: 'number', describe: 'Milliseconds to wait after each navigation', placeholder: 'ms' },
    'login-script': { type: 'string', describe: 'JavaScript to run on the first page', placeholder: 'file' },
  },
  detail: [
    'Starts a proxy, launches Chromium pointed at it, and walks the application.',
    'Everything the browser requests -- including what a bundle fetches after the',
    'page loads -- lands in the project through the proxy.',
    '',
    'Playwright is an optional dependency. If its own Chromium is not downloaded,',
    'an installed Chrome is used instead.',
  ].join('\n'),
  async run(argv) {
    const parsed = parse(argv, this.specs);
    const entry = parsed.positionals[0];
    if (entry === undefined) throw new UsageError('awb browse needs a URL to start from');

    const dir = projectDir(argv, this.specs);
    const project = Project.openOrCreate(dir);
    let scope = project.scope();

    if (scope.include.length === 0) {
      // A browse of one URL with no scope configured is almost certainly a
      // first run; derive the obvious scope and say so rather than refusing.
      const origin = new URL(entry).origin;
      scope = parseScopeConfig({ include: [origin] });
      project.setScope(scope);
      log(parsed, `scope was empty; set to ${origin}`);
    }

    const { browse } = await import('../browser/drive.js');
    const ca = ensureCa(join(dir, 'ca'));
    const existingPort = parsed.options['proxy-port'];
    let proxy: Proxy | undefined;
    let port: number;

    if (existingPort === undefined) {
      proxy = new Proxy({
        port: 0,
        scope,
        ca,
        onExchange: (exchange) => project.append(exchange),
        onFrame: (frame) => project.appendFrame(frame),
      });
      port = await proxy.listen();
      log(parsed, `proxy on 127.0.0.1:${port}`);
    } else {
      port = num(parsed, 'proxy-port', 8080);
    }

    const loginScriptPath = str(parsed, 'login-script');
    try {
      const result = await browse({
        scope,
        proxy: { host: '127.0.0.1', port },
        entries: [entry],
        maxPages: num(parsed, 'max-pages', 10),
        headless: !bool(parsed, 'headful'),
        settleMs: num(parsed, 'settle', 1200),
        ...(str(parsed, 'browser-path') === undefined
          ? {}
          : { executablePath: str(parsed, 'browser-path') as string }),
        ...(loginScriptPath === undefined
          ? {}
          : { loginScript: readFileSync(loginScriptPath, 'utf8') }),
        onLog: (message) => log(parsed, message),
      });

      out(`visited ${result.visited.length} page(s)`);
      for (const page of result.pages) {
        out(`  ${page.url}`);
        if (page.title.length > 0) out(`      title: ${page.title}`);
        if (page.forms.length > 0) {
          for (const form of page.forms) {
            out(`      form: ${form.method} ${form.action} (${form.fields.map((f) => f.name).filter((n) => n.length > 0).join(', ')})`);
          }
        }
        for (const sink of page.domSinks) {
          out(`      DOM sink: ${sink.source} -> ${sink.sink} in ${sink.script}`);
        }
        if (page.storageKeys.length > 0) out(`      storage keys: ${page.storageKeys.join(', ')}`);
        for (const error of page.consoleErrors.slice(0, 3)) out(`      console error: ${error.slice(0, 120)}`);
      }
      for (const skip of result.skipped) out(`  skipped ${skip.url}: ${skip.reason}`);
      out('');
      out(`${project.count()} exchange(s) in ${dir}`);
      return EXIT_OK;
    } finally {
      await proxy?.close();
    }
  },
};

const oobCommand: Command = {
  name: 'oob',
  summary: 'Run the out-of-band interaction listener',
  usage: 'awb oob serve --domain oob.example.com [--answer 203.0.113.9]',
  specs: {
    ...COMMON,
    domain: { type: 'string', describe: 'Domain whose subdomains are canary tokens', placeholder: 'domain' },
    answer: { type: 'string', describe: 'Address to answer A queries with', placeholder: 'addr' },
    'http-port': { type: 'number', describe: 'HTTP port (default 8081)', placeholder: 'n' },
    'dns-port': { type: 'number', describe: 'DNS port (default 5353; 53 needs privilege)', placeholder: 'n' },
    host: { type: 'string', describe: 'Listen address (default 0.0.0.0)', placeholder: 'addr' },
    'record-unknown': { type: 'boolean', describe: 'Also record tokens this process did not mint' },
  },
  detail: [
    'For the bugs with no response to look at: blind server-side request forgery,',
    'XXE, out-of-band injection. Run this where the target can reach it, point a',
    'wildcard DNS record at it, and the checks that need it will mint canaries.',
    '',
    'Interactions whose token this process did not mint are dropped, which is what',
    'stops internet background noise becoming findings.',
  ].join('\n'),
  async run(argv) {
    const parsed = parse(argv, this.specs);
    if ((parsed.positionals[0] ?? 'serve') !== 'serve') {
      throw new UsageError(`unknown oob action ${JSON.stringify(parsed.positionals[0])}`);
    }
    const domain = str(parsed, 'domain');
    if (domain === undefined) throw new UsageError('awb oob serve needs --domain');

    const answer = str(parsed, 'answer');
    const listener = new OobListener({
      domain,
      ...(answer === undefined ? {} : { answerAddress: answer }),
      httpPort: num(parsed, 'http-port', 8081),
      dnsPort: num(parsed, 'dns-port', 5353),
      host: str(parsed, 'host') ?? '0.0.0.0',
      ...(bool(parsed, 'record-unknown') ? { recordUnknown: true } : {}),
      onInteraction: (interaction) => {
        out(
          `${new Date(interaction.at).toISOString()}  ${interaction.kind.padEnd(4)} ` +
            `${interaction.detail.padEnd(6)} ${interaction.target}  from ${interaction.remoteAddress}`,
        );
      },
    });

    const ports = await listener.listen();
    log(parsed, `listening: http ${ports.httpPort}, dns ${ports.dnsPort}, domain ${domain}`);
    log(parsed, 'point a wildcard DNS record for that domain at this host');
    log(parsed, 'press ctrl-c to stop');

    await new Promise<void>((resolveWait) => {
      const stop = (): void => {
        log(parsed, `${listener.all().length} interaction(s), ${listener.unknownDropped} dropped as unknown`);
        void listener.close().then(resolveWait);
      };
      process.once('SIGINT', stop);
      process.once('SIGTERM', stop);
    });
    return EXIT_OK;
  },
};

const aiCommand: Command = {
  name: 'ai',
  summary: 'Use Claude to triage findings or summarise a capture',
  usage: 'awb ai <triage|summarise> [--model ...] [--dry-run]',
  specs: {
    ...COMMON,
    model: { type: 'string', describe: `Model id (default ${MODELS.default})`, placeholder: 'id' },
    'dry-run': { type: 'boolean', describe: 'Print the exact request and send nothing' },
    'api-key': { type: 'string', describe: 'Overrides ANTHROPIC_API_KEY', placeholder: 'key' },
    'unsafe-send-secrets': { type: 'boolean', describe: 'Send credentials to the API unredacted' },
    'min-severity': { type: 'string', describe: 'Only triage findings at or above this', placeholder: 'severity' },
    limit: { type: 'number', describe: 'Most findings to triage (default 10)', placeholder: 'n' },
  },
  detail: [
    'Everything sent is redacted first: credentials in headers, bodies and URLs',
    'are replaced with length-preserving markers before the prompt is built.',
    '--dry-run prints the exact bytes that would be sent.',
    '',
    'Captured content is passed as fenced data and the answer is constrained to a',
    'schema, because a response body is attacker-controlled and the obvious move',
    'against a tool like this is to put instructions in one.',
    '',
    'The model proposes; it does not act. Nothing it returns is sent anywhere.',
  ].join('\n'),
  async run(argv) {
    const parsed = parse(argv, this.specs);
    const action = parsed.positionals[0];
    if (action === undefined) throw new UsageError('awb ai needs an action: triage or summarise');

    const project = openProject(argv, this.specs);
    const apiKey = str(parsed, 'api-key');
    const client = new AiClient({
      ...(apiKey === undefined ? {} : { apiKey }),
      ...(bool(parsed, 'dry-run') ? { dryRun: true, onDryRun: (payload) => out(payload) } : {}),
    });
    const model = str(parsed, 'model') ?? MODELS.default;
    const render = {
      ...(bool(parsed, 'unsafe-send-secrets') ? { unsafeSendSecrets: true } : {}),
    };

    if (action === 'summarise') {
      const exchanges = [...project.exchanges()];
      if (exchanges.length === 0) {
        process.stderr.write('the project has no traffic to summarise\n');
        return EXIT_INPUT;
      }
      const response = await client.ask(
        buildSummaryRequest(exchanges, { model, render }),
        validateSummary,
      );
      out('observations:');
      for (const note of response.value.surfaceNotes) out(`  - ${note}`);
      out('');
      out('worth testing:');
      for (const target of response.value.worthTesting) out(`  ${target.target}\n      ${target.why}`);
      if (response.value.promptInjectionObserved) {
        out('');
        out('NOTE: the model reports the capture contained text attempting to steer this');
        out('analysis. That is itself worth looking at.');
      }
      reportUsage(parsed, client, response.model);
      return EXIT_OK;
    }

    if (action === 'triage') {
      const minSeverity = str(parsed, 'min-severity');
      const floor = minSeverity === undefined ? 'info' : parseSeverity(minSeverity);
      const findings = project
        .dedupedFindings()
        .filter((f) => severityRank(f.severity) <= severityRank(floor))
        .slice(0, num(parsed, 'limit', 10));
      if (findings.length === 0) {
        process.stderr.write('no findings to triage. Run `awb scan` first.\n');
        return EXIT_INPUT;
      }

      const byId = new Map([...project.exchanges()].map((e) => [e.id, e]));
      for (const finding of findings) {
        const evidence = finding.evidence
          .map((id) => byId.get(id))
          .filter((e): e is NonNullable<typeof e> => e !== undefined);
        const response = await triage(client, finding, evidence, { model, render });
        out(`${finding.check}  ${finding.title}`);
        out(`  model verdict: ${response.value.verdict}`);
        out(`  ${response.value.reasoning}`);
        if (response.value.nextStep !== undefined) {
          out(`  next: awb replay ${finding.evidence[0] ?? '<id>'} --set ${response.value.nextStep}`);
        }
        if (response.value.promptInjectionObserved) {
          out('  NOTE: the evidence contained text attempting to steer this analysis');
        }
        out('');
      }
      reportUsage(parsed, client, model);
      return EXIT_OK;
    }

    throw new UsageError(`unknown ai action ${JSON.stringify(action)}`);
  },
};

function reportUsage(parsed: ReturnType<typeof parse>, client: AiClient, model: string): void {
  const usd = estimateCostUsd(model, client.totalUsage);
  log(
    parsed,
    `${client.calls} call(s), ${client.totalUsage.inputTokens} in / ` +
      `${client.totalUsage.outputTokens} out tokens` +
      (usd === undefined ? '' : `, about $${usd.toFixed(4)} at published prices`),
  );
}

const checksCommand: Command = {
  name: 'checks',
  summary: 'List the checks and what each one is for',
  usage: 'awb checks [--active] [--passive]',
  specs: {
    ...COMMON,
    active: { type: 'boolean', describe: 'Only the active checks' },
    passive: { type: 'boolean', describe: 'Only the passive checks' },
  },
  async run(argv) {
    const parsed = parse(argv, this.specs);
    const wantActive = bool(parsed, 'active') || !bool(parsed, 'passive');
    const wantPassive = bool(parsed, 'passive') || !bool(parsed, 'active');

    if (wantPassive) {
      out('passive -- a pure function of traffic you already have; nothing is sent');
      out('');
      for (const check of PASSIVE_CHECKS) {
        out(`  ${check.id}  ${check.title}`);
        out(`            ${check.description}`);
        out('');
      }
    }
    if (wantActive) {
      out('active -- sends requests; needs an authorisation record');
      out('');
      for (const check of ACTIVE_CHECKS) {
        out(`  ${check.id}  ${check.title}${check.needsOob === true ? '  [needs --oob-domain]' : ''}`);
        out(`            ${check.description}`);
        out(`            about ${check.costPerPoint} request(s) per injection point`);
        out('');
      }
    }
    return EXIT_OK;
  },
};

const doctorCommand: Command = {
  name: 'doctor',
  summary: 'Check the environment and the project',
  usage: 'awb doctor',
  specs: COMMON,
  async run(argv) {
    // Parsed for validation: an unknown option on `doctor` should still be an
    // error rather than being ignored by the one command meant to find errors.
    parse(argv, this.specs);
    let problems = 0;
    const ok = (label: string, detail: string): void => out(`  ok    ${label.padEnd(22)} ${detail}`);
    const bad = (label: string, detail: string): void => {
      problems += 1;
      out(`  FAIL  ${label.padEnd(22)} ${detail}`);
    };

    out(`appsec-workbench ${VERSION}`);
    out('');
    ok('node', process.version);

    try {
      ok('openssl', opensslVersion());
    } catch (err) {
      bad('openssl', (err as Error).message.split('\n')[0] ?? 'not found');
    }

    try {
      const { loadPlaywright, findInstalledChrome } = await import('../browser/drive.js');
      await loadPlaywright();
      const chrome = findInstalledChrome();
      ok('playwright', chrome === undefined ? 'installed' : `installed; Chrome at ${chrome}`);
    } catch {
      out('  --    playwright             not installed; only `awb browse` needs it');
    }

    out(
      process.env['ANTHROPIC_API_KEY'] === undefined
        ? '  --    ANTHROPIC_API_KEY      not set; only `awb ai` needs it'
        : '  ok    ANTHROPIC_API_KEY      set',
    );

    const dir = projectDir(argv, this.specs);
    if (!existsSync(join(dir, 'meta.json'))) {
      out(`  --    project                none at ${dir}; \`awb init\` creates one`);
      out('');
      return problems > 0 ? EXIT_INPUT : EXIT_OK;
    }

    const project = Project.open(dir);
    ok('project', `${dir} (${project.count()} exchanges, ${project.blobCount()} blobs)`);

    const scope = project.scope();
    if (scope.include.length === 0) bad('scope', 'empty, and scope is deny by default');
    else ok('scope', scope.include.map(formatRule).join(', '));

    const problemsInScope = lintScope(scope);
    if (problemsInScope.length > 0) {
      for (const problem of problemsInScope) bad('scope lint', problem.detail);
    }

    const status = checkAuthorisation(project.authorisation());
    if (status.ok) ok('authorisation', status.reason);
    else out(`  --    authorisation          ${status.reason.split('.')[0]}`);

    const caDir = join(dir, 'ca');
    if (caExists(caDir)) ok('CA', `${caFingerprint(caDir)} valid to ${caValidTo(caDir)}`);
    else out('  --    CA                     not created yet; `awb ca show` creates it');

    out('');
    return problems > 0 ? EXIT_INPUT : EXIT_OK;
  },
};

// ---------------------------------------------------------------------------

const COMMANDS: readonly Command[] = [
  initCommand,
  doctorCommand,
  scopeCommand,
  authCommand,
  caCommand,
  proxyCommand,
  browseCommand,
  lsCommand,
  showCommand,
  replayCommand,
  diffCommand,
  fuzzCommand,
  scanCommand,
  oobCommand,
  aiCommand,
  reportCommand,
  checksCommand,
];

function helpText(): string {
  const width = Math.max(...COMMANDS.map((c) => c.name.length));
  return [
    `appsec-workbench ${VERSION} -- a CLI web application security workbench`,
    '',
    'usage: awb <command> [options]',
    '',
    'commands:',
    ...COMMANDS.map((c) => `  ${c.name.padEnd(width + 2)}${c.summary}`),
    '',
    '  awb <command> --help  for that command',
    '',
    'Authorised testing only. Scope is deny by default, and the active checks need',
    'an authorisation record in the project before they will send anything.',
    '',
    'exit codes: 0 clean, 1 findings, 2 usage, 3 input, 4 refused',
  ].join('\n');
}

function commandHelp(command: Command): string {
  return [
    `awb ${command.name} -- ${command.summary}`,
    '',
    `usage: ${command.usage}`,
    ...(command.detail === undefined ? [] : ['', command.detail]),
    '',
    'options:',
    renderOptions(command.specs),
  ].join('\n');
}

export async function main(argv: readonly string[]): Promise<number> {
  const [first, ...rest] = argv;

  if (first === undefined || first === '--help' || first === '-h' || first === 'help') {
    out(helpText());
    return first === undefined ? EXIT_USAGE : EXIT_OK;
  }
  if (first === '--version' || first === '-V' || first === 'version') {
    out(VERSION);
    return EXIT_OK;
  }

  const command = COMMANDS.find((c) => c.name === first);
  if (command === undefined) {
    process.stderr.write(`unknown command ${JSON.stringify(first)}\n\n${helpText()}\n`);
    return EXIT_USAGE;
  }
  if (rest.includes('--help') || rest.includes('-h')) {
    out(commandHelp(command));
    return EXIT_OK;
  }

  try {
    return await command.run(rest);
  } catch (err) {
    if (err instanceof UsageError) {
      process.stderr.write(`${err.message}\n\n${commandHelp(command)}\n`);
      return EXIT_USAGE;
    }
    if (err instanceof ScopeViolation || err instanceof NotAuthorised) {
      process.stderr.write(`${err.message}\n`);
      return EXIT_REFUSED;
    }
    if ((err as Error).name === 'BudgetExhausted') {
      process.stderr.write(`${(err as Error).message}\n`);
      return EXIT_REFUSED;
    }
    const error = err as NodeJS.ErrnoException;
    if (error.code === 'ENOENT' || error.code === 'EACCES') {
      process.stderr.write(`${error.message}\n`);
      return EXIT_INPUT;
    }
    process.stderr.write(`${(err as Error).message}\n`);
    return EXIT_INPUT;
  }
}

/** Only run when executed, so the suite can import and call main directly. */
const invokedDirectly =
  process.argv[1] !== undefined &&
  (process.argv[1].endsWith('main.js') || process.argv[1].endsWith('awb'));

if (invokedDirectly) {
  main(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err: unknown) => {
      process.stderr.write(`unexpected: ${(err as Error).stack ?? String(err)}\n`);
      process.exitCode = EXIT_INPUT;
    });
}

export { EXIT_FINDINGS, EXIT_INPUT, EXIT_OK, EXIT_REFUSED, EXIT_USAGE, COMMANDS, helpText };
