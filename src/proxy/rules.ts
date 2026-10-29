/**
 * Match-and-replace, and the session rules that make long tests possible.
 *
 * Burp calls these two separate features. They are the same mechanism: a
 * predicate over a message, and an edit applied when it matches. Keeping them
 * one mechanism means a session rule can do anything a replace rule can --
 * rewrite a body, drop a header -- rather than only the three things a
 * dedicated session feature thought of.
 *
 * Every rule is declarative so it can live in the project file and be
 * reviewed. Nothing here evaluates arbitrary code: a rule that could run a
 * callback would be more flexible and would also mean a project file is
 * executable, which is not a property you want in a file you were sent.
 */

import {
  add as addHeader,
  get as getHeader,
  remove as removeHeader,
  set as setHeader,
} from '../core/headers.js';
import type { HttpRequest, HttpResponse } from '../core/message.js';
import { contentType } from '../core/message.js';

export interface RuleMatch {
  /** Host pattern, `*` or `*.example.com`. Defaults to any. */
  readonly host?: string;
  /** Regular expression against the path and query. */
  readonly path?: string;
  /** Methods this applies to. Defaults to any. */
  readonly methods?: readonly string[];
  /** Response status codes this applies to. Response rules only. */
  readonly status?: readonly number[];
  /** Media type prefix, e.g. `application/json`. */
  readonly contentType?: string;
  /** Only when this regex matches the body. */
  readonly bodyContains?: string;
}

export type RuleAction =
  | { readonly kind: 'set-header'; readonly name: string; readonly value: string }
  | { readonly kind: 'add-header'; readonly name: string; readonly value: string }
  | { readonly kind: 'remove-header'; readonly name: string }
  | {
      readonly kind: 'replace-header';
      readonly name: string;
      readonly pattern: string;
      readonly replacement: string;
    }
  | {
      readonly kind: 'replace-body';
      readonly pattern: string;
      readonly replacement: string;
      /** Replace every occurrence rather than the first. Default true. */
      readonly all?: boolean;
    }
  | { readonly kind: 'set-body'; readonly value: string }
  | { readonly kind: 'set-method'; readonly value: string }
  | { readonly kind: 'rewrite-path'; readonly pattern: string; readonly replacement: string }
  | { readonly kind: 'set-status'; readonly value: number }
  /** Stop later rules from running. Useful for an allow-first rule. */
  | { readonly kind: 'stop' };

export interface Rule {
  readonly id: string;
  readonly on: 'request' | 'response';
  readonly enabled?: boolean;
  readonly match?: RuleMatch;
  readonly actions: readonly RuleAction[];
  readonly note?: string;
}

export interface RuleApplication {
  readonly ruleId: string;
  readonly action: RuleAction['kind'];
  readonly detail: string;
}

/**
 * A value referencing an environment variable rather than a literal.
 *
 * `{{env:BEARER}}` in a rule value is substituted at apply time. It exists so
 * a project file committed to a repository can carry the *shape* of the
 * session handling without carrying the token, which is the thing that
 * otherwise gets committed by accident.
 */
export function expand(value: string, env: NodeJS.ProcessEnv = process.env): string {
  return value.replace(/\{\{env:([A-Za-z_][A-Za-z0-9_]*)\}\}/g, (_whole, name: string) => {
    const found = env[name];
    if (found === undefined) {
      throw new Error(
        `rule references {{env:${name}}} but that variable is not set. ` +
          'Export it, or edit the rule.',
      );
    }
    return found;
  });
}

function hostMatches(pattern: string, host: string): boolean {
  if (pattern === '*') return true;
  const p = pattern.toLowerCase();
  const h = host.toLowerCase();
  if (!p.startsWith('*.')) return p === h;
  const suffix = p.slice(1);
  return h.endsWith(suffix) && h.length > suffix.length;
}

function matchesRequest(match: RuleMatch | undefined, request: HttpRequest): boolean {
  if (match === undefined) return true;
  let url: URL;
  try {
    url = new URL(request.url);
  } catch {
    return false;
  }
  if (match.host !== undefined && !hostMatches(match.host, url.hostname)) return false;
  if (match.path !== undefined && !new RegExp(match.path).test(url.pathname + url.search)) {
    return false;
  }
  if (match.methods !== undefined && !match.methods.some((m) => m.toUpperCase() === request.method.toUpperCase())) {
    return false;
  }
  if (match.contentType !== undefined) {
    const ct = contentType(request.headers);
    if (ct === undefined || !ct.startsWith(match.contentType.toLowerCase())) return false;
  }
  if (match.bodyContains !== undefined && !new RegExp(match.bodyContains).test(request.body.toString('utf8'))) {
    return false;
  }
  return true;
}

function matchesResponse(
  match: RuleMatch | undefined,
  request: HttpRequest,
  response: HttpResponse,
): boolean {
  if (match === undefined) return true;
  if (match.status !== undefined && !match.status.includes(response.status)) return false;
  if (match.contentType !== undefined) {
    const ct = contentType(response.headers);
    if (ct === undefined || !ct.startsWith(match.contentType.toLowerCase())) return false;
  }
  if (match.bodyContains !== undefined && !new RegExp(match.bodyContains).test(response.body.toString('utf8'))) {
    return false;
  }
  // Host, path and method still refer to the request that produced it.
  const { contentType: _ct, bodyContains: _bc, status: _st, ...rest } = match;
  return matchesRequest(rest, request);
}

export interface ApplyResult<T> {
  readonly message: T;
  readonly applied: readonly RuleApplication[];
}

export function applyRequestRules(
  rules: readonly Rule[],
  request: HttpRequest,
  env?: NodeJS.ProcessEnv,
): ApplyResult<HttpRequest> {
  let current = request;
  const applied: RuleApplication[] = [];

  for (const rule of rules) {
    if (rule.on !== 'request' || rule.enabled === false) continue;
    if (!matchesRequest(rule.match, current)) continue;
    let stop = false;
    for (const action of rule.actions) {
      if (action.kind === 'stop') {
        applied.push({ ruleId: rule.id, action: 'stop', detail: 'later rules skipped' });
        stop = true;
        break;
      }
      const next = applyToRequest(current, action, env);
      if (next === undefined) continue;
      applied.push({ ruleId: rule.id, action: action.kind, detail: describe(action) });
      current = next;
    }
    if (stop) break;
  }

  return { message: current, applied };
}

function applyToRequest(
  request: HttpRequest,
  action: RuleAction,
  env?: NodeJS.ProcessEnv,
): HttpRequest | undefined {
  switch (action.kind) {
    case 'set-header':
      return { ...request, headers: setHeader(request.headers, action.name, expand(action.value, env)) };
    case 'add-header':
      return { ...request, headers: addHeader(request.headers, action.name, expand(action.value, env)) };
    case 'remove-header':
      if (getHeader(request.headers, action.name) === undefined) return undefined;
      return { ...request, headers: removeHeader(request.headers, action.name) };
    case 'replace-header': {
      const current = getHeader(request.headers, action.name);
      if (current === undefined) return undefined;
      const next = current.replace(
        new RegExp(action.pattern, 'g'),
        expand(action.replacement, env),
      );
      if (next === current) return undefined;
      return { ...request, headers: setHeader(request.headers, action.name, next) };
    }
    case 'replace-body': {
      const text = request.body.toString('utf8');
      const next = text.replace(
        new RegExp(action.pattern, action.all === false ? '' : 'g'),
        expand(action.replacement, env),
      );
      if (next === text) return undefined;
      return withBody(request, Buffer.from(next, 'utf8'));
    }
    case 'set-body':
      return withBody(request, Buffer.from(expand(action.value, env), 'utf8'));
    case 'set-method':
      return { ...request, method: action.value.toUpperCase() };
    case 'rewrite-path': {
      let url: URL;
      try {
        url = new URL(request.url);
      } catch {
        return undefined;
      }
      const target = url.pathname + url.search;
      const next = target.replace(new RegExp(action.pattern), expand(action.replacement, env));
      if (next === target) return undefined;
      const rebuilt = new URL(next, url.origin);
      return { ...request, url: rebuilt.toString() };
    }
    case 'set-status':
    case 'stop':
      return undefined;
    default: {
      const exhaustive: never = action;
      return exhaustive;
    }
  }
}

/**
 * Rewrite the body and fix Content-Length to match -- but only if it was
 * already present and already correct.
 *
 * A rule that rewrote a body and left a stale Content-Length would break the
 * request in a way that looks like a server bug. A rule applied to a request
 * whose Content-Length was *deliberately* wrong must not helpfully correct
 * it, because that is the test.
 */
function withBody(request: HttpRequest, body: Buffer): HttpRequest {
  const declared = getHeader(request.headers, 'content-length');
  const headers =
    declared !== undefined && Number(declared) === request.body.length
      ? setHeader(request.headers, 'content-length', String(body.length))
      : request.headers;
  return { ...request, headers, body };
}

export function applyResponseRules(
  rules: readonly Rule[],
  request: HttpRequest,
  response: HttpResponse,
  env?: NodeJS.ProcessEnv,
): ApplyResult<HttpResponse> {
  let current = response;
  const applied: RuleApplication[] = [];

  for (const rule of rules) {
    if (rule.on !== 'response' || rule.enabled === false) continue;
    if (!matchesResponse(rule.match, request, current)) continue;
    let stop = false;
    for (const action of rule.actions) {
      if (action.kind === 'stop') {
        applied.push({ ruleId: rule.id, action: 'stop', detail: 'later rules skipped' });
        stop = true;
        break;
      }
      const next = applyToResponse(current, action, env);
      if (next === undefined) continue;
      applied.push({ ruleId: rule.id, action: action.kind, detail: describe(action) });
      current = next;
    }
    if (stop) break;
  }

  return { message: current, applied };
}

function applyToResponse(
  response: HttpResponse,
  action: RuleAction,
  env?: NodeJS.ProcessEnv,
): HttpResponse | undefined {
  switch (action.kind) {
    case 'set-header':
      return { ...response, headers: setHeader(response.headers, action.name, expand(action.value, env)) };
    case 'add-header':
      return { ...response, headers: addHeader(response.headers, action.name, expand(action.value, env)) };
    case 'remove-header':
      if (getHeader(response.headers, action.name) === undefined) return undefined;
      return { ...response, headers: removeHeader(response.headers, action.name) };
    case 'replace-header': {
      const current = getHeader(response.headers, action.name);
      if (current === undefined) return undefined;
      const next = current.replace(new RegExp(action.pattern, 'g'), expand(action.replacement, env));
      if (next === current) return undefined;
      return { ...response, headers: setHeader(response.headers, action.name, next) };
    }
    case 'replace-body': {
      const text = response.body.toString('utf8');
      const next = text.replace(
        new RegExp(action.pattern, action.all === false ? '' : 'g'),
        expand(action.replacement, env),
      );
      if (next === text) return undefined;
      return responseWithBody(response, Buffer.from(next, 'utf8'));
    }
    case 'set-body':
      return responseWithBody(response, Buffer.from(expand(action.value, env), 'utf8'));
    case 'set-status':
      return { ...response, status: action.value };
    case 'set-method':
    case 'rewrite-path':
    case 'stop':
      return undefined;
    default: {
      const exhaustive: never = action;
      return exhaustive;
    }
  }
}

function responseWithBody(response: HttpResponse, body: Buffer): HttpResponse {
  const declared = getHeader(response.headers, 'content-length');
  const headers =
    declared !== undefined
      ? setHeader(response.headers, 'content-length', String(body.length))
      : response.headers;
  return { ...response, headers, body };
}

function describe(action: RuleAction): string {
  switch (action.kind) {
    case 'set-header':
    case 'add-header':
      return `${action.name}`;
    case 'remove-header':
      return action.name;
    case 'replace-header':
      return `${action.name} ~ /${action.pattern}/`;
    case 'replace-body':
      return `/${action.pattern}/`;
    case 'set-body':
      return `${action.value.length} bytes`;
    case 'set-method':
      return action.value;
    case 'rewrite-path':
      return `/${action.pattern}/ -> ${action.replacement}`;
    case 'set-status':
      return String(action.value);
    case 'stop':
      return '';
    default:
      return '';
  }
}

/** Validate a rule set before a proxy starts, so a typo fails at startup. */
export function validateRules(rules: readonly Rule[]): string[] {
  const problems: string[] = [];
  const ids = new Set<string>();

  for (const rule of rules) {
    if (rule.id.trim().length === 0) problems.push('a rule has an empty id');
    if (ids.has(rule.id)) problems.push(`duplicate rule id ${JSON.stringify(rule.id)}`);
    ids.add(rule.id);
    if (rule.on !== 'request' && rule.on !== 'response') {
      problems.push(`rule ${rule.id}: "on" must be "request" or "response"`);
    }
    if (rule.actions.length === 0) problems.push(`rule ${rule.id} has no actions`);

    for (const pattern of [rule.match?.path, rule.match?.bodyContains]) {
      if (pattern === undefined) continue;
      try {
        new RegExp(pattern);
      } catch (err) {
        problems.push(`rule ${rule.id}: ${JSON.stringify(pattern)} is not a valid regex: ${(err as Error).message}`);
      }
    }

    for (const action of rule.actions) {
      if ('pattern' in action) {
        try {
          new RegExp(action.pattern);
        } catch (err) {
          problems.push(
            `rule ${rule.id}: ${JSON.stringify(action.pattern)} is not a valid regex: ${(err as Error).message}`,
          );
        }
      }
      if (rule.on === 'request' && action.kind === 'set-status') {
        problems.push(`rule ${rule.id}: set-status has no meaning on a request`);
      }
      if (rule.on === 'response' && (action.kind === 'set-method' || action.kind === 'rewrite-path')) {
        problems.push(`rule ${rule.id}: ${action.kind} has no meaning on a response`);
      }
    }
  }

  return problems;
}
