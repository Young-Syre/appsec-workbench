/**
 * Replay: take a captured request, change one thing, send it again.
 *
 * The thing that makes this useful rather than a curl wrapper is that the
 * mutations are structural. `query:id=2` edits one parameter and leaves the
 * rest of a forty-parameter query alone; `json:user.role=admin` edits one
 * field of a nested body and re-serialises it; `-header:Cookie` removes a
 * header without disturbing the order of the others. Doing any of that by
 * hand-editing a request line is where mistakes come from, and a mistake in
 * the request means hours spent explaining a response that was never
 * interesting.
 *
 * Every mutation is recorded on the resulting exchange, so a finding can say
 * what was changed rather than only what came back.
 */

import {
  add as addHeader,
  get as getHeader,
  remove as removeHeader,
  set as setHeader,
} from '../core/headers.js';
import {
  type Exchange,
  type HttpRequest,
  contentType,
  exchangeId,
  parseRawRequest,
  serialiseRequest,
} from '../core/message.js';
import { type ScopeConfig, assertAllowed } from '../core/scope.js';
import { type SendOptions, send } from '../net/send.js';

export type Mutation =
  | { readonly kind: 'set-header'; readonly name: string; readonly value: string }
  | { readonly kind: 'add-header'; readonly name: string; readonly value: string }
  | { readonly kind: 'remove-header'; readonly name: string }
  | { readonly kind: 'set-method'; readonly value: string }
  | { readonly kind: 'set-path'; readonly value: string }
  | { readonly kind: 'set-query'; readonly name: string; readonly value: string }
  | { readonly kind: 'remove-query'; readonly name: string }
  | { readonly kind: 'set-form'; readonly name: string; readonly value: string }
  | { readonly kind: 'set-json'; readonly pointer: string; readonly value: string }
  | { readonly kind: 'set-body'; readonly value: string }
  | { readonly kind: 'set-cookie'; readonly name: string; readonly value: string }
  | { readonly kind: 'remove-cookie'; readonly name: string };

/**
 * Parse the shorthand the CLI accepts.
 *
 *   header:X-Forwarded-For=127.0.0.1
 *   +header:X-Trace=1            (add alongside an existing one)
 *   -header:Cookie
 *   method=POST
 *   path=/admin/users
 *   query:id=2
 *   -query:page
 *   form:role=admin
 *   json:user.role=admin
 *   json:items.0.qty=-1
 *   cookie:session=other
 *   -cookie:remember_me
 *   body=@payload.txt            (resolved by the caller, not here)
 */
export function parseMutation(text: string): Mutation {
  const eq = text.indexOf('=');
  const lhs = eq < 0 ? text : text.slice(0, eq);
  const rhs = eq < 0 ? undefined : text.slice(eq + 1);

  const removal = lhs.startsWith('-');
  const addition = lhs.startsWith('+');
  const bare = removal || addition ? lhs.slice(1) : lhs;
  const colon = bare.indexOf(':');
  const kind = colon < 0 ? bare : bare.slice(0, colon);
  const name = colon < 0 ? undefined : bare.slice(colon + 1);

  const needValue = (): string => {
    if (rhs === undefined) throw new Error(`mutation ${JSON.stringify(text)} needs a value after =`);
    return rhs;
  };
  const needName = (): string => {
    if (name === undefined || name.length === 0) {
      throw new Error(`mutation ${JSON.stringify(text)} needs a name, as in ${kind}:name=value`);
    }
    return name;
  };

  switch (kind) {
    case 'header':
      if (removal) return { kind: 'remove-header', name: needName() };
      return addition
        ? { kind: 'add-header', name: needName(), value: needValue() }
        : { kind: 'set-header', name: needName(), value: needValue() };
    case 'method':
      return { kind: 'set-method', value: needValue() };
    case 'path':
      return { kind: 'set-path', value: needValue() };
    case 'query':
      return removal
        ? { kind: 'remove-query', name: needName() }
        : { kind: 'set-query', name: needName(), value: needValue() };
    case 'form':
      return { kind: 'set-form', name: needName(), value: needValue() };
    case 'json':
      return { kind: 'set-json', pointer: needName(), value: needValue() };
    case 'cookie':
      return removal
        ? { kind: 'remove-cookie', name: needName() }
        : { kind: 'set-cookie', name: needName(), value: needValue() };
    case 'body':
      return { kind: 'set-body', value: needValue() };
    default:
      throw new Error(
        `unknown mutation ${JSON.stringify(kind)}. Known: header, method, path, query, ` +
          'form, json, cookie, body. Prefix with - to remove or + to add.',
      );
  }
}

export function describeMutation(m: Mutation): string {
  switch (m.kind) {
    case 'set-header':
      return `header ${m.name}=${m.value}`;
    case 'add-header':
      return `+header ${m.name}=${m.value}`;
    case 'remove-header':
      return `-header ${m.name}`;
    case 'set-method':
      return `method=${m.value}`;
    case 'set-path':
      return `path=${m.value}`;
    case 'set-query':
      return `query ${m.name}=${m.value}`;
    case 'remove-query':
      return `-query ${m.name}`;
    case 'set-form':
      return `form ${m.name}=${m.value}`;
    case 'set-json':
      return `json ${m.pointer}=${m.value}`;
    case 'set-body':
      return `body (${m.value.length} bytes)`;
    case 'set-cookie':
      return `cookie ${m.name}=${m.value}`;
    case 'remove-cookie':
      return `-cookie ${m.name}`;
    default: {
      const exhaustive: never = m;
      return exhaustive;
    }
  }
}

export function applyMutation(request: HttpRequest, m: Mutation): HttpRequest {
  switch (m.kind) {
    case 'set-header':
      return { ...request, headers: setHeader(request.headers, m.name, m.value) };
    case 'add-header':
      return { ...request, headers: addHeader(request.headers, m.name, m.value) };
    case 'remove-header':
      return { ...request, headers: removeHeader(request.headers, m.name) };
    case 'set-method':
      return { ...request, method: m.value.toUpperCase() };
    case 'set-path': {
      const url = new URL(request.url);
      url.pathname = m.value.startsWith('/') ? m.value : `/${m.value}`;
      return { ...request, url: url.toString() };
    }
    case 'set-query': {
      const url = new URL(request.url);
      url.searchParams.set(m.name, m.value);
      return { ...request, url: url.toString() };
    }
    case 'remove-query': {
      const url = new URL(request.url);
      url.searchParams.delete(m.name);
      return { ...request, url: url.toString() };
    }
    case 'set-form': {
      const params = new URLSearchParams(request.body.toString('utf8'));
      params.set(m.name, m.value);
      return withBody(request, Buffer.from(params.toString(), 'utf8'));
    }
    case 'set-json':
      return withBody(request, Buffer.from(setJsonPointer(request.body.toString('utf8'), m.pointer, m.value), 'utf8'));
    case 'set-body':
      return withBody(request, Buffer.from(m.value, 'utf8'));
    case 'set-cookie':
    case 'remove-cookie': {
      const existing = getHeader(request.headers, 'cookie') ?? '';
      const jar = parseCookies(existing);
      if (m.kind === 'set-cookie') jar.set(m.name, m.value);
      else jar.delete(m.name);
      if (jar.size === 0) return { ...request, headers: removeHeader(request.headers, 'cookie') };
      const serialised = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
      return { ...request, headers: setHeader(request.headers, 'cookie', serialised) };
    }
    default: {
      const exhaustive: never = m;
      return exhaustive;
    }
  }
}

function parseCookies(header: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of header.split(';')) {
    const trimmed = part.trim();
    if (trimmed.length === 0) continue;
    const eq = trimmed.indexOf('=');
    if (eq < 0) out.set(trimmed, '');
    else out.set(trimmed.slice(0, eq), trimmed.slice(eq + 1));
  }
  return out;
}

/**
 * Set a value inside a JSON body by dotted path.
 *
 * Numeric segments index arrays. The value is parsed as JSON when it parses,
 * so `qty=-1` sets a number and `enabled=true` sets a boolean, and anything
 * else is a string -- which is what you want, because the type of the field is
 * frequently the test.
 */
export function setJsonPointer(body: string, pointer: string, value: string): string {
  let root: unknown;
  try {
    root = JSON.parse(body.length === 0 ? '{}' : body);
  } catch (err) {
    throw new Error(
      `the request body is not JSON, so json: cannot edit it (${(err as Error).message}). ` +
        'Use form: for urlencoded bodies or body= to replace it outright.',
    );
  }

  const segments = pointer.split('.').filter((s) => s.length > 0);
  if (segments.length === 0) throw new Error('json: needs a field path, as in json:user.role=admin');

  const parsed: unknown = (() => {
    if (value === 'null') return null;
    try {
      return JSON.parse(value);
    } catch {
      return value;
    }
  })();

  let cursor: Record<string, unknown> | unknown[] = root as Record<string, unknown>;
  for (let i = 0; i < segments.length - 1; i += 1) {
    const key = segments[i] as string;
    const next = Array.isArray(cursor)
      ? (cursor as unknown[])[Number(key)]
      : (cursor as Record<string, unknown>)[key];
    if (typeof next !== 'object' || next === null) {
      throw new Error(
        `json: cannot walk into ${segments.slice(0, i + 1).join('.')} because it is ` +
          `${next === undefined ? 'absent' : typeof next}`,
      );
    }
    cursor = next as Record<string, unknown> | unknown[];
  }

  const last = segments[segments.length - 1] as string;
  if (Array.isArray(cursor)) (cursor as unknown[])[Number(last)] = parsed;
  else (cursor as Record<string, unknown>)[last] = parsed;

  return JSON.stringify(root);
}

/**
 * Replace a body and keep Content-Length honest -- only when it was honest.
 *
 * The same rule as the proxy's rule engine: a mismatch that was already there
 * was put there deliberately.
 */
function withBody(request: HttpRequest, body: Buffer): HttpRequest {
  const declared = getHeader(request.headers, 'content-length');
  const headers =
    declared !== undefined && Number(declared) === request.body.length
      ? setHeader(request.headers, 'content-length', String(body.length))
      : request.headers;
  return { ...request, headers, body };
}

export interface ReplayOptions extends SendOptions {
  readonly scope: ScopeConfig;
  readonly mutations?: readonly Mutation[];
  /** Replace the whole request with this raw text, after mutations. */
  readonly raw?: string;
  readonly tags?: readonly string[];
}

export interface ReplayResult {
  readonly exchange: Exchange;
  readonly applied: readonly string[];
  readonly notes: readonly string[];
}

/**
 * Build the request a replay would send, without sending it.
 *
 * Separate from `replay` so that `--dry-run` shows the exact bytes, which is
 * the difference between trusting the mutation syntax and checking it.
 */
export function buildReplayRequest(
  original: HttpRequest,
  options: ReplayOptions,
): { request: HttpRequest; applied: string[] } {
  let request: HttpRequest = { ...original, startedAt: Date.now() };
  const applied: string[] = [];

  for (const mutation of options.mutations ?? []) {
    request = applyMutation(request, mutation);
    applied.push(describeMutation(mutation));
  }

  if (options.raw !== undefined) {
    const origin = new URL(request.url).origin;
    request = parseRawRequest(options.raw, origin, request.startedAt);
    applied.push('raw request supplied');
  }

  return { request, applied };
}

export async function replay(
  original: HttpRequest,
  options: ReplayOptions,
  parentId?: string,
): Promise<ReplayResult> {
  const { request, applied } = buildReplayRequest(original, options);

  // Checked after mutation, because a mutation can change the host.
  assertAllowed(options.scope, request.url);

  const result = await send(request, options);
  const id = exchangeId(request, `replay:${applied.join('|')}`);

  const exchange: Exchange = {
    id,
    request,
    ...(result.response === undefined ? {} : { response: result.response }),
    ...(result.error === undefined ? {} : { error: result.error }),
    source: 'replay',
    tags: [...(options.tags ?? []), ...applied.map((a) => `mutation:${a}`)],
    ...(parentId === undefined ? {} : { parentId }),
  };

  return { exchange, applied, notes: result.notes };
}

/** The editable text form, for `awb replay --edit`. */
export function toEditable(request: HttpRequest): string {
  return [
    '# Edit freely and save. Nothing is recomputed: a Content-Length you leave',
    '# wrong is sent wrong, which is usually the point. Lines starting with #',
    '# before the request line are stripped.',
    `# Target: ${new URL(request.url).origin}`,
    '',
    serialiseRequest(request),
  ].join('\n');
}

export function fromEditable(text: string, origin: string): HttpRequest {
  const lines = text.split(/\r?\n/);
  let start = 0;
  while (start < lines.length && (lines[start]?.startsWith('#') === true || lines[start] === '')) {
    start += 1;
  }
  return parseRawRequest(lines.slice(start).join('\r\n'), origin);
}

/** Does this request carry a body shape a `form:` or `json:` mutation fits? */
export function bodyKind(request: HttpRequest): 'json' | 'form' | 'other' | 'empty' {
  if (request.body.length === 0) return 'empty';
  const ct = contentType(request.headers);
  if (ct === 'application/x-www-form-urlencoded') return 'form';
  if (ct === 'application/json' || ct?.endsWith('+json') === true) return 'json';
  const text = request.body.toString('utf8').trimStart();
  if (text.startsWith('{') || text.startsWith('[')) return 'json';
  if (/^[A-Za-z0-9_.%-]+=/.test(text)) return 'form';
  return 'other';
}
