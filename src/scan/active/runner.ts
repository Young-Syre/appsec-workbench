/**
 * The active scanning framework.
 *
 * Active means sending requests nobody asked for. Everything here exists to
 * make that defensible:
 *
 *   - **Nothing runs without an authorisation record.** Not a flag: a record
 *     in the project naming the engagement, who authorised it and when it
 *     expires. Every finding an active check produces cites it.
 *   - **Every request is scope-checked individually**, immediately before it
 *     is sent, because a payload can change a host.
 *   - **Every request is recorded.** A finding is a claim about a specific
 *     exchange, and after the fact "what exactly did this tool send" has to
 *     be answerable from the project file.
 *   - **Rate is bounded and the budget is finite.** A check that can issue an
 *     unbounded number of requests is a denial of service with good
 *     intentions.
 *   - **Nothing destructive is attempted.** The checks confirm a defect and
 *     stop. There is no payload here that writes, deletes, or executes
 *     anything beyond arithmetic and a DNS lookup.
 *
 * Timing checks get particular care. A single slow response proves nothing --
 * networks are noisy and shared hosts stall - so any timing conclusion here
 * requires repeated measurement against a baseline, and the threshold is
 * expressed in multiples of observed variance rather than in milliseconds.
 */

import {
  type HttpRequest,
  type HttpResponse,
  type Exchange,
  exchangeId,
} from '../../core/message.js';
import { get as getHeader, set as setHeader } from '../../core/headers.js';
import { type ScopeConfig, assertAllowed } from '../../core/scope.js';
import { type Authorisation, citation } from '../../core/authorization.js';
import { type SendOptions, send } from '../../net/send.js';
import type { Confidence, Severity } from '../../core/store.js';
import type { OobListener } from '../../oob/listener.js';
import { contentType } from '../../core/message.js';

/** Somewhere a value can be put. */
export interface InjectionPoint {
  readonly kind: 'query' | 'form' | 'json' | 'header' | 'cookie' | 'path-segment';
  /** Parameter name, header name, JSON path, or the segment index as text. */
  readonly name: string;
  /** What was there, so a check can restore it and compare. */
  readonly original: string;
  /** A short label for a report. */
  readonly label: string;
}

/**
 * Find the places worth testing in a request.
 *
 * Headers are *not* enumerated by default. A request carries twenty of them,
 * nineteen are the browser's, and fuzzing all of them quadruples the traffic
 * for almost no yield. The specific headers that are worth it -- the ones a
 * reverse proxy may trust -- are tested by the checks that care about them.
 */
export function injectionPoints(request: HttpRequest): InjectionPoint[] {
  const out: InjectionPoint[] = [];

  let url: URL | undefined;
  try {
    url = new URL(request.url);
  } catch {
    url = undefined;
  }

  if (url !== undefined) {
    for (const [name, value] of url.searchParams) {
      out.push({ kind: 'query', name, original: value, label: `query ${name}` });
    }

    const segments = url.pathname.split('/').filter((s) => s.length > 0);
    segments.forEach((segment, index) => {
      // Only segments that look like identifiers. Testing `/api` and `/v1`
      // finds nothing and triples the request count.
      if (/^\d+$/.test(segment) || /^[0-9a-f]{8,}$/i.test(segment) || /^[0-9a-f-]{36}$/i.test(segment)) {
        out.push({
          kind: 'path-segment',
          name: String(index),
          original: segment,
          label: `path segment ${index} (${segment})`,
        });
      }
    });
  }

  const ct = contentType(request.headers);
  const bodyText = request.body.toString('utf8');

  if (ct === 'application/x-www-form-urlencoded' && bodyText.length > 0) {
    for (const [name, value] of new URLSearchParams(bodyText)) {
      out.push({ kind: 'form', name, original: value, label: `form ${name}` });
    }
  } else if (
    (ct === 'application/json' || ct?.endsWith('+json') === true || bodyText.trimStart().startsWith('{')) &&
    bodyText.length > 0
  ) {
    try {
      const parsed: unknown = JSON.parse(bodyText);
      for (const [path, value] of flattenJson(parsed)) {
        out.push({ kind: 'json', name: path, original: value, label: `json ${path}` });
      }
    } catch {
      /* not JSON after all; nothing to enumerate */
    }
  }

  const cookie = getHeader(request.headers, 'cookie');
  if (cookie !== undefined) {
    for (const part of cookie.split(';')) {
      const trimmed = part.trim();
      const eq = trimmed.indexOf('=');
      if (eq <= 0) continue;
      out.push({
        kind: 'cookie',
        name: trimmed.slice(0, eq),
        original: trimmed.slice(eq + 1),
        label: `cookie ${trimmed.slice(0, eq)}`,
      });
    }
  }

  return out;
}

/** Scalar leaves of a JSON document, as dotted paths. */
function flattenJson(value: unknown, prefix = '', depth = 0): [string, string][] {
  if (depth > 8) return [];
  if (value === null) return prefix.length > 0 ? [[prefix, 'null']] : [];
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return prefix.length > 0 ? [[prefix, String(value)]] : [];
  }
  const out: [string, string][] = [];
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      out.push(...flattenJson(item, prefix.length > 0 ? `${prefix}.${index}` : String(index), depth + 1));
    });
    return out;
  }
  if (typeof value === 'object') {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      out.push(...flattenJson(item, prefix.length > 0 ? `${prefix}.${key}` : key, depth + 1));
    }
  }
  return out;
}

/** Put a value into an injection point, leaving everything else alone. */
export function inject(
  request: HttpRequest,
  point: InjectionPoint,
  value: string,
): HttpRequest {
  switch (point.kind) {
    case 'query': {
      const url = new URL(request.url);
      url.searchParams.set(point.name, value);
      return { ...request, url: url.toString() };
    }
    case 'path-segment': {
      const url = new URL(request.url);
      const segments = url.pathname.split('/');
      // The index counts non-empty segments; map it back to the split array.
      let seen = -1;
      for (let i = 0; i < segments.length; i += 1) {
        if ((segments[i] ?? '').length === 0) continue;
        seen += 1;
        if (seen === Number(point.name)) {
          segments[i] = encodeURIComponent(value);
          break;
        }
      }
      url.pathname = segments.join('/');
      return { ...request, url: url.toString() };
    }
    case 'form': {
      const params = new URLSearchParams(request.body.toString('utf8'));
      params.set(point.name, value);
      return reframe(request, Buffer.from(params.toString(), 'utf8'));
    }
    case 'json': {
      const parsed: unknown = JSON.parse(request.body.toString('utf8'));
      setPath(parsed, point.name.split('.'), value);
      return reframe(request, Buffer.from(JSON.stringify(parsed), 'utf8'));
    }
    case 'cookie': {
      const jar = new Map<string, string>();
      for (const part of (getHeader(request.headers, 'cookie') ?? '').split(';')) {
        const trimmed = part.trim();
        const eq = trimmed.indexOf('=');
        if (eq > 0) jar.set(trimmed.slice(0, eq), trimmed.slice(eq + 1));
      }
      jar.set(point.name, value);
      return {
        ...request,
        headers: setHeader(
          request.headers,
          'cookie',
          [...jar].map(([k, v]) => `${k}=${v}`).join('; '),
        ),
      };
    }
    case 'header':
      return { ...request, headers: setHeader(request.headers, point.name, value) };
    default: {
      const exhaustive: never = point.kind;
      return exhaustive;
    }
  }
}

function setPath(root: unknown, segments: readonly string[], value: string): void {
  let cursor = root;
  for (let i = 0; i < segments.length - 1; i += 1) {
    const key = segments[i] as string;
    cursor = Array.isArray(cursor)
      ? (cursor as unknown[])[Number(key)]
      : (cursor as Record<string, unknown>)[key];
    if (typeof cursor !== 'object' || cursor === null) return;
  }
  const last = segments[segments.length - 1] as string;
  if (Array.isArray(cursor)) (cursor as unknown[])[Number(last)] = value;
  else if (typeof cursor === 'object' && cursor !== null) {
    (cursor as Record<string, unknown>)[last] = value;
  }
}

/** Replace a body, correcting Content-Length only if it was already correct. */
function reframe(request: HttpRequest, body: Buffer): HttpRequest {
  const declared = getHeader(request.headers, 'content-length');
  const headers =
    declared !== undefined && Number(declared) === request.body.length
      ? setHeader(request.headers, 'content-length', String(body.length))
      : request.headers;
  return { ...request, headers, body };
}

// ---- the gated sender -----------------------------------------------------

export interface ActiveFinding {
  readonly check: string;
  readonly title: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly detail: string;
  readonly remediation: string;
  readonly url: string;
  readonly evidence: readonly string[];
}

export interface Budget {
  /** Hard cap on requests for the whole run. */
  readonly maxRequests: number;
  /** Minimum milliseconds between request starts. */
  readonly minIntervalMs: number;
}

export class BudgetExhausted extends Error {
  constructor(max: number) {
    super(
      `the active scan budget of ${max} requests is spent. Raise --max-requests if you have ` +
        'agreed that volume with whoever owns the target, or narrow the scan.',
    );
    this.name = 'BudgetExhausted';
  }
}

/**
 * The only way an active check is allowed to send anything.
 *
 * Holds the scope, the authorisation, the budget and the record. A check
 * cannot bypass it, because a check is handed this and nothing else.
 */
export class ActiveSender {
  private readonly scope: ScopeConfig;
  private readonly authorisation: Authorisation;
  private readonly budget: Budget;
  private readonly sendOptions: SendOptions;
  private readonly onExchange: ((exchange: Exchange) => void) | undefined;
  private spent = 0;
  private lastStart = 0;

  constructor(options: {
    scope: ScopeConfig;
    authorisation: Authorisation;
    budget: Budget;
    sendOptions?: SendOptions;
    onExchange?: (exchange: Exchange) => void;
  }) {
    this.scope = options.scope;
    this.authorisation = options.authorisation;
    this.budget = options.budget;
    this.sendOptions = options.sendOptions ?? {};
    this.onExchange = options.onExchange;
  }

  get requestsSpent(): number {
    return this.spent;
  }

  get requestsLeft(): number {
    return Math.max(0, this.budget.maxRequests - this.spent);
  }

  get citation(): string {
    return citation(this.authorisation);
  }

  async send(
    request: HttpRequest,
    tag: string,
  ): Promise<{ exchange: Exchange; response?: HttpResponse }> {
    if (this.spent >= this.budget.maxRequests) throw new BudgetExhausted(this.budget.maxRequests);
    assertAllowed(this.scope, request.url);

    if (this.budget.minIntervalMs > 0) {
      const wait = this.lastStart + this.budget.minIntervalMs - Date.now();
      this.lastStart = Math.max(Date.now(), this.lastStart + this.budget.minIntervalMs);
      if (wait > 0) await sleep(wait);
    }

    this.spent += 1;
    const result = await send(request, this.sendOptions);
    const exchange: Exchange = {
      id: exchangeId(request, `active:${tag}:${this.spent}`),
      request,
      ...(result.response === undefined ? {} : { response: result.response }),
      ...(result.error === undefined ? {} : { error: result.error }),
      source: 'active-scan',
      tags: [`check:${tag}`],
    };
    this.onExchange?.(exchange);
    return {
      exchange,
      ...(result.response === undefined ? {} : { response: result.response }),
    };
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

export interface ActiveContext {
  readonly sender: ActiveSender;
  readonly oob?: OobListener;
  /** A second session's credentials, for authorisation testing. */
  readonly secondSession?: readonly (readonly [string, string])[];
}

export interface ActiveCheck {
  readonly id: string;
  readonly title: string;
  readonly description: string;
  /** Requests this check needs per injection point, for budgeting. */
  readonly costPerPoint: number;
  /** Does this check need an out-of-band listener? */
  readonly needsOob?: boolean;
  run(
    request: HttpRequest,
    points: readonly InjectionPoint[],
    context: ActiveContext,
  ): Promise<ActiveFinding[]>;
}

// ---- timing, done defensibly ---------------------------------------------

export interface TimingSample {
  readonly elapsedMs: number;
  readonly status: number | undefined;
}

export interface TimingVerdict {
  readonly delayed: boolean;
  readonly baselineMedian: number;
  readonly baselineSpread: number;
  readonly testMedian: number;
  readonly reason: string;
}

/**
 * Did the payload make the response slower, in a way noise cannot explain?
 *
 * The test is against the baseline's own spread rather than a fixed
 * millisecond threshold, because a 5-second delay is obvious on a local
 * service and invisible on one whose ordinary response time varies by ten
 * seconds. Requiring the test median to clear the baseline median by several
 * times the baseline's spread, *and* by a sizeable absolute margin, is what
 * makes a timing claim worth making.
 */
export function judgeTiming(
  baseline: readonly TimingSample[],
  test: readonly TimingSample[],
  expectedDelayMs: number,
): TimingVerdict {
  const baseMedian = median(baseline.map((s) => s.elapsedMs));
  const baseSpread = Math.max(spread(baseline.map((s) => s.elapsedMs)), 1);
  const testMedian = median(test.map((s) => s.elapsedMs));

  const absolute = testMedian - baseMedian;
  const relative = absolute / baseSpread;

  // Three conditions, all of them. Fewer and this reports network weather.
  const clearsSpread = relative >= 4;
  const clearsAbsolute = absolute >= expectedDelayMs * 0.6;
  const everySampleSlow = test.every((s) => s.elapsedMs > baseMedian + baseSpread * 2);

  const delayed = clearsSpread && clearsAbsolute && everySampleSlow;

  return {
    delayed,
    baselineMedian: baseMedian,
    baselineSpread: baseSpread,
    testMedian,
    reason: delayed
      ? `the delayed requests took a median of ${testMedian.toFixed(0)}ms against a baseline of ` +
        `${baseMedian.toFixed(0)}ms (spread ${baseSpread.toFixed(0)}ms), an increase of ` +
        `${absolute.toFixed(0)}ms and ${relative.toFixed(1)} times the baseline spread, and ` +
        'every sample was slow'
      : `not distinguishable from noise: baseline median ${baseMedian.toFixed(0)}ms with spread ` +
        `${baseSpread.toFixed(0)}ms, test median ${testMedian.toFixed(0)}ms ` +
        `(${absolute >= 0 ? '+' : ''}${absolute.toFixed(0)}ms, ${relative.toFixed(1)}x spread)`,
  };
}

export function median(values: readonly number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1
    ? (sorted[mid] as number)
    : ((sorted[mid - 1] as number) + (sorted[mid] as number)) / 2;
}

/** Interquartile range, which is robust to the one stalled request. */
export function spread(values: readonly number[]): number {
  if (values.length < 2) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const q = (p: number): number => {
    const at = (sorted.length - 1) * p;
    const low = Math.floor(at);
    const high = Math.ceil(at);
    const weight = at - low;
    return (sorted[low] as number) * (1 - weight) + (sorted[high] as number) * weight;
  };
  return q(0.75) - q(0.25);
}
