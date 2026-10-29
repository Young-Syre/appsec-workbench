/**
 * The fuzzing engine: positions, attack shapes, and reading the results.
 *
 * Positions are marked in the raw request with a delimiter, the same idea as
 * Burp's Intruder. The attack shapes are the same four, because they cover
 * the actual cases: one position at a time, the same value everywhere, lists
 * stepped in lockstep, and the full product.
 *
 * Three things here matter more than the shapes.
 *
 * **It refuses to start an attack it cannot finish.** The request count is
 * computed before the first request and compared against a cap. A cluster
 * bomb over two wordlists is a number people do not expect, and finding that
 * out after an hour of traffic against somebody's production service is the
 * kind of mistake that ends an engagement.
 *
 * **Rate is a first-class input.** Not because of politeness: a tool that
 * hammers a target produces rate-limited responses, and a run whose results
 * are mostly 429 has measured the rate limiter rather than the application.
 *
 * **Results are judged against a baseline.** The raw table of status codes and
 * lengths is nearly useless on a real application. What is useful is which
 * responses differ from the unfuzzed request in a way the differ calls
 * material, and that is what gets surfaced first.
 */

import {
  type HttpRequest,
  type HttpResponse,
  exchangeId,
  parseRawRequest,
  serialiseRequest,
} from '../core/message.js';
import type { Exchange } from '../core/message.js';
import { type ScopeConfig, assertAllowed } from '../core/scope.js';
import { type SendOptions, send } from '../net/send.js';
import { type ResponseDiff, diffResponses, findReflections, isMaterial } from '../replay/diff.js';
import { type PayloadSource, type Processor, applyProcessors } from './payloads.js';

export type AttackShape = 'sniper' | 'battering-ram' | 'pitchfork' | 'cluster-bomb';

export const DEFAULT_MARKER = '§';

export interface Position {
  /** Index in the template string where the payload goes. */
  readonly start: number;
  readonly end: number;
  /** What was between the markers: a default value, or empty. */
  readonly original: string;
}

export interface Template {
  /** The request text with markers removed. */
  readonly text: string;
  readonly positions: readonly Position[];
}

/**
 * Find the marked positions in a raw request.
 *
 * Markers come in pairs. An odd number of them is a typo that would otherwise
 * silently produce one fewer position than intended, so it is an error.
 */
export function parseTemplate(raw: string, marker = DEFAULT_MARKER): Template {
  const parts = raw.split(marker);
  if (parts.length % 2 === 0) {
    throw new Error(
      `the request contains ${parts.length - 1} ${marker} markers, which is an odd number. ` +
        'Positions are marked in pairs, as in id=§1§.',
    );
  }

  let text = '';
  const positions: Position[] = [];
  for (let i = 0; i < parts.length; i += 1) {
    const part = parts[i] as string;
    if (i % 2 === 0) {
      text += part;
      continue;
    }
    positions.push({ start: text.length, end: text.length + part.length, original: part });
    text += part;
  }

  return { text, positions };
}

/** Mark every value of every query parameter, as a starting point. */
export function autoMarkQuery(request: HttpRequest, marker = DEFAULT_MARKER): string {
  const raw = serialiseRequest(request);
  const firstLineEnd = raw.indexOf('\r\n');
  const line = raw.slice(0, firstLineEnd);
  const rest = raw.slice(firstLineEnd);

  const marked = line.replace(/([?&][^=&\s]+=)([^&\s]*)/g, (_whole, key: string, value: string) => {
    return `${key}${marker}${value}${marker}`;
  });
  return marked + rest;
}

/** Substitute payloads into a template. */
export function render(
  template: Template,
  payloads: readonly string[],
): string {
  if (payloads.length !== template.positions.length) {
    throw new Error(
      `${template.positions.length} positions but ${payloads.length} payloads`,
    );
  }
  let out = '';
  let at = 0;
  template.positions.forEach((position, i) => {
    out += template.text.slice(at, position.start);
    out += payloads[i] as string;
    at = position.end;
  });
  out += template.text.slice(at);
  return out;
}

export interface AttackPlan {
  readonly shape: AttackShape;
  readonly positions: number;
  readonly requests: number;
  /** Payload tuples, lazily. */
  tuples(): Generator<readonly string[]>;
}

/**
 * Work out what an attack will actually do, before it does any of it.
 *
 * Returned rather than executed so that `--dry-run` can print the count and
 * the first few payload tuples.
 */
export function planAttack(
  shape: AttackShape,
  positions: number,
  sources: readonly PayloadSource[],
): AttackPlan {
  if (positions === 0) {
    throw new Error('no payload positions were marked. Wrap a value in markers, as in id=§1§.');
  }
  if (sources.length === 0) throw new Error('no payload sets were given');

  switch (shape) {
    case 'sniper': {
      const source = sources[0] as PayloadSource;
      if (sources.length > 1) {
        throw new Error('sniper uses one payload set; give one, or choose another shape');
      }
      return {
        shape,
        positions,
        requests: positions * source.length,
        *tuples() {
          for (let p = 0; p < positions; p += 1) {
            for (const value of source.values()) {
              // Every other position keeps its original content; the caller
              // supplies those via the template's defaults.
              const tuple = new Array<string>(positions).fill(SNIPER_KEEP);
              tuple[p] = value;
              yield tuple;
            }
          }
        },
      };
    }
    case 'battering-ram': {
      const source = sources[0] as PayloadSource;
      if (sources.length > 1) {
        throw new Error('battering-ram uses one payload set; give one, or choose another shape');
      }
      return {
        shape,
        positions,
        requests: source.length,
        *tuples() {
          for (const value of source.values()) yield new Array<string>(positions).fill(value);
        },
      };
    }
    case 'pitchfork': {
      if (sources.length !== positions) {
        throw new Error(
          `pitchfork needs one payload set per position: ${positions} positions, ${sources.length} sets`,
        );
      }
      const shortest = Math.min(...sources.map((s) => s.length));
      return {
        shape,
        positions,
        requests: shortest,
        *tuples() {
          const iterators = sources.map((s) => s.values());
          for (let i = 0; i < shortest; i += 1) {
            const tuple: string[] = [];
            for (const it of iterators) {
              const next = it.next();
              if (next.done === true) return;
              tuple.push(next.value);
            }
            yield tuple;
          }
        },
      };
    }
    case 'cluster-bomb': {
      if (sources.length !== positions) {
        throw new Error(
          `cluster-bomb needs one payload set per position: ${positions} positions, ${sources.length} sets`,
        );
      }
      const requests = sources.reduce((n, s) => n * s.length, 1);
      return {
        shape,
        positions,
        requests,
        *tuples() {
          yield* product(sources.map((s) => [...s.values()]));
        },
      };
    }
    default: {
      const exhaustive: never = shape;
      return exhaustive;
    }
  }
}

/** Sentinel meaning "leave this position as it was", used by sniper. */
export const SNIPER_KEEP = '\u0000awb-keep\u0000';

function* product(lists: readonly string[][]): Generator<string[]> {
  const indices = new Array<number>(lists.length).fill(0);
  if (lists.some((l) => l.length === 0)) return;
  for (;;) {
    yield lists.map((list, i) => list[indices[i] as number] as string);
    let pos = lists.length - 1;
    for (;;) {
      indices[pos] = (indices[pos] as number) + 1;
      if ((indices[pos] as number) < (lists[pos] as string[]).length) break;
      indices[pos] = 0;
      pos -= 1;
      if (pos < 0) return;
    }
  }
}

export interface FuzzResult {
  readonly index: number;
  readonly payloads: readonly string[];
  readonly exchange: Exchange;
  /** Against the unfuzzed baseline, when one was taken. */
  readonly diff?: ResponseDiff;
  readonly material: boolean;
  /** Payloads that came back in the response, with where they landed. */
  readonly reflected: readonly string[];
  /** Regexes from --grep that matched. */
  readonly matched: readonly string[];
}

export interface FuzzOptions extends SendOptions {
  readonly scope: ScopeConfig;
  readonly shape: AttackShape;
  readonly sources: readonly PayloadSource[];
  readonly processors?: readonly Processor[];
  readonly marker?: string;
  /** Simultaneous requests. */
  readonly concurrency?: number;
  /** Minimum milliseconds between request starts, across all workers. */
  readonly minIntervalMs?: number;
  /** Refuse to start above this many requests. */
  readonly maxRequests?: number;
  /** Regexes to look for in each response. */
  readonly grep?: readonly string[];
  /** Take an unfuzzed baseline first and diff every response against it. */
  readonly baseline?: boolean;
  readonly onResult?: (result: FuzzResult) => void;
  readonly onProgress?: (done: number, total: number) => void;
  readonly tags?: readonly string[];
}

export interface FuzzSummary {
  readonly plan: AttackPlan;
  readonly results: readonly FuzzResult[];
  readonly baseline?: Exchange;
  readonly sent: number;
  readonly failed: number;
  readonly elapsedMs: number;
  /** Set when the run stopped early. */
  readonly stoppedBecause?: string;
}

const DEFAULT_MAX_REQUESTS = 10_000;

/**
 * Run an attack.
 *
 * Ordered: results come back in the order the payload tuples were generated,
 * regardless of which finished first, so two runs over the same inputs
 * produce the same report and can be diffed.
 */
export async function fuzz(
  rawTemplate: string,
  origin: string,
  options: FuzzOptions,
): Promise<FuzzSummary> {
  const template = parseTemplate(rawTemplate, options.marker ?? DEFAULT_MARKER);
  const plan = planAttack(options.shape, template.positions.length, options.sources);
  const cap = options.maxRequests ?? DEFAULT_MAX_REQUESTS;

  if (plan.requests > cap) {
    throw new Error(
      `this attack is ${plan.requests.toLocaleString()} requests, above the cap of ` +
        `${cap.toLocaleString()}. Narrow the payload sets, or raise --max-requests if you ` +
        'have agreed that volume with whoever owns the target.',
    );
  }

  // Scope is checked once on the unfuzzed request. A payload cannot change
  // the host without changing the Host header, and a template that does that
  // is checked again per request below.
  const baseRequest = parseRawRequest(template.text, origin);
  assertAllowed(options.scope, baseRequest.url);

  const started = Date.now();
  let baselineExchange: Exchange | undefined;
  let baselineResponse: HttpResponse | undefined;

  if (options.baseline !== false) {
    const result = await send(baseRequest, options);
    baselineExchange = {
      id: exchangeId(baseRequest, 'fuzz-baseline'),
      request: baseRequest,
      ...(result.response === undefined ? {} : { response: result.response }),
      ...(result.error === undefined ? {} : { error: result.error }),
      source: 'fuzz',
      tags: [...(options.tags ?? []), 'fuzz:baseline'],
    };
    baselineResponse = result.response;
  }

  const tuples = [...plan.tuples()];
  const results = new Array<FuzzResult | undefined>(tuples.length);
  const concurrency = Math.max(1, Math.min(options.concurrency ?? 4, 64));
  const minInterval = options.minIntervalMs ?? 0;
  const greps = (options.grep ?? []).map((g) => ({ source: g, re: new RegExp(g) }));

  let next = 0;
  let sent = 0;
  let failed = 0;
  let lastStart = 0;
  let stoppedBecause: string | undefined;

  const worker = async (): Promise<void> => {
    for (;;) {
      if (stoppedBecause !== undefined) return;
      const index = next;
      next += 1;
      if (index >= tuples.length) return;

      if (minInterval > 0) {
        const wait = lastStart + minInterval - Date.now();
        lastStart = Math.max(Date.now(), lastStart + minInterval);
        if (wait > 0) await sleep(wait);
      }

      const tuple = tuples[index] as readonly string[];
      const substituted = template.positions.map((position, i) => {
        const value = tuple[i] as string;
        if (value === SNIPER_KEEP) return position.original;
        return applyProcessors(value, options.processors ?? []);
      });

      const rendered = render(template, substituted);
      let request: HttpRequest;
      try {
        request = parseRawRequest(rendered, origin);
      } catch (err) {
        failed += 1;
        results[index] = {
          index,
          payloads: substituted,
          exchange: {
            id: `invalid-${index}`,
            request: baseRequest,
            error: `the payload produced an unparseable request: ${(err as Error).message}`,
            source: 'fuzz',
            tags: ['fuzz:invalid'],
          },
          material: false,
          reflected: [],
          matched: [],
        };
        continue;
      }

      try {
        assertAllowed(options.scope, request.url);
      } catch (err) {
        stoppedBecause = (err as Error).message;
        return;
      }

      const result = await send(request, options);
      sent += 1;
      if (result.response === undefined) failed += 1;

      const exchange: Exchange = {
        id: exchangeId(request, `fuzz:${index}`),
        request,
        ...(result.response === undefined ? {} : { response: result.response }),
        ...(result.error === undefined ? {} : { error: result.error }),
        source: 'fuzz',
        tags: [...(options.tags ?? []), `fuzz:${index}`],
        ...(baselineExchange === undefined ? {} : { parentId: baselineExchange.id }),
      };

      const diff =
        baselineResponse !== undefined && result.response !== undefined
          ? diffResponses(baselineResponse, result.response)
          : undefined;

      const reflected: string[] = [];
      const matched: string[] = [];
      if (result.response !== undefined) {
        for (const value of substituted) {
          if (value.length >= 3 && findReflections(result.response, value, 1).length > 0) {
            reflected.push(value);
          }
        }
        const text = result.response.body.toString('utf8');
        for (const { source, re } of greps) {
          if (re.test(text)) matched.push(source);
        }
      }

      const entry: FuzzResult = {
        index,
        payloads: substituted,
        exchange,
        ...(diff === undefined ? {} : { diff }),
        material: diff === undefined ? result.response !== undefined : isMaterial(diff),
        reflected,
        matched,
      };
      results[index] = entry;
      options.onResult?.(entry);
      options.onProgress?.(sent, tuples.length);
    }
  };

  await Promise.all(Array.from({ length: concurrency }, () => worker()));

  return {
    plan,
    results: results.filter((r): r is FuzzResult => r !== undefined),
    ...(baselineExchange === undefined ? {} : { baseline: baselineExchange }),
    sent,
    failed,
    elapsedMs: Date.now() - started,
    ...(stoppedBecause === undefined ? {} : { stoppedBecause }),
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 * Group results so a human reads the interesting ones first.
 *
 * Responses that are identical to each other are collapsed to one row with a
 * count. On a 500-request run against a parameter that does nothing, that
 * turns 500 lines into one, and the three that differ become impossible to
 * miss rather than merely present.
 */
export interface ResultGroup {
  readonly status: number | undefined;
  readonly length: number | undefined;
  readonly count: number;
  readonly examples: readonly FuzzResult[];
  readonly material: boolean;
}

export function groupResults(results: readonly FuzzResult[], examplesPerGroup = 3): ResultGroup[] {
  const groups = new Map<string, { entries: FuzzResult[]; material: boolean }>();
  for (const result of results) {
    const status = result.exchange.response?.status;
    const length = result.exchange.response?.body.length;
    const key = `${status ?? 'err'}:${length ?? 0}:${result.matched.join(',')}`;
    const group = groups.get(key) ?? { entries: [], material: false };
    group.entries.push(result);
    group.material = group.material || result.material || result.reflected.length > 0;
    groups.set(key, group);
  }

  return [...groups.values()]
    .map((group) => {
      const first = group.entries[0] as FuzzResult;
      return {
        status: first.exchange.response?.status,
        length: first.exchange.response?.body.length,
        count: group.entries.length,
        examples: group.entries.slice(0, examplesPerGroup),
        material: group.material,
      };
    })
    .sort((a, b) => {
      if (a.material !== b.material) return a.material ? -1 : 1;
      // Rare groups first: a response seen once among a thousand is the one.
      return a.count - b.count;
    });
}
