/**
 * Interactive interception: hold a message until a person decides.
 *
 * The proxy hands a request (and optionally the response) to an
 * `Interceptor`, which parks it in a queue and returns a promise that settles
 * when somebody forwards it, edits it, or drops it. The queue knows nothing
 * about terminals -- the CLI drives it from a keyboard, a test drives it from
 * code, and either can be swapped without touching the proxy.
 *
 * Three decisions worth knowing about.
 *
 * **Only what scope cleared is ever held.** Interception happens after the
 * scope verdict, so an out-of-scope request is refused or tunnelled exactly
 * as before and never reaches the queue. An *edited* request is checked
 * again by the proxy before it is sent, because an edit can change the host.
 *
 * **A held message has a deadline.** A browser gives up on a request after a
 * minute or two, and a proxy that waits forever for a person who has gone to
 * lunch fills up with sockets the browser has abandoned. When the deadline
 * passes, the configured fallback applies -- forward by default, because a
 * timed-out page load is a worse surprise than a request that went through
 * unedited -- and the decision says it was the timeout that made it.
 *
 * **Nothing is recomputed on the operator's behalf.** An edited request goes
 * out as edited. The one exception is opt-in and explicit: a caller may ask
 * for Content-Length to be corrected, because an editor that changed the body
 * almost never meant to change the framing as well.
 */

import { EventEmitter } from 'node:events';

import type { HttpRequest, HttpResponse } from '../core/message.js';

export type InterceptAction = 'forward' | 'drop';

export interface RequestDecision {
  readonly action: InterceptAction;
  /** Present when the operator changed the request. Sent instead of the original. */
  readonly request?: HttpRequest;
  /** Why the decision was made. */
  readonly by: DecidedBy;
}

export interface ResponseDecision {
  readonly action: InterceptAction;
  readonly response?: HttpResponse;
  readonly by: DecidedBy;
}

/**
 * Who settled a held message: a person, the deadline, interception being
 * switched off, or the client hanging up while it waited.
 */
export type DecidedBy = 'operator' | 'timeout' | 'released' | 'abandoned';

export interface HeldRequest {
  readonly kind: 'request';
  readonly id: number;
  readonly request: HttpRequest;
  readonly heldAt: number;
}

export interface HeldResponse {
  readonly kind: 'response';
  readonly id: number;
  readonly request: HttpRequest;
  readonly response: HttpResponse;
  readonly heldAt: number;
}

export type Held = HeldRequest | HeldResponse;

/** Which messages to hold. Both patterns must match when both are given. */
export interface InterceptFilter {
  /** Matched against the absolute URL. */
  readonly url?: RegExp;
  /** Matched against the method, case-insensitively. */
  readonly method?: RegExp;
}

export interface InterceptorOptions {
  /** Hold requests. On unless switched off. */
  readonly requests?: boolean;
  /** Hold responses too. Off unless asked for, since it doubles the keystrokes. */
  readonly responses?: boolean;
  readonly filter?: InterceptFilter;
  /** How long a message may wait for a decision. Default two minutes. */
  readonly timeoutMs?: number;
  /** What happens when the deadline passes. Default forward. */
  readonly onTimeout?: InterceptAction;
}

const DEFAULT_TIMEOUT = 120_000;

interface Pending {
  readonly held: Held;
  readonly settle: (decision: RequestDecision | ResponseDecision) => void;
  readonly timer: NodeJS.Timeout;
}

/**
 * The queue.
 *
 * Emits `held` when a message joins the queue and `settled` when one leaves
 * it, with the decision. Decisions are addressed by id rather than "the
 * current one", so that two people -- or a person and a test -- cannot
 * forward the wrong message by racing each other.
 */
export class Interceptor extends EventEmitter {
  private readonly pending = new Map<number, Pending>();
  private nextId = 1;
  private holdRequests: boolean;
  private holdResponses: boolean;
  private readonly filter: InterceptFilter;
  private readonly timeoutMs: number;
  private readonly onTimeout: InterceptAction;

  constructor(options: InterceptorOptions = {}) {
    super();
    this.holdRequests = options.requests ?? true;
    this.holdResponses = options.responses ?? false;
    this.filter = options.filter ?? {};
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT;
    this.onTimeout = options.onTimeout ?? 'forward';
  }

  get interceptingRequests(): boolean {
    return this.holdRequests;
  }

  get interceptingResponses(): boolean {
    return this.holdResponses;
  }

  /** Everything waiting, oldest first. */
  queue(): Held[] {
    return [...this.pending.values()].map((p) => p.held).sort((a, b) => a.id - b.id);
  }

  /** The oldest message waiting, which is the one a person is looking at. */
  head(): Held | undefined {
    return this.queue()[0];
  }

  get size(): number {
    return this.pending.size;
  }

  matches(request: HttpRequest): boolean {
    if (this.filter.url !== undefined && !this.filter.url.test(request.url)) return false;
    if (this.filter.method !== undefined && !this.filter.method.test(request.method)) return false;
    return true;
  }

  /**
   * Called by the proxy for every in-scope request, after rules have run.
   *
   * Resolves immediately with an unedited forward when interception is off or
   * the filter does not match, so the proxy has one code path either way.
   * `signal` is the client's connection: if it closes while the request
   * waits, the request leaves the queue as abandoned rather than sitting in
   * front of the operator for a browser that has stopped listening.
   */
  holdRequest(request: HttpRequest, signal?: AbortSignal): Promise<RequestDecision> {
    if (!this.holdRequests || !this.matches(request)) {
      return Promise.resolve({ action: 'forward', by: 'released' });
    }
    const held: HeldRequest = { kind: 'request', id: this.nextId++, request, heldAt: Date.now() };
    return this.enqueue(held, signal) as Promise<RequestDecision>;
  }

  holdResponse(
    request: HttpRequest,
    response: HttpResponse,
    signal?: AbortSignal,
  ): Promise<ResponseDecision> {
    if (!this.holdResponses || !this.matches(request)) {
      return Promise.resolve({ action: 'forward', by: 'released' });
    }
    const held: HeldResponse = {
      kind: 'response',
      id: this.nextId++,
      request,
      response,
      heldAt: Date.now(),
    };
    return this.enqueue(held, signal) as Promise<ResponseDecision>;
  }

  /** Forward a held message, optionally replaced by an edited one. */
  forward(id: number, edited?: HttpRequest | HttpResponse): boolean {
    const pending = this.pending.get(id);
    if (pending === undefined) return false;
    if (edited === undefined) {
      this.settle(id, { action: 'forward', by: 'operator' });
    } else if (pending.held.kind === 'request') {
      this.settle(id, { action: 'forward', request: edited as HttpRequest, by: 'operator' });
    } else {
      this.settle(id, { action: 'forward', response: edited as HttpResponse, by: 'operator' });
    }
    return true;
  }

  drop(id: number): boolean {
    if (!this.pending.has(id)) return false;
    this.settle(id, { action: 'drop', by: 'operator' });
    return true;
  }

  /**
   * Switch request interception on or off.
   *
   * Switching it off releases everything waiting, unedited. Leaving messages
   * parked after the operator has said "stop intercepting" would hang pages
   * for no reason anybody could see.
   */
  setRequests(on: boolean): void {
    this.holdRequests = on;
    if (!on) this.releaseAll('request');
  }

  setResponses(on: boolean): void {
    this.holdResponses = on;
    if (!on) this.releaseAll('response');
  }

  /** Forward everything waiting, unedited. Used on shutdown. */
  releaseAll(kind?: Held['kind']): void {
    for (const [id, pending] of [...this.pending]) {
      if (kind === undefined || pending.held.kind === kind) {
        this.settle(id, { action: 'forward', by: 'released' });
      }
    }
  }

  private enqueue(held: Held, signal?: AbortSignal): Promise<RequestDecision | ResponseDecision> {
    return new Promise((resolve) => {
      if (signal?.aborted === true) {
        resolve({ action: 'drop', by: 'abandoned' });
        return;
      }
      const timer = setTimeout(() => {
        this.settle(held.id, { action: this.onTimeout, by: 'timeout' });
      }, this.timeoutMs);
      this.pending.set(held.id, { held, settle: resolve, timer });
      signal?.addEventListener(
        'abort',
        () => this.settle(held.id, { action: 'drop', by: 'abandoned' }),
        { once: true },
      );
      this.emit('held', held);
    });
  }

  private settle(id: number, decision: RequestDecision | ResponseDecision): void {
    const pending = this.pending.get(id);
    if (pending === undefined) return;
    this.pending.delete(id);
    clearTimeout(pending.timer);
    pending.settle(decision);
    this.emit('settled', pending.held, decision);
  }
}

/**
 * Strip the newline an editor appends on save.
 *
 * Almost every editor terminates the file with a newline whether or not one
 * was there, and in a request that newline is a byte of body. If the text
 * handed to the editor did not end with one and the saved text does, exactly
 * one is removed; a body that genuinely ends in a newline survives because it
 * was written out with one.
 */
export function stripEditorNewline(written: string, saved: string): string {
  if (written.endsWith('\n')) return saved;
  if (saved.endsWith('\r\n')) return saved.slice(0, -2);
  if (saved.endsWith('\n')) return saved.slice(0, -1);
  return saved;
}

/**
 * Does the declared Content-Length disagree with the body?
 *
 * Returned rather than fixed, so the interface can say so and let the
 * operator decide. `undefined` when there is no Content-Length to disagree.
 */
export function lengthMismatch(
  message: { readonly headers: HttpRequest['headers']; readonly body: Buffer },
): { declared: string; actual: number } | undefined {
  const declared = message.headers.find(([k]) => k.toLowerCase() === 'content-length')?.[1];
  if (declared === undefined) return undefined;
  if (Number(declared) === message.body.length && /^\d+$/.test(declared.trim())) return undefined;
  return { declared, actual: message.body.length };
}

/** Correct Content-Length to the body actually held. The explicit opt-in. */
export function withFixedLength<T extends { readonly headers: HttpRequest['headers']; readonly body: Buffer }>(
  message: T,
): T {
  return {
    ...message,
    headers: message.headers.map(([k, v]) =>
      k.toLowerCase() === 'content-length' ? ([k, String(message.body.length)] as const) : ([k, v] as const),
    ),
  };
}
