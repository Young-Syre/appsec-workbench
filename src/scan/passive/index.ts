/**
 * The passive check registry.
 *
 * Passive means a pure function of an exchange that has already happened: no
 * request is sent, nothing on the target is touched, and running the whole set
 * over a week-old capture gives the same answers it would have given live.
 * That is what makes it safe to run by default, and it is why the first thing
 * this tool does with traffic is this.
 */

import type { Exchange } from '../../core/message.js';
import type { Finding } from '../../core/store.js';
import { type FindingDraft, type PassiveCheck, type PassiveContext, runPassive } from '../check.js';
import { HEADER_CHECKS } from './headers.js';
import { COOKIE_CHECKS } from './cookies.js';
import { CORS_CHECKS } from './cors.js';
import { DISCLOSURE_CHECKS } from './disclosure.js';
import { CONTENT_CHECKS } from './content.js';

export const PASSIVE_CHECKS: readonly PassiveCheck[] = [
  ...HEADER_CHECKS,
  ...COOKIE_CHECKS,
  ...CORS_CHECKS,
  ...DISCLOSURE_CHECKS,
  ...CONTENT_CHECKS,
];

export function checkById(id: string): PassiveCheck | undefined {
  return PASSIVE_CHECKS.find((c) => c.id === id);
}

export interface PassiveScanOptions {
  readonly only?: readonly string[];
  readonly skip?: readonly string[];
  readonly context?: PassiveContext;
}

function selected(options: PassiveScanOptions): readonly PassiveCheck[] {
  let checks = PASSIVE_CHECKS;
  if (options.only !== undefined && options.only.length > 0) {
    const wanted = new Set(options.only.map((id) => id.toUpperCase()));
    checks = checks.filter((c) => wanted.has(c.id.toUpperCase()));
  }
  if (options.skip !== undefined && options.skip.length > 0) {
    const unwanted = new Set(options.skip.map((id) => id.toUpperCase()));
    checks = checks.filter((c) => !unwanted.has(c.id.toUpperCase()));
  }
  return checks;
}

/** Turn a draft into a stored finding, which means giving it its evidence. */
export function toFinding(draft: FindingDraft, exchange: Exchange, at = Date.now()): Finding {
  return {
    id: `${draft.check}-${exchange.id}-${hash(draft.title)}`,
    check: draft.check,
    title: draft.title,
    severity: draft.severity,
    confidence: draft.confidence,
    evidence: [exchange.id, ...(draft.alsoEvidence ?? [])],
    detail: draft.detail,
    remediation: draft.remediation,
    url: draft.url ?? exchange.request.url,
    at,
  };
}

function hash(text: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i += 1) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

/** Scan one exchange. */
export function scanExchange(
  exchange: Exchange,
  options: PassiveScanOptions = {},
): Finding[] {
  const drafts = runPassive(selected(options), exchange, options.context ?? {});
  return drafts.map((d) => toFinding(d, exchange));
}

/** Scan many, in capture order. */
export function scanAll(
  exchanges: Iterable<Exchange>,
  options: PassiveScanOptions = {},
): Finding[] {
  const list = [...exchanges];
  const context: PassiveContext = { all: list, ...(options.context ?? {}) };
  const out: Finding[] = [];
  for (const exchange of list) {
    out.push(...scanExchange(exchange, { ...options, context }));
  }
  return out;
}

export { type PassiveCheck, type FindingDraft, type PassiveContext } from '../check.js';
