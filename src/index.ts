/**
 * The library surface.
 *
 * Everything the CLI does is available here, because the interesting uses of a
 * tool like this are the ones nobody anticipated: a check of your own in a
 * script, a proxy embedded in an integration test, a report generated from a
 * capture your CI already has.
 */

export * from './core/headers.js';
export * from './core/message.js';
export * from './core/scope.js';
export * from './core/redact.js';
export * from './core/encoding.js';
export * from './core/authorization.js';
export { Project, type Finding, type Severity, type Confidence, severityRank, SEVERITY_ORDER } from './core/store.js';

export { send, serialiseToWire, parseResponse, type SendOptions, type SendResult } from './net/send.js';

export { Proxy, startProxy, type ProxyOptions, type ProxyStats } from './proxy/server.js';
export * from './proxy/ca.js';
export * from './proxy/rules.js';
export * from './proxy/websocket.js';

export * from './replay/replay.js';
export * from './replay/diff.js';

export * from './fuzz/payloads.js';
export * from './fuzz/engine.js';

export { PASSIVE_CHECKS, scanAll, scanExchange, checkById, toFinding } from './scan/passive/index.js';
export { type PassiveCheck, type FindingDraft, type PassiveContext } from './scan/check.js';
export * from './scan/active/runner.js';
export { ACTIVE_CHECKS, activeCheckById, estimateCost } from './scan/active/checks.js';

export * from './oob/listener.js';

export { AiClient, MODELS, type Transport, renderExchange, fence, estimateCostUsd } from './ai/client.js';
// `Verdict` exists in both the scope engine and the AI tasks; the scope one
// wins the bare name because it is the more fundamental concept here.
export {
  type TriageResult,
  type Verdict as AiVerdict,
  type PayloadSuggestion,
  type ReportDraft,
  type TrafficSummary,
  VERDICTS,
  buildTriageRequest,
  buildPayloadRequest,
  buildReportRequest,
  buildSummaryRequest,
  triage,
  validateTriage,
  validatePayloads,
  validateReport,
  validateSummary,
} from './ai/tasks.js';

export { render, renderText, renderJson, renderMarkdown, renderSarif, parseFormat, parseSeverity, counts } from './report/index.js';

export { VERSION } from './version.js';
