/**
 * Scope, and the rule that nothing is sent anywhere scope has not cleared.
 *
 * This is the one module in the project that is allowed to be paranoid. Every
 * outbound request in the workbench -- proxy forwarding, replay, fuzzing,
 * active checks, the browser -- asks this module first, and a scope that has
 * not been configured answers no. The alternative default, "allow unless
 * excluded", turns a mistyped host into unauthorised traffic against a third
 * party, and no amount of care elsewhere recovers from that.
 *
 * A decision always carries the rule that produced it, so a capture can be
 * audited after the fact.
 */

export interface ScopeRule {
  /** `https`, `http`, or `*`. */
  readonly scheme: string;
  /** Host pattern: exact, or `*.example.com` for one-or-more labels. */
  readonly host: string;
  /** Port, or `*`. The default port for the scheme if omitted. */
  readonly port: string;
  /** Path prefix pattern; `*` matches anything. */
  readonly path: string;
}

export type Verdict = 'in-scope' | 'out-of-scope' | 'not-covered';

export interface ScopeDecision {
  readonly verdict: Verdict;
  readonly url: string;
  /** The rule that decided it, if any rule did. */
  readonly rule?: ScopeRule;
  readonly reason: string;
}

export interface ScopeConfig {
  readonly include: readonly ScopeRule[];
  readonly exclude: readonly ScopeRule[];
}

export const EMPTY_SCOPE: ScopeConfig = { include: [], exclude: [] };

/**
 * Parse a rule from the shorthand people actually type.
 *
 *   example.com                  -> any scheme, any port, any path
 *   https://example.com          -> https, default port, any path
 *   *.example.com/api            -> any subdomain, paths under /api
 *   http://10.0.0.5:8080         -> exact host and port
 */
export function parseRule(text: string): ScopeRule {
  const trimmed = text.trim();
  if (trimmed.length === 0) throw new Error('empty scope rule');

  let rest = trimmed;
  let scheme = '*';
  const schemeMatch = /^([a-z][a-z0-9+.-]*):\/\//i.exec(rest);
  if (schemeMatch) {
    scheme = (schemeMatch[1] as string).toLowerCase();
    rest = rest.slice(schemeMatch[0].length);
  }

  const slash = rest.indexOf('/');
  const authority = slash < 0 ? rest : rest.slice(0, slash);
  const path = slash < 0 ? '*' : rest.slice(slash);

  let host = authority;
  let port = '*';
  // IPv6 literals are bracketed, and the colon inside them is not a port.
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    if (close < 0) throw new Error(`unterminated IPv6 literal in ${JSON.stringify(text)}`);
    host = authority.slice(0, close + 1);
    const tail = authority.slice(close + 1);
    if (tail.startsWith(':')) port = tail.slice(1);
  } else {
    const colon = authority.lastIndexOf(':');
    if (colon > 0) {
      host = authority.slice(0, colon);
      port = authority.slice(colon + 1);
    }
  }

  if (host.length === 0) throw new Error(`no host in scope rule ${JSON.stringify(text)}`);
  if (port !== '*' && !/^\d+$/.test(port)) {
    throw new Error(`port must be a number or * in ${JSON.stringify(text)}`);
  }

  return { scheme, host: host.toLowerCase(), port, path };
}

export function formatRule(rule: ScopeRule): string {
  const scheme = rule.scheme === '*' ? '' : `${rule.scheme}://`;
  const port = rule.port === '*' ? '' : `:${rule.port}`;
  const path = rule.path === '*' ? '' : rule.path;
  return `${scheme}${rule.host}${port}${path}`;
}

function defaultPort(scheme: string): string | undefined {
  if (scheme === 'https' || scheme === 'wss') return '443';
  if (scheme === 'http' || scheme === 'ws') return '80';
  return undefined;
}

/**
 * Wildcard host matching.
 *
 * `*.example.com` matches one or more labels to the left and deliberately
 * does NOT match the apex. Matching the apex is the behaviour people assume
 * and programmes rarely mean, and being wrong in that direction puts traffic
 * on a host nobody cleared.
 */
export function hostMatches(pattern: string, host: string): boolean {
  const h = host.toLowerCase();
  const p = pattern.toLowerCase();
  if (p === '*') return true;
  if (!p.startsWith('*.')) return p === h;
  const suffix = p.slice(1); // ".example.com"
  return h.endsWith(suffix) && h.length > suffix.length;
}

function pathMatches(pattern: string, path: string): boolean {
  if (pattern === '*' || pattern === '/') return true;
  const p = pattern.endsWith('/') ? pattern.slice(0, -1) : pattern;
  return path === p || path.startsWith(p + '/') || path.startsWith(p + '?');
}

function ruleMatches(rule: ScopeRule, url: URL): boolean {
  const scheme = url.protocol.replace(':', '').toLowerCase();
  if (rule.scheme !== '*' && rule.scheme !== scheme) return false;

  const host = url.hostname.toLowerCase();
  if (!hostMatches(rule.host, host)) return false;

  if (rule.port !== '*') {
    const actual = url.port !== '' ? url.port : (defaultPort(scheme) ?? '');
    if (actual !== rule.port) return false;
  }

  return pathMatches(rule.path, url.pathname + url.search);
}

/**
 * Decide, and say why.
 *
 * Exclusion wins over inclusion unconditionally. Programmes differ on that
 * ordering for *reporting* -- some say demonstrated impact beats a listed
 * exclusion -- but this is not a reporting decision, it is a decision about
 * where to send packets, and there the conservative order is the only
 * defensible one.
 */
export function decide(config: ScopeConfig, rawUrl: string): ScopeDecision {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return {
      verdict: 'not-covered',
      url: rawUrl,
      reason: 'not a parseable absolute URL, so no rule can apply to it',
    };
  }

  for (const rule of config.exclude) {
    if (ruleMatches(rule, url)) {
      return {
        verdict: 'out-of-scope',
        url: rawUrl,
        rule,
        reason: `excluded by ${formatRule(rule)}`,
      };
    }
  }

  for (const rule of config.include) {
    if (ruleMatches(rule, url)) {
      return {
        verdict: 'in-scope',
        url: rawUrl,
        rule,
        reason: `included by ${formatRule(rule)}`,
      };
    }
  }

  return {
    verdict: 'not-covered',
    url: rawUrl,
    reason:
      config.include.length === 0
        ? 'no include rules are configured, and scope is deny by default'
        : 'no include rule matches, and scope is deny by default',
  };
}

/** The question every outbound code path actually asks. */
export function isAllowed(config: ScopeConfig, url: string): boolean {
  return decide(config, url).verdict === 'in-scope';
}

export class ScopeViolation extends Error {
  readonly decision: ScopeDecision;
  constructor(decision: ScopeDecision) {
    super(
      `refusing to send a request to ${decision.url}: ${decision.reason}. ` +
        'Add it with `awb scope add` if you are authorised to test it.',
    );
    this.name = 'ScopeViolation';
    this.decision = decision;
  }
}

/** Throw unless the URL is in scope. Called immediately before every send. */
export function assertAllowed(config: ScopeConfig, url: string): void {
  const decision = decide(config, url);
  if (decision.verdict !== 'in-scope') throw new ScopeViolation(decision);
}

export function parseScopeConfig(input: {
  include?: readonly string[];
  exclude?: readonly string[];
}): ScopeConfig {
  return {
    include: (input.include ?? []).map(parseRule),
    exclude: (input.exclude ?? []).map(parseRule),
  };
}

/**
 * Contradictions inside a scope configuration.
 *
 * A rule that is both included and excluded, or an exclusion no inclusion
 * could ever reach, means the file does not say what its author thought. That
 * is a question for whoever owns the programme, and it is cheaper to ask it
 * before testing than to argue about it after.
 */
export interface ScopeProblem {
  readonly kind: 'shadowed-include' | 'unreachable-exclude' | 'duplicate';
  readonly detail: string;
}

export function lintScope(config: ScopeConfig): ScopeProblem[] {
  const problems: ScopeProblem[] = [];
  const seen = new Map<string, 'include' | 'exclude'>();

  for (const [list, kind] of [
    [config.include, 'include'],
    [config.exclude, 'exclude'],
  ] as const) {
    for (const rule of list) {
      const key = formatRule(rule);
      const prior = seen.get(key);
      if (prior === kind) {
        problems.push({ kind: 'duplicate', detail: `${key} is listed twice as an ${kind}` });
      } else if (prior !== undefined) {
        problems.push({
          kind: 'shadowed-include',
          detail: `${key} is both included and excluded; the exclusion wins and the inclusion never fires`,
        });
      }
      seen.set(key, kind);
    }
  }

  for (const ex of config.exclude) {
    const reachable = config.include.some((inc) => couldOverlap(inc, ex));
    if (!reachable && config.include.length > 0) {
      problems.push({
        kind: 'unreachable-exclude',
        detail: `${formatRule(ex)} excludes something no include rule reaches, so it has no effect`,
      });
    }
  }

  return problems;
}

/** Conservative overlap test: true unless the two rules provably cannot meet. */
function couldOverlap(a: ScopeRule, b: ScopeRule): boolean {
  if (a.scheme !== '*' && b.scheme !== '*' && a.scheme !== b.scheme) return false;
  if (a.port !== '*' && b.port !== '*' && a.port !== b.port) return false;
  if (!hostOverlap(a.host, b.host)) return false;
  if (a.path === '*' || b.path === '*') return true;
  return a.path.startsWith(b.path) || b.path.startsWith(a.path);
}

function hostOverlap(a: string, b: string): boolean {
  if (a === '*' || b === '*') return true;
  if (a.startsWith('*.') && b.startsWith('*.')) {
    return a.endsWith(b.slice(1)) || b.endsWith(a.slice(1));
  }
  if (a.startsWith('*.')) return hostMatches(a, b);
  if (b.startsWith('*.')) return hostMatches(b, a);
  return a === b;
}
