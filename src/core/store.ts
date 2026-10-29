/**
 * The project file: an append-only log of exchanges with deduplicated bodies.
 *
 * Burp's project file is opaque and single-writer. This one is a directory:
 *
 *   project.awb/
 *     meta.json          scope, authorisation, settings
 *     exchanges.jsonl    one metadata record per exchange, append-only
 *     blobs/<sha256>     bodies, content-addressed and therefore deduplicated
 *     frames.jsonl       websocket frames
 *     findings.jsonl     findings, each referencing an exchange id
 *
 * Append-only matters for two reasons. A capture is evidence, and evidence
 * that can be edited in place is worth less; and an append-only log can be
 * read by another process while a proxy is still writing to it, which is how
 * you grep live traffic without stopping the proxy.
 *
 * Content-addressed bodies matter because a crawl of a single-page app
 * downloads the same 2MB bundle on every navigation. Deduplicating turns a
 * gigabyte of capture into a few megabytes.
 */

import { createHash } from 'node:crypto';
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from 'node:fs';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { join } from 'node:path';

import type { Exchange, HttpRequest, HttpResponse, WebSocketFrame } from './message.js';
import type { HeaderList } from './headers.js';
import { EMPTY_SCOPE, type ScopeConfig, formatRule, parseRule } from './scope.js';
import { type Authorisation, parseAuthorisation } from './authorization.js';

export interface Finding {
  readonly id: string;
  readonly check: string;
  readonly title: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  /** Exchange ids that evidence this finding. At least one, always. */
  readonly evidence: readonly string[];
  readonly detail: string;
  readonly remediation: string;
  readonly url: string;
  /** Set when an active check produced it: the authorisation it ran under. */
  readonly authorisation?: string;
  readonly at: number;
  /** Populated only by `awb ai triage`, and marked as model output. */
  readonly aiAssessment?: AiAssessment;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'certain' | 'firm' | 'tentative';

export interface AiAssessment {
  readonly model: string;
  readonly verdict: 'exploitable' | 'likely' | 'unclear' | 'not-exploitable';
  readonly reasoning: string;
  readonly nextStep?: string;
  readonly at: number;
}

export const SEVERITY_ORDER: readonly Severity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

interface StoredMessageHead {
  readonly headers: HeaderList;
  readonly bodyRef: string;
  readonly bodyLength: number;
}

interface StoredExchange {
  readonly id: string;
  readonly source: string;
  readonly tags: readonly string[];
  readonly parentId?: string;
  readonly error?: string;
  readonly request: StoredMessageHead & {
    readonly method: string;
    readonly url: string;
    readonly httpVersion: string;
    readonly startedAt: number;
  };
  readonly response?: StoredMessageHead & {
    readonly status: number;
    readonly statusText: string;
    readonly httpVersion: string;
    readonly elapsedMs: number;
  };
}

export interface ProjectMeta {
  readonly version: 1;
  readonly createdAt: number;
  readonly scope: { readonly include: string[]; readonly exclude: string[] };
  readonly authorisation?: Authorisation;
  readonly notes?: string;
}

const EMPTY_BLOB = createHash('sha256').update(Buffer.alloc(0)).digest('hex');

export class Project {
  readonly dir: string;
  private meta: ProjectMeta;

  private constructor(dir: string, meta: ProjectMeta) {
    this.dir = dir;
    this.meta = meta;
  }

  static create(dir: string): Project {
    if (existsSync(join(dir, 'meta.json'))) {
      throw new Error(`a project already exists at ${dir}`);
    }
    mkdirSync(join(dir, 'blobs'), { recursive: true });
    const meta: ProjectMeta = {
      version: 1,
      createdAt: Date.now(),
      scope: { include: [], exclude: [] },
    };
    writeFileSync(join(dir, 'meta.json'), JSON.stringify(meta, null, 2) + '\n');
    for (const f of ['exchanges.jsonl', 'frames.jsonl', 'findings.jsonl']) {
      writeFileSync(join(dir, f), '');
    }
    return new Project(dir, meta);
  }

  static open(dir: string): Project {
    const path = join(dir, 'meta.json');
    if (!existsSync(path)) {
      throw new Error(
        `no project at ${dir}. Create one with \`awb init ${dir}\`, or pass --project.`,
      );
    }
    const raw = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
    if (raw['version'] !== 1) {
      throw new Error(`unsupported project version ${String(raw['version'])}`);
    }
    const scope = (raw['scope'] ?? { include: [], exclude: [] }) as {
      include?: string[];
      exclude?: string[];
    };
    const meta: ProjectMeta = {
      version: 1,
      createdAt: Number(raw['createdAt'] ?? Date.now()),
      scope: { include: scope.include ?? [], exclude: scope.exclude ?? [] },
      ...(raw['authorisation'] === undefined
        ? {}
        : { authorisation: parseAuthorisation(raw['authorisation']) }),
      ...(typeof raw['notes'] === 'string' ? { notes: raw['notes'] } : {}),
    };
    if (!existsSync(join(dir, 'blobs'))) mkdirSync(join(dir, 'blobs'), { recursive: true });
    for (const f of ['exchanges.jsonl', 'frames.jsonl', 'findings.jsonl']) {
      if (!existsSync(join(dir, f))) writeFileSync(join(dir, f), '');
    }
    return new Project(dir, meta);
  }

  static openOrCreate(dir: string): Project {
    return existsSync(join(dir, 'meta.json')) ? Project.open(dir) : Project.create(dir);
  }

  /** Scope as the engine wants it, parsed from the stored shorthand. */
  scope(): ScopeConfig {
    try {
      return {
        include: this.meta.scope.include.map(parseRule),
        exclude: this.meta.scope.exclude.map(parseRule),
      };
    } catch (err) {
      throw new Error(`project scope is malformed: ${(err as Error).message}`);
    }
  }

  setScope(scope: ScopeConfig): void {
    this.meta = {
      ...this.meta,
      scope: {
        include: scope.include.map(formatRule),
        exclude: scope.exclude.map(formatRule),
      },
    };
    this.flushMeta();
  }

  authorisation(): Authorisation | undefined {
    return this.meta.authorisation;
  }

  setAuthorisation(record: Authorisation): void {
    this.meta = { ...this.meta, authorisation: record };
    this.flushMeta();
  }

  metadata(): ProjectMeta {
    return this.meta;
  }

  private flushMeta(): void {
    writeFileSync(join(this.dir, 'meta.json'), JSON.stringify(this.meta, null, 2) + '\n');
  }

  // ---- blobs -------------------------------------------------------------

  private blobPath(ref: string): string {
    return join(this.dir, 'blobs', ref);
  }

  putBlob(body: Buffer): string {
    const ref = createHash('sha256').update(body).digest('hex');
    const path = this.blobPath(ref);
    if (!existsSync(path)) writeFileSync(path, body);
    return ref;
  }

  getBlob(ref: string): Buffer {
    if (ref === EMPTY_BLOB) return Buffer.alloc(0);
    const path = this.blobPath(ref);
    if (!existsSync(path)) {
      throw new Error(`body blob ${ref.slice(0, 12)} is missing from ${this.dir}/blobs`);
    }
    return readFileSync(path);
  }

  blobCount(): number {
    return readdirSync(join(this.dir, 'blobs')).length;
  }

  // ---- exchanges ---------------------------------------------------------

  append(exchange: Exchange): void {
    const stored: StoredExchange = {
      id: exchange.id,
      source: exchange.source,
      tags: exchange.tags,
      ...(exchange.parentId === undefined ? {} : { parentId: exchange.parentId }),
      ...(exchange.error === undefined ? {} : { error: exchange.error }),
      request: {
        method: exchange.request.method,
        url: exchange.request.url,
        httpVersion: exchange.request.httpVersion,
        startedAt: exchange.request.startedAt,
        headers: exchange.request.headers,
        bodyRef: this.putBlob(exchange.request.body),
        bodyLength: exchange.request.body.length,
      },
      ...(exchange.response === undefined
        ? {}
        : {
            response: {
              status: exchange.response.status,
              statusText: exchange.response.statusText,
              httpVersion: exchange.response.httpVersion,
              elapsedMs: exchange.response.elapsedMs,
              headers: exchange.response.headers,
              bodyRef: this.putBlob(exchange.response.body),
              bodyLength: exchange.response.body.length,
            },
          }),
    };
    appendFileSync(join(this.dir, 'exchanges.jsonl'), JSON.stringify(stored) + '\n');
  }

  private hydrate(stored: StoredExchange): Exchange {
    const request: HttpRequest = {
      method: stored.request.method,
      url: stored.request.url,
      httpVersion: stored.request.httpVersion,
      headers: stored.request.headers,
      body: this.getBlob(stored.request.bodyRef),
      startedAt: stored.request.startedAt,
    };
    const response: HttpResponse | undefined =
      stored.response === undefined
        ? undefined
        : {
            status: stored.response.status,
            statusText: stored.response.statusText,
            httpVersion: stored.response.httpVersion,
            headers: stored.response.headers,
            body: this.getBlob(stored.response.bodyRef),
            elapsedMs: stored.response.elapsedMs,
          };
    return {
      id: stored.id,
      request,
      ...(response === undefined ? {} : { response }),
      ...(stored.error === undefined ? {} : { error: stored.error }),
      source: stored.source as Exchange['source'],
      tags: stored.tags,
      ...(stored.parentId === undefined ? {} : { parentId: stored.parentId }),
    };
  }

  /** Every exchange, in capture order. Bodies are read lazily per record. */
  *exchanges(): Generator<Exchange> {
    const path = join(this.dir, 'exchanges.jsonl');
    if (!existsSync(path)) return;
    const text = readFileSync(path, 'utf8');
    for (const line of text.split('\n')) {
      if (line.trim().length === 0) continue;
      yield this.hydrate(JSON.parse(line) as StoredExchange);
    }
  }

  /** Stream the log without holding it in memory, for a long capture. */
  async *stream(): AsyncGenerator<Exchange> {
    const path = join(this.dir, 'exchanges.jsonl');
    if (!existsSync(path)) return;
    const rl = createInterface({
      input: createReadStream(path, 'utf8'),
      crlfDelay: Infinity,
    });
    try {
      for await (const line of rl) {
        if (line.trim().length === 0) continue;
        yield this.hydrate(JSON.parse(line) as StoredExchange);
      }
    } finally {
      rl.close();
    }
  }

  get(id: string): Exchange | undefined {
    for (const ex of this.exchanges()) if (ex.id === id || ex.id.startsWith(id)) return ex;
    return undefined;
  }

  count(): number {
    const path = join(this.dir, 'exchanges.jsonl');
    if (!existsSync(path)) return 0;
    return readFileSync(path, 'utf8')
      .split('\n')
      .filter((l) => l.trim().length > 0).length;
  }

  // ---- websocket frames --------------------------------------------------

  appendFrame(frame: WebSocketFrame): void {
    appendFileSync(
      join(this.dir, 'frames.jsonl'),
      JSON.stringify({
        exchangeId: frame.exchangeId,
        direction: frame.direction,
        opcode: frame.opcode,
        at: frame.at,
        bodyRef: this.putBlob(frame.payload),
        length: frame.payload.length,
      }) + '\n',
    );
  }

  *frames(): Generator<WebSocketFrame> {
    const path = join(this.dir, 'frames.jsonl');
    if (!existsSync(path)) return;
    for (const line of readFileSync(path, 'utf8').split('\n')) {
      if (line.trim().length === 0) continue;
      const o = JSON.parse(line) as {
        exchangeId: string;
        direction: 'sent' | 'received';
        opcode: WebSocketFrame['opcode'];
        at: number;
        bodyRef: string;
      };
      yield {
        exchangeId: o.exchangeId,
        direction: o.direction,
        opcode: o.opcode,
        at: o.at,
        payload: this.getBlob(o.bodyRef),
      };
    }
  }

  // ---- findings ----------------------------------------------------------

  appendFinding(finding: Finding): void {
    appendFileSync(join(this.dir, 'findings.jsonl'), JSON.stringify(finding) + '\n');
  }

  *findings(): Generator<Finding> {
    const path = join(this.dir, 'findings.jsonl');
    if (!existsSync(path)) return;
    for (const line of readFileSync(path, 'utf8').split('\n')) {
      if (line.trim().length === 0) continue;
      yield JSON.parse(line) as Finding;
    }
  }

  /**
   * Findings with duplicates collapsed.
   *
   * The same check firing on fifty URLs of one application is one finding
   * with fifty pieces of evidence, not fifty findings. Collapsing happens on
   * read rather than on write so the raw log stays complete.
   */
  dedupedFindings(): Finding[] {
    const byKey = new Map<string, Finding>();
    for (const f of this.findings()) {
      const key = `${f.check}\0${f.title}\0${originOf(f.url)}`;
      const prior = byKey.get(key);
      if (prior === undefined) {
        byKey.set(key, f);
        continue;
      }
      byKey.set(key, {
        ...prior,
        evidence: [...new Set([...prior.evidence, ...f.evidence])],
        // Keep the worst severity and the strongest confidence seen.
        severity:
          severityRank(f.severity) < severityRank(prior.severity) ? f.severity : prior.severity,
        confidence: strongerConfidence(prior.confidence, f.confidence),
      });
    }
    return [...byKey.values()].sort(
      (a, b) => severityRank(a.severity) - severityRank(b.severity) || a.check.localeCompare(b.check),
    );
  }
}

function strongerConfidence(a: Confidence, b: Confidence): Confidence {
  const order: Confidence[] = ['certain', 'firm', 'tentative'];
  return order.indexOf(a) <= order.indexOf(b) ? a : b;
}

function originOf(raw: string): string {
  try {
    return new URL(raw).origin;
  } catch {
    return raw;
  }
}

/** Scope-and-authorisation state in one place, as the CLI needs it. */
export interface ProjectContext {
  readonly project: Project;
  readonly scope: ScopeConfig;
}

export function contextFor(dir: string): ProjectContext {
  const project = Project.open(dir);
  let scope: ScopeConfig;
  try {
    scope = project.scope();
  } catch {
    scope = EMPTY_SCOPE;
  }
  return { project, scope };
}
