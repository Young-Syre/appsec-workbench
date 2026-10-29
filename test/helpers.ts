/**
 * Test helpers: a throwaway project directory and an exchange factory.
 *
 * Nothing in the suite touches a network it did not itself start, and nothing
 * writes outside a temporary directory.
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { Exchange, HttpRequest, HttpResponse } from '../src/core/message.js';
import { exchangeId } from '../src/core/message.js';
import { Project } from '../src/core/store.js';

export function tempDir(): string {
  return mkdtempSync(join(tmpdir(), 'awb-test-'));
}

export function withProject<T>(fn: (project: Project, dir: string) => T): T {
  const dir = join(tempDir(), 'p.awb');
  const project = Project.create(dir);
  try {
    return fn(project, dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export async function withProjectAsync<T>(
  fn: (project: Project, dir: string) => Promise<T>,
): Promise<T> {
  const dir = join(tempDir(), 'p.awb');
  const project = Project.create(dir);
  try {
    return await fn(project, dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

let clock = 1_700_000_000_000;

export function makeRequest(over: Partial<HttpRequest> = {}): HttpRequest {
  clock += 1000;
  return {
    method: 'GET',
    url: 'https://target.example/',
    httpVersion: '1.1',
    headers: [
      ['Host', 'target.example'],
      ['User-Agent', 'awb-test'],
    ],
    body: Buffer.alloc(0),
    startedAt: clock,
    ...over,
  };
}

export function makeResponse(over: Partial<HttpResponse> = {}): HttpResponse {
  return {
    status: 200,
    statusText: 'OK',
    httpVersion: '1.1',
    headers: [['Content-Type', 'text/html']],
    body: Buffer.from('<html><body>ok</body></html>'),
    elapsedMs: 10,
    ...over,
  };
}

export function makeExchange(over: Partial<Exchange> = {}): Exchange {
  const request = over.request ?? makeRequest();
  return {
    id: over.id ?? exchangeId(request),
    request,
    response: makeResponse(),
    source: 'proxy',
    tags: [],
    ...over,
  };
}
