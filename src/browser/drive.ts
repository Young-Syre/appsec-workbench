/**
 * Driving a real browser, and why that is not optional.
 *
 * A crawler that fetches URLs and parses HTML sees the 1998 web. Everything
 * interesting in a modern application happens after the JavaScript runs: the
 * routes exist in a client-side router, the API calls are issued by a bundle,
 * the authentication is three redirects and a token exchange, and the forms
 * are rendered by a framework. A proxy with no browser behind it records
 * whatever you happened to click.
 *
 * So the browser is the crawler. Chromium is launched pointed at the
 * workbench's own proxy, which means every request it makes -- including the
 * ones a bundle issues from a service worker -- lands in the project file
 * through exactly the same path as traffic from a human. Nothing here needs to
 * reimplement capture.
 *
 * Playwright is an optional peer dependency. Install it for this command;
 * every other command works without it, and the error if it is missing says
 * so rather than failing on an import.
 */

import { existsSync } from 'node:fs';

import type { ScopeConfig } from '../core/scope.js';
import { decide } from '../core/scope.js';

/**
 * The parts of Playwright used here.
 *
 * Declared structurally rather than imported as types so the package is not
 * a build-time dependency: a user who never runs `awb browse` should not have
 * to install a browser engine to compile this.
 */
interface PlaywrightLike {
  chromium: {
    launch(options: Record<string, unknown>): Promise<BrowserLike>;
  };
}

interface BrowserLike {
  newContext(options: Record<string, unknown>): Promise<ContextLike>;
  close(): Promise<void>;
}

interface ContextLike {
  newPage(): Promise<PageLike>;
  addCookies(cookies: readonly Record<string, unknown>[]): Promise<void>;
  cookies(): Promise<Record<string, unknown>[]>;
  close(): Promise<void>;
}

interface PageLike {
  goto(url: string, options?: Record<string, unknown>): Promise<unknown>;
  content(): Promise<string>;
  title(): Promise<string>;
  url(): string;
  evaluate<T>(fn: string): Promise<T>;
  waitForTimeout(ms: number): Promise<void>;
  on(event: string, handler: (arg: unknown) => void): void;
  close(): Promise<void>;
}

export async function loadPlaywright(): Promise<PlaywrightLike> {
  try {
    // The specifier is a variable so that TypeScript does not try to resolve
    // it at build time: playwright is an optional peer dependency, and the
    // whole point is that this compiles and runs without it installed.
    const specifier = 'playwright';
    const mod = (await import(specifier)) as unknown as PlaywrightLike;
    return mod;
  } catch {
    throw new Error(
      'playwright is not installed, and `awb browse` needs it to drive a real browser.\n\n' +
        '  npm install playwright && npx playwright install chromium\n\n' +
        'It is an optional dependency: proxy, replay, fuzz, scan and the rest work without it.',
    );
  }
}

export interface FormFact {
  readonly action: string;
  readonly method: string;
  readonly fields: readonly { readonly name: string; readonly type: string }[];
}

export interface PageFacts {
  readonly url: string;
  readonly title: string;
  readonly links: readonly string[];
  readonly forms: readonly FormFact[];
  /** Keys only. The values are credentials often enough to not collect them. */
  readonly storageKeys: readonly string[];
  readonly inlineEventHandlers: readonly string[];
  readonly scriptSources: readonly string[];
  readonly consoleErrors: readonly string[];
  /** Dangerous DOM sinks reachable from a URL-controlled source. */
  readonly domSinks: readonly DomSink[];
}

export interface DomSink {
  readonly sink: string;
  readonly source: string;
  readonly script: string;
  readonly excerpt: string;
}

/**
 * The in-page script that collects the facts.
 *
 * Kept as one expression so it can be handed to `page.evaluate` without a
 * build step. Everything it returns is serialisable, and it deliberately
 * collects storage *keys* and not values: local storage is where single-page
 * applications keep their tokens.
 */
const COLLECT = `(() => {
  const abs = (href) => { try { return new URL(href, location.href).toString(); } catch { return null; } };

  const links = [...document.querySelectorAll('a[href]')]
    .map((a) => abs(a.getAttribute('href')))
    .filter((u) => u !== null);

  const forms = [...document.querySelectorAll('form')].map((form) => ({
    action: abs(form.getAttribute('action') || location.href) || location.href,
    method: (form.getAttribute('method') || 'GET').toUpperCase(),
    fields: [...form.querySelectorAll('input,select,textarea')].map((el) => ({
      name: el.getAttribute('name') || '',
      type: el.getAttribute('type') || el.tagName.toLowerCase(),
    })),
  }));

  const storageKeys = [];
  try { for (let i = 0; i < localStorage.length; i++) storageKeys.push('localStorage:' + localStorage.key(i)); } catch {}
  try { for (let i = 0; i < sessionStorage.length; i++) storageKeys.push('sessionStorage:' + sessionStorage.key(i)); } catch {}

  const handlerAttributes = ['onclick','onerror','onload','onmouseover','onfocus','onsubmit'];
  const inlineEventHandlers = [];
  for (const attr of handlerAttributes) {
    for (const el of document.querySelectorAll('[' + attr + ']')) {
      inlineEventHandlers.push(el.tagName.toLowerCase() + '[' + attr + ']');
    }
  }

  const scriptSources = [...document.querySelectorAll('script[src]')]
    .map((s) => abs(s.getAttribute('src')))
    .filter((u) => u !== null);

  const inlineScripts = [...document.querySelectorAll('script:not([src])')]
    .map((s) => s.textContent || '')
    .filter((t) => t.length > 0);

  return { links: [...new Set(links)], forms, storageKeys, inlineEventHandlers,
           scriptSources: [...new Set(scriptSources)], inlineScripts };
})()`;

/**
 * Sources an attacker controls, and sinks that turn a string into behaviour.
 *
 * The pairing is what matters: `innerHTML` on a server-rendered constant is
 * fine, and on `location.hash` it is a client-side injection. So this looks
 * for both in the same script and reports the pair, which is the difference
 * between a finding and a list of every use of innerHTML on the internet.
 */
const DOM_SOURCES: readonly { readonly name: string; readonly pattern: RegExp }[] = [
  { name: 'location.hash', pattern: /location\s*\.\s*hash/ },
  { name: 'location.search', pattern: /location\s*\.\s*search/ },
  { name: 'location.href', pattern: /location\s*\.\s*href/ },
  { name: 'document.referrer', pattern: /document\s*\.\s*referrer/ },
  { name: 'window.name', pattern: /window\s*\.\s*name/ },
  { name: 'postMessage data', pattern: /addEventListener\s*\(\s*['"]message['"]/ },
  { name: 'URLSearchParams', pattern: /new\s+URLSearchParams/ },
];

const DOM_SINKS: readonly { readonly name: string; readonly pattern: RegExp; readonly severity: string }[] = [
  { name: 'innerHTML', pattern: /\.\s*innerHTML\s*=/, severity: 'high' },
  { name: 'outerHTML', pattern: /\.\s*outerHTML\s*=/, severity: 'high' },
  { name: 'document.write', pattern: /document\s*\.\s*write(?:ln)?\s*\(/, severity: 'high' },
  { name: 'insertAdjacentHTML', pattern: /\.\s*insertAdjacentHTML\s*\(/, severity: 'high' },
  { name: 'eval', pattern: /\beval\s*\(/, severity: 'high' },
  { name: 'new Function', pattern: /new\s+Function\s*\(/, severity: 'high' },
  { name: 'setTimeout with a string', pattern: /setTimeout\s*\(\s*['"]/, severity: 'medium' },
  { name: 'location assignment', pattern: /location\s*(?:\.\s*(?:href|assign|replace)\s*(?:=|\())/, severity: 'medium' },
  { name: 'jQuery html()', pattern: /\$\([^)]*\)\s*\.\s*html\s*\(/, severity: 'high' },
  { name: 'srcdoc', pattern: /\.\s*srcdoc\s*=/, severity: 'high' },
];

/** Pair sources with sinks inside one script. */
export function findDomSinks(scripts: readonly { readonly name: string; readonly text: string }[]): DomSink[] {
  const out: DomSink[] = [];
  for (const script of scripts) {
    const sources = DOM_SOURCES.filter((s) => s.pattern.test(script.text));
    if (sources.length === 0) continue;
    for (const sink of DOM_SINKS) {
      const match = sink.pattern.exec(script.text);
      if (match === null) continue;
      for (const source of sources) {
        out.push({
          sink: sink.name,
          source: source.name,
          script: script.name,
          excerpt: script.text
            .slice(Math.max(0, match.index - 80), match.index + 120)
            .replace(/\s+/g, ' '),
        });
      }
    }
  }
  return out;
}

export interface BrowseOptions {
  readonly scope: ScopeConfig;
  /** Where the proxy is listening, so every request is captured. */
  readonly proxy?: { readonly host: string; readonly port: number };
  readonly headless?: boolean;
  /**
   * A browser binary to use instead of Playwright's own download.
   *
   * Most machines that will run this already have Chrome or Chromium, and a
   * 130MB download to drive a browser that is already installed is a poor
   * trade. Playwright's bundled build is still preferred when present,
   * because its revision is known to match the client library.
   */
  readonly executablePath?: string;
  /** Entry URLs. */
  readonly entries: readonly string[];
  /** Follow same-origin links up to this many pages. */
  readonly maxPages?: number;
  /** Milliseconds to let client-side code settle after each navigation. */
  readonly settleMs?: number;
  readonly cookies?: readonly Record<string, unknown>[];
  /** A script run on the first page, for logging in. */
  readonly loginScript?: string;
  readonly onPage?: (facts: PageFacts) => void;
  readonly onLog?: (message: string) => void;
  readonly timeoutMs?: number;
}

export interface BrowseResult {
  readonly pages: readonly PageFacts[];
  readonly visited: readonly string[];
  readonly skipped: readonly { readonly url: string; readonly reason: string }[];
  /** Cookies the session ended with, for handing to replay. */
  readonly cookies: readonly Record<string, unknown>[];
}

/**
 * Walk the application with a real browser.
 *
 * Same-origin and bounded. The scope engine decides every navigation, so a
 * link to a third party is recorded as skipped rather than followed -- the
 * browser is the component most likely to wander, because pages link
 * outwards.
 */
export async function browse(options: BrowseOptions): Promise<BrowseResult> {
  const playwright = await loadPlaywright();
  const maxPages = options.maxPages ?? 10;
  const settle = options.settleMs ?? 1200;
  const timeout = options.timeoutMs ?? 20_000;

  const launchOptions: Record<string, unknown> = {
    headless: options.headless !== false,
    ...(options.proxy === undefined
      ? {}
      : { proxy: { server: `http://${options.proxy.host}:${options.proxy.port}` } }),
  };
  if (options.executablePath !== undefined) launchOptions['executablePath'] = options.executablePath;

  let browser: BrowserLike;
  try {
    browser = await playwright.chromium.launch(launchOptions);
  } catch (err) {
    const message = (err as Error).message;
    if (options.executablePath === undefined && /Executable doesn't exist/.test(message)) {
      const found = findInstalledChrome();
      if (found !== undefined) {
        options.onLog?.(`Playwright's own Chromium is not downloaded; using ${found}`);
        browser = await playwright.chromium.launch({ ...launchOptions, executablePath: found });
      } else {
        throw new Error(
          `${message}\n\nEither run \`npx playwright install chromium\`, or pass ` +
            '--browser-path pointing at a Chrome or Chromium you already have.',
        );
      }
    } else {
      throw err;
    }
  }

  // Certificate errors are ignored because the certificate is the
  // workbench's own, minted seconds earlier for this host. Trusting the CA at
  // the operating system level would work too and would leave a CA installed
  // on the machine afterwards; this way nothing outlives the process.
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) appsec-workbench Chrome/120 Safari/537.36',
  });

  if (options.cookies !== undefined && options.cookies.length > 0) {
    await context.addCookies(options.cookies);
  }

  const pages: PageFacts[] = [];
  const visited: string[] = [];
  const skipped: { url: string; reason: string }[] = [];
  const queue = [...options.entries];
  const seen = new Set<string>();
  let loginDone = false;

  try {
    while (queue.length > 0 && visited.length < maxPages) {
      const url = queue.shift() as string;
      const key = normalise(url);
      if (seen.has(key)) continue;
      seen.add(key);

      const verdict = decide(options.scope, url);
      if (verdict.verdict !== 'in-scope') {
        skipped.push({ url, reason: verdict.reason });
        continue;
      }

      const page = await context.newPage();
      const consoleErrors: string[] = [];
      page.on('console', (message: unknown) => {
        const m = message as { type?: () => string; text?: () => string };
        if (m.type?.() === 'error') consoleErrors.push((m.text?.() ?? '').slice(0, 500));
      });
      page.on('pageerror', (error: unknown) => {
        consoleErrors.push(String((error as Error).message ?? error).slice(0, 500));
      });

      try {
        options.onLog?.(`visiting ${url}`);
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout });

        if (!loginDone && options.loginScript !== undefined) {
          options.onLog?.('running the login script');
          await page.evaluate(options.loginScript);
          await page.waitForTimeout(settle);
          loginDone = true;
        }

        await page.waitForTimeout(settle);

        const collected = await page.evaluate<{
          links: string[];
          forms: FormFact[];
          storageKeys: string[];
          inlineEventHandlers: string[];
          scriptSources: string[];
          inlineScripts: string[];
        }>(COLLECT);

        const facts: PageFacts = {
          url: page.url(),
          title: await page.title(),
          links: collected.links,
          forms: collected.forms,
          storageKeys: collected.storageKeys,
          inlineEventHandlers: [...new Set(collected.inlineEventHandlers)],
          scriptSources: collected.scriptSources,
          consoleErrors: [...new Set(consoleErrors)],
          domSinks: findDomSinks(
            collected.inlineScripts.map((text, i) => ({ name: `inline script ${i}`, text })),
          ),
        };

        pages.push(facts);
        visited.push(facts.url);
        options.onPage?.(facts);

        for (const link of facts.links) {
          if (queue.length + visited.length >= maxPages * 4) break;
          if (!seen.has(normalise(link))) queue.push(link);
        }
      } catch (err) {
        skipped.push({ url, reason: (err as Error).message });
      } finally {
        await page.close();
      }
    }

    const cookies = await context.cookies();
    return { pages, visited, skipped, cookies };
  } finally {
    await context.close();
    await browser.close();
  }
}

/**
 * Where Chrome and Chromium usually are.
 *
 * Checked only as a fallback, and only for the binary -- nothing about the
 * user's own profile, extensions or cookies is touched, because the context
 * this launches is a fresh one.
 */
export function findInstalledChrome(
  candidates: readonly string[] = CHROME_CANDIDATES,
  exists: (path: string) => boolean = defaultExists,
): string | undefined {
  for (const candidate of candidates) {
    if (exists(candidate)) return candidate;
  }
  return undefined;
}

const CHROME_CANDIDATES: readonly string[] = [
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/snap/bin/chromium',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
];

function defaultExists(path: string): boolean {
  try {
    return existsSync(path);
  } catch {
    return false;
  }
}

/** Strip the fragment: it is not part of what the server sees. */
function normalise(url: string): string {
  try {
    const parsed = new URL(url);
    parsed.hash = '';
    return parsed.toString();
  } catch {
    return url;
  }
}

/**
 * Turn what the browser saw into requests worth testing.
 *
 * A form is a request nobody made yet: its action, method and field names are
 * exactly what a test needs, and a crawl that only records navigations never
 * submits one. This produces the request the form would have sent, with
 * placeholder values, so it can be handed to replay or to the active checks.
 */
export function formsToRequests(
  facts: readonly PageFacts[],
): { url: string; method: string; contentType?: string; body?: string }[] {
  const out: { url: string; method: string; contentType?: string; body?: string }[] = [];
  for (const page of facts) {
    for (const form of page.forms) {
      const fields = form.fields.filter((f) => f.name.length > 0);
      if (form.method === 'GET') {
        let url: URL;
        try {
          url = new URL(form.action);
        } catch {
          continue;
        }
        for (const f of fields) url.searchParams.set(f.name, placeholderFor(f.type));
        out.push({ url: url.toString(), method: 'GET' });
        continue;
      }
      const params = new URLSearchParams();
      for (const f of fields) params.set(f.name, placeholderFor(f.type));
      out.push({
        url: form.action,
        method: form.method,
        contentType: 'application/x-www-form-urlencoded',
        body: params.toString(),
      });
    }
  }
  return out;
}

/**
 * A plausible value per input type.
 *
 * Plausible matters: a field validated as an email address rejects "test" at
 * the edge and the request never reaches the code under test, so the whole
 * point of enumerating the form is lost.
 */
function placeholderFor(type: string): string {
  switch (type.toLowerCase()) {
    case 'email':
      return 'awb-probe@example.invalid';
    case 'number':
    case 'range':
      return '1';
    case 'tel':
      return '+15550100';
    case 'url':
      return 'https://example.invalid/';
    case 'date':
      return '2026-01-01';
    case 'datetime-local':
      return '2026-01-01T00:00';
    case 'month':
      return '2026-01';
    case 'time':
      return '00:00';
    case 'checkbox':
    case 'radio':
      return 'on';
    case 'password':
      return 'awb-probe-value';
    case 'hidden':
      // A hidden field is usually a token the application needs intact; the
      // caller should overwrite it from the page it was read from.
      return '';
    default:
      return 'awbprobe';
  }
}
