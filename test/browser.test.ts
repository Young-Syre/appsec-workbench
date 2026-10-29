import { strict as assert } from 'node:assert';
import { createServer, type Server } from 'node:http';
import { join } from 'node:path';
import test, { after, before, describe } from 'node:test';

import {
  browse,
  findDomSinks,
  findInstalledChrome,
  formsToRequests,
  loadPlaywright,
} from '../src/browser/drive.js';
import { Proxy } from '../src/proxy/server.js';
import { createCa, caPaths } from '../src/proxy/ca.js';
import { parseScopeConfig } from '../src/core/scope.js';
import type { Exchange } from '../src/core/message.js';
import { tempDir } from './helpers.js';

/**
 * Is any Chromium available? Downloading one inside a test is not on.
 *
 * Tries Playwright's own build first and an installed Chrome second, which is
 * the same order the tool itself uses.
 */
async function chromiumAvailable(): Promise<string | undefined | false> {
  const playwright = await loadPlaywright().catch(() => undefined);
  if (playwright === undefined) return false;
  try {
    const browser = await playwright.chromium.launch({ headless: true });
    await browser.close();
    return undefined; // the bundled build works; no executablePath needed
  } catch {
    const found = findInstalledChrome();
    if (found === undefined) return false;
    try {
      const browser = await playwright.chromium.launch({ headless: true, executablePath: found });
      await browser.close();
      return found;
    } catch {
      return false;
    }
  }
}

describe('DOM sink analysis pairs a source with a sink', () => {
  test('a URL fragment reaching innerHTML is reported', () => {
    const sinks = findDomSinks([
      { name: 'app.js', text: 'const t = location.hash.slice(1); el.innerHTML = t;' },
    ]);
    assert.equal(sinks.length, 1);
    assert.equal(sinks[0]?.sink, 'innerHTML');
    assert.equal(sinks[0]?.source, 'location.hash');
    assert.ok((sinks[0]?.excerpt ?? '').includes('innerHTML'));
  });

  test('a sink with no attacker-controlled source is not reported', () => {
    // This is the whole reason the pairing exists: innerHTML on a constant is
    // every application on the internet.
    assert.deepEqual(findDomSinks([{ name: 'a.js', text: 'el.innerHTML = "<b>hello</b>";' }]), []);
  });

  test('a source with no sink is not reported', () => {
    assert.deepEqual(
      findDomSinks([{ name: 'a.js', text: 'const page = new URLSearchParams(location.search).get("p");' }]),
      [],
    );
  });

  test('a message listener counts as a source', () => {
    const sinks = findDomSinks([
      {
        name: 'a.js',
        text: 'window.addEventListener("message", (e) => { document.body.innerHTML = e.data; });',
      },
    ]);
    assert.equal(sinks[0]?.source, 'postMessage data');
  });

  test('several sinks in one script are each reported', () => {
    const sinks = findDomSinks([
      { name: 'a.js', text: 'const h = location.hash; eval(h); document.write(h);' },
    ]);
    assert.deepEqual(new Set(sinks.map((s) => s.sink)), new Set(['eval', 'document.write']));
  });

  test('jQuery html() is recognised', () => {
    const sinks = findDomSinks([
      { name: 'a.js', text: '$("#out").html(location.search);' },
    ]);
    assert.equal(sinks[0]?.sink, 'jQuery html()');
  });

  test('sinks in separate scripts are not paired across them', () => {
    assert.deepEqual(
      findDomSinks([
        { name: 'a.js', text: 'const h = location.hash;' },
        { name: 'b.js', text: 'el.innerHTML = "constant";' },
      ]),
      [],
    );
  });
});

describe('forms become requests worth testing', () => {
  test('a GET form becomes a URL with its fields as parameters', () => {
    const requests = formsToRequests([
      {
        url: 'https://t.example/',
        title: '',
        links: [],
        forms: [
          {
            action: 'https://t.example/search',
            method: 'GET',
            fields: [
              { name: 'q', type: 'text' },
              { name: 'page', type: 'number' },
            ],
          },
        ],
        storageKeys: [],
        inlineEventHandlers: [],
        scriptSources: [],
        consoleErrors: [],
        domSinks: [],
      },
    ]);
    assert.equal(requests.length, 1);
    const url = new URL(requests[0]?.url ?? '');
    assert.equal(url.searchParams.get('q'), 'awbprobe');
    assert.equal(url.searchParams.get('page'), '1', 'a number field needs a number');
  });

  test('a POST form becomes an urlencoded body with type-appropriate values', () => {
    const requests = formsToRequests([
      {
        url: 'https://t.example/',
        title: '',
        links: [],
        forms: [
          {
            action: 'https://t.example/register',
            method: 'POST',
            fields: [
              { name: 'email', type: 'email' },
              { name: 'website', type: 'url' },
              { name: 'dob', type: 'date' },
            ],
          },
        ],
        storageKeys: [],
        inlineEventHandlers: [],
        scriptSources: [],
        consoleErrors: [],
        domSinks: [],
      },
    ]);
    const body = new URLSearchParams(requests[0]?.body ?? '');
    assert.equal(requests[0]?.method, 'POST');
    assert.equal(requests[0]?.contentType, 'application/x-www-form-urlencoded');
    assert.match(body.get('email') ?? '', /@/, 'an email field validated at the edge needs an email');
    assert.match(body.get('website') ?? '', /^https:/);
    assert.equal(body.get('dob'), '2026-01-01');
  });

  test('unnamed fields are dropped, because they are not submitted', () => {
    const requests = formsToRequests([
      {
        url: 'https://t.example/',
        title: '',
        links: [],
        forms: [{ action: 'https://t.example/a', method: 'POST', fields: [{ name: '', type: 'text' }] }],
        storageKeys: [],
        inlineEventHandlers: [],
        scriptSources: [],
        consoleErrors: [],
        domSinks: [],
      },
    ]);
    assert.equal(requests[0]?.body, '');
  });
});

describe('a real browser driven through the proxy', () => {
  let available: string | undefined | false = false;
  let app: Server;
  let appPort = 0;
  let proxy: Proxy;
  let captured: Exchange[];

  before(async () => {
    available = await chromiumAvailable();
    if (available === false) return;

    app = createServer((req, res) => {
      const path = (req.url ?? '/').split('?')[0];
      if (path === '/') {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end(
          `<html><head><title>Workbench fixture</title></head><body>
            <a href="/second">second</a>
            <a href="https://third-party.invalid/x">offsite</a>
            <form action="/search" method="GET"><input name="q" type="text"></form>
            <div id="out"></div>
            <script>
              localStorage.setItem('auth_token', 'should-not-be-collected');
              var frag = location.hash.slice(1);
              document.getElementById('out').innerHTML = frag;
              fetch('/api/data');
            </script>
          </body></html>`,
        );
        return;
      }
      if (path === '/second') {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end('<html><head><title>Second</title></head><body><p>second page</p></body></html>');
        return;
      }
      if (path === '/api/data') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{"ok":true}');
        return;
      }
      res.writeHead(404, { 'content-type': 'text/html' });
      res.end('<html><body>nope</body></html>');
    });
    await new Promise<void>((resolve) => app.listen(0, '127.0.0.1', resolve));
    const addr = app.address();
    appPort = typeof addr === 'object' && addr !== null ? addr.port : 0;

    const caDir = join(tempDir(), 'ca');
    createCa(caDir);
    captured = [];
    proxy = new Proxy({
      port: 0,
      scope: parseScopeConfig({ include: [`http://127.0.0.1:${appPort}`] }),
      ca: caPaths(caDir),
      onExchange: (e) => captured.push(e),
    });
    await proxy.listen();
  });

  after(async () => {
    if (available === false) return;
    await proxy.close();
    await new Promise<void>((resolve) => app.close(() => resolve()));
  });

  test('pages are visited, facts collected, and offsite links refused', async (t) => {
    if (available === false) {
      t.skip('no Chromium available; run `npx playwright install chromium`');
      return;
    }

    const result = await browse({
      scope: parseScopeConfig({ include: [`http://127.0.0.1:${appPort}`] }),
      proxy: { host: '127.0.0.1', port: proxy.port },
      entries: [`http://127.0.0.1:${appPort}/`],
      maxPages: 3,
      settleMs: 600,
      headless: true,
      ...(available === undefined ? {} : { executablePath: available }),
    });

    assert.ok(result.pages.length >= 2, `expected to follow the link, visited ${result.visited.length}`);
    assert.equal(result.pages[0]?.title, 'Workbench fixture');

    assert.ok(
      result.skipped.some((s) => s.url.includes('third-party.invalid')),
      'the offsite link must be refused by scope, not followed',
    );
  });

  test('every browser request landed in the capture, including the fetch', async (t) => {
    if (available === false) {
      t.skip('no Chromium available');
      return;
    }
    const paths = captured.map((e) => new URL(e.request.url).pathname);
    assert.ok(paths.includes('/'), 'the document');
    assert.ok(paths.includes('/api/data'), 'the XHR the bundle issued, which a fetch-crawler never sees');
  });

  test('forms and storage keys are collected, and storage values are not', async (t) => {
    if (available === false) {
      t.skip('no Chromium available');
      return;
    }
    const result = await browse({
      scope: parseScopeConfig({ include: [`http://127.0.0.1:${appPort}`] }),
      proxy: { host: '127.0.0.1', port: proxy.port },
      entries: [`http://127.0.0.1:${appPort}/`],
      maxPages: 1,
      settleMs: 600,
      ...(available === undefined ? {} : { executablePath: available }),
    });
    const page = result.pages[0];
    assert.ok(page !== undefined);
    assert.equal(page.forms.length, 1);
    assert.equal(page.forms[0]?.fields[0]?.name, 'q');
    assert.ok(page.storageKeys.includes('localStorage:auth_token'));
    assert.ok(
      !JSON.stringify(page).includes('should-not-be-collected'),
      'storage values are credentials often enough that only the keys are collected',
    );
  });

  test('a DOM sink in an inline script is found in the live page', async (t) => {
    if (available === false) {
      t.skip('no Chromium available');
      return;
    }
    const result = await browse({
      scope: parseScopeConfig({ include: [`http://127.0.0.1:${appPort}`] }),
      proxy: { host: '127.0.0.1', port: proxy.port },
      entries: [`http://127.0.0.1:${appPort}/`],
      maxPages: 1,
      settleMs: 600,
      ...(available === undefined ? {} : { executablePath: available }),
    });
    const sinks = result.pages[0]?.domSinks ?? [];
    assert.ok(
      sinks.some((s) => s.sink === 'innerHTML' && s.source === 'location.hash'),
      `expected the hash-to-innerHTML pair, got ${JSON.stringify(sinks)}`,
    );
  });
});
