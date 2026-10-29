/**
 * The intercept console: one held message on screen, one keystroke to decide.
 *
 *   f / enter   forward as shown
 *   e           edit in $EDITOR, then forward the edit
 *   d           drop
 *   i           interception on or off (off releases everything waiting)
 *   r           response interception on or off
 *   ?           the key list again
 *
 * The console owns the terminal while it runs, so it also owns the log: a
 * line printed into the middle of somebody's editor session corrupts the
 * screen they are editing on, so lines arriving during an edit are held and
 * printed when the editor exits.
 *
 * What is shown is redacted in the same way the proxy log is, unless
 * `--unsafe-show-secrets` was given. The editor is handed the real bytes,
 * because a request cannot be edited through a redaction.
 */

import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { emitKeypressEvents } from 'node:readline';

import {
  type HttpRequest,
  type HttpResponse,
  isTextual,
  parseRawResponse,
  serialiseRequest,
  serialiseResponse,
} from '../core/message.js';
import { decodeBody } from '../core/encoding.js';
import { observedSecrets, redactHeaders, redactText } from '../core/redact.js';
import {
  type Held,
  type Interceptor,
  lengthMismatch,
  stripEditorNewline,
  withFixedLength,
} from '../proxy/intercept.js';
import { fromEditable, toEditable } from '../replay/replay.js';

/** Opens text in an editor and returns what was saved, or undefined if it failed. */
export type Editor = (text: string, suffix: string) => Promise<string | undefined>;

export interface ConsoleIo {
  readonly write: (text: string) => void;
  readonly edit: Editor;
}

export interface ConsoleOptions {
  readonly showSecrets?: boolean;
  /** Body lines shown before the view is cut short. */
  readonly bodyLines?: number;
}

type Mode =
  | { readonly kind: 'idle' }
  | { readonly kind: 'editing' }
  | { readonly kind: 'confirm-length'; readonly id: number; readonly edited: HttpRequest };

const KEYS =
  '[f]orward  [e]dit  [d]rop  [i]ntercept on/off  [r]esponses on/off  [?] keys';

export class InterceptConsole {
  private readonly interceptor: Interceptor;
  private readonly io: ConsoleIo;
  private readonly options: ConsoleOptions;
  private mode: Mode = { kind: 'idle' };
  private shownId: number | undefined;
  private readonly deferred: string[] = [];

  constructor(interceptor: Interceptor, io: ConsoleIo, options: ConsoleOptions = {}) {
    this.interceptor = interceptor;
    this.io = io;
    this.options = options;
    interceptor.on('held', () => {
      if (this.mode.kind === 'idle' && this.shownId === undefined) this.showHead();
      else this.status();
    });
    interceptor.on('settled', (held: Held) => {
      if (held.id === this.shownId) {
        this.shownId = undefined;
        if (this.mode.kind === 'confirm-length' && this.mode.id === held.id) {
          this.mode = { kind: 'idle' };
        }
        if (this.mode.kind === 'idle') this.showHead();
      }
    });
  }

  /** A log line, held back while an editor has the screen. */
  log(line: string): void {
    if (this.mode.kind === 'editing') this.deferred.push(line);
    else this.io.write(`${line}\n`);
  }

  /** Draw the oldest held message, or say nothing is waiting. */
  showHead(): void {
    const head = this.interceptor.head();
    if (head === undefined) {
      this.shownId = undefined;
      return;
    }
    this.shownId = head.id;
    this.io.write(this.render(head));
  }

  /**
   * One keystroke. Returns once whatever it started has finished, which for
   * an edit means after the editor has exited -- a test can await it.
   */
  async key(name: string): Promise<void> {
    if (this.mode.kind === 'editing') return;

    if (this.mode.kind === 'confirm-length') {
      const { id, edited } = this.mode;
      if (name === 'f' || name === 'return') {
        this.mode = { kind: 'idle' };
        this.interceptor.forward(id, edited);
      } else if (name === 'l') {
        this.mode = { kind: 'idle' };
        this.interceptor.forward(id, withFixedLength(edited));
      } else if (name === 'e') {
        this.mode = { kind: 'idle' };
        await this.editRequest(id, edited);
      } else if (name === 'd') {
        this.mode = { kind: 'idle' };
        this.interceptor.drop(id);
      }
      return;
    }

    switch (name) {
      case 'i': {
        const on = !this.interceptor.interceptingRequests;
        this.interceptor.setRequests(on);
        this.log(`request interception ${on ? 'on' : 'off'}${on ? '' : ' -- everything waiting was forwarded'}`);
        return;
      }
      case 'r': {
        const on = !this.interceptor.interceptingResponses;
        this.interceptor.setResponses(on);
        this.log(`response interception ${on ? 'on' : 'off'}`);
        return;
      }
      case '?':
        this.log(KEYS);
        return;
      default:
        break;
    }

    const head = this.interceptor.queue().find((h) => h.id === this.shownId);
    if (head === undefined) return;

    switch (name) {
      case 'f':
      case 'return':
        this.interceptor.forward(head.id);
        return;
      case 'd':
        this.interceptor.drop(head.id);
        return;
      case 'e':
        if (head.kind === 'request') await this.editRequest(head.id, head.request);
        else await this.editResponse(head.id, head.response);
        return;
      default:
        return;
    }
  }

  private async editRequest(id: number, request: HttpRequest): Promise<void> {
    const written = toEditable(request);
    const saved = await this.withEditor(written, '.http');
    if (saved === undefined) {
      this.log('the edit was abandoned; the request is still held');
      this.redraw(id);
      return;
    }
    let edited: HttpRequest;
    try {
      edited = fromEditable(stripEditorNewline(written, saved), new URL(request.url).origin);
    } catch (err) {
      this.log(`that is not a request (${(err as Error).message}); the original is still held`);
      this.redraw(id);
      return;
    }
    if (!this.interceptor.queue().some((h) => h.id === id)) {
      this.log('the request left the queue while it was being edited (timed out or abandoned); the edit was not sent');
      this.showHead();
      return;
    }
    const mismatch = lengthMismatch(edited);
    if (mismatch !== undefined) {
      this.mode = { kind: 'confirm-length', id, edited };
      this.io.write(
        `Content-Length says ${mismatch.declared} and the body is ${mismatch.actual} bytes.\n` +
          '[f]orward as edited  [l] correct the length and forward  [e]dit again  [d]rop\n',
      );
      return;
    }
    this.interceptor.forward(id, edited);
  }

  private async editResponse(id: number, response: HttpResponse): Promise<void> {
    // The body is decoded for editing: nobody can edit gzip in a text
    // editor. The proxy recomputes framing for the browser in any case, so
    // the encoding header goes with it.
    const decoded = decodeBody(response.headers, response.body);
    const undid = decoded.codings.length > 0 && decoded.error === undefined;
    const plain: HttpResponse = {
      ...response,
      headers: response.headers.filter(([k]) => {
        const lower = k.toLowerCase();
        return !(undid && lower === 'content-encoding') && lower !== 'transfer-encoding';
      }),
      body: decoded.body,
    };
    const written = serialiseResponse(plain);
    const saved = await this.withEditor(written, '.http');
    if (saved === undefined) {
      this.log('the edit was abandoned; the response is still held');
      this.redraw(id);
      return;
    }
    try {
      this.interceptor.forward(id, parseRawResponse(stripEditorNewline(written, saved), response.elapsedMs));
    } catch (err) {
      this.log(`that is not a response (${(err as Error).message}); the original is still held`);
      this.redraw(id);
    }
  }

  private async withEditor(text: string, suffix: string): Promise<string | undefined> {
    this.mode = { kind: 'editing' };
    try {
      return await this.io.edit(text, suffix);
    } finally {
      this.mode = { kind: 'idle' };
      for (const line of this.deferred.splice(0)) this.io.write(`${line}\n`);
    }
  }

  private redraw(id: number): void {
    const held = this.interceptor.queue().find((h) => h.id === id);
    if (held === undefined) this.showHead();
    else this.io.write(this.render(held));
  }

  private status(): void {
    if (this.mode.kind === 'editing') return;
    this.io.write(`  (${this.interceptor.size} held)\n`);
  }

  render(held: Held): string {
    const waiting = this.interceptor.size;
    const rule = `-- ${held.kind} #${held.id} -- ${waiting} held `.padEnd(72, '-');
    const text =
      held.kind === 'request'
        ? this.messageText(serialiseRequestHead(held.request, this.options.showSecrets), held.request.headers, held.request.body, held.request.headers)
        : this.messageText(
            serialiseResponseHead(held.response, this.options.showSecrets),
            held.response.headers,
            held.response.body,
            held.request.headers,
          );
    const target = held.kind === 'response' ? `  for ${held.request.method} ${this.scrub(held.request.url, held.request.headers)}\n` : '';
    return `\n${rule}\n${target}${text}\n${KEYS}\n`;
  }

  private messageText(
    head: string,
    headers: HttpRequest['headers'],
    body: Buffer,
    credentialSource: HttpRequest['headers'],
  ): string {
    let shown = '';
    if (body.length > 0) {
      const decoded = decodeBody(headers, body);
      if (isTextual(headers) || looksLikeText(decoded.body)) {
        const lines = decoded.body.toString('utf8').split('\n');
        const max = this.options.bodyLines ?? 30;
        shown = lines.slice(0, max).join('\n');
        if (lines.length > max) shown += `\n... ${lines.length - max} more lines (e shows all of it)`;
      } else {
        shown = `(${body.length} bytes, not text)`;
      }
    }
    return this.scrub(`${head}\r\n\r\n${shown}`, credentialSource);
  }

  private scrub(text: string, credentialSource: HttpRequest['headers']): string {
    if (this.options.showSecrets === true) return text;
    return redactText(text, { extraValues: observedSecrets(credentialSource) });
  }
}

function serialiseRequestHead(request: HttpRequest, showSecrets = false): string {
  const headers = showSecrets ? request.headers : redactHeaders(request.headers);
  const full = serialiseRequest({ ...request, headers, body: Buffer.alloc(0) });
  return full.replace(/\r\n\r\n$/, '');
}

function serialiseResponseHead(response: HttpResponse, showSecrets = false): string {
  const headers = showSecrets ? response.headers : redactHeaders(response.headers);
  const full = serialiseResponse({ ...response, headers, body: Buffer.alloc(0) });
  return full.replace(/\r\n\r\n$/, '');
}

function looksLikeText(body: Buffer): boolean {
  const sample = body.subarray(0, 512);
  for (const byte of sample) {
    if (byte === 0) return false;
  }
  return true;
}

/**
 * The editor everyone expects: `$VISUAL`, then `$EDITOR`, then `vi`.
 *
 * The file lives in a private temporary directory and is removed whether or
 * not the edit succeeds, since it holds the request's real credentials.
 */
export function systemEditor(env: NodeJS.ProcessEnv = process.env): Editor {
  return async (text, suffix) => {
    const dir = mkdtempSync(join(tmpdir(), 'awb-intercept-'));
    const file = join(dir, `held${suffix}`);
    try {
      writeFileSync(file, text, { mode: 0o600 });
      const command = env.VISUAL ?? env.EDITOR ?? 'vi';
      const code = await new Promise<number | null>((resolve) => {
        // Through a shell, because $EDITOR is routinely `code --wait` or
        // `emacsclient -t` and splitting it ourselves would get quoting wrong.
        const child = spawn(`${command} "$AWB_FILE"`, {
          shell: true,
          stdio: 'inherit',
          env: { ...env, AWB_FILE: file },
        });
        child.on('exit', (c) => resolve(c));
        child.on('error', () => resolve(null));
      });
      if (code !== 0) return undefined;
      return readFileSync(file, 'utf8');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };
}

/**
 * Attach a console to the real terminal. Returns a function that detaches it.
 *
 * Raw mode is switched off while an editor runs, since the editor needs the
 * terminal in whatever mode it wants, and restored afterwards.
 */
export function attachToTerminal(
  console_: InterceptConsole,
  stdin: NodeJS.ReadStream,
  onInterrupt: () => void,
): () => void {
  emitKeypressEvents(stdin);
  const setRaw = (on: boolean): void => {
    if (stdin.isTTY) stdin.setRawMode(on);
  };
  setRaw(true);
  stdin.resume();
  let busy = false;
  const onKey = (str: string | undefined, key: { name?: string; ctrl?: boolean } | undefined): void => {
    if (key?.ctrl === true && key.name === 'c') {
      onInterrupt();
      return;
    }
    if (busy) return;
    const name = key?.name ?? str ?? '';
    if (name === 'e') {
      busy = true;
      setRaw(false);
      stdin.pause();
      void console_.key(name).finally(() => {
        setRaw(true);
        stdin.resume();
        busy = false;
      });
      return;
    }
    void console_.key(name === '?' || str === '?' ? '?' : name);
  };
  stdin.on('keypress', onKey);
  return () => {
    stdin.removeListener('keypress', onKey);
    setRaw(false);
    stdin.pause();
  };
}
