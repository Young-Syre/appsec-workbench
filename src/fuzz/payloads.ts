import { createHash } from 'node:crypto';

/**
 * Payload sources and the processing applied to them.
 *
 * Generators are lazy. A cluster-bomb attack over two 10,000-entry lists is
 * a hundred million requests, and the right behaviour when somebody asks for
 * that is to refuse with the number in the message, not to allocate the list
 * and die. So every source reports its length up front and yields values one
 * at a time.
 *
 * The built-in sets are deliberately small and diagnostic. They exist to tell
 * you whether a parameter is interesting, not to exploit it: a canary to see
 * if input is reflected, a quote to see if an error leaks, a traversal prefix
 * to see if a path is resolved. Anything that would modify or destroy data is
 * not here, and a wordlist that is really someone else's research belongs in
 * a file you point at rather than vendored into a repository.
 */

export interface PayloadSource {
  readonly name: string;
  /** How many values this will yield. */
  readonly length: number;
  values(): Generator<string>;
}

export function listSource(values: readonly string[], name = 'list'): PayloadSource {
  return {
    name,
    length: values.length,
    *values() {
      for (const v of values) yield v;
    },
  };
}

/** A numeric range, which is what an identifier-enumeration test needs. */
export function numberSource(from: number, to: number, step = 1): PayloadSource {
  if (step === 0) throw new Error('number payload step cannot be zero');
  const count = Math.floor((to - from) / step) + 1;
  if (count <= 0) throw new Error(`number range ${from}..${to} step ${step} yields nothing`);
  return {
    name: `numbers ${from}..${to} step ${step}`,
    length: count,
    *values() {
      for (let i = 0; i < count; i += 1) yield String(from + i * step);
    },
  };
}

/** Every string of a given length over a character set. Grows fast; bounded. */
export function bruteSource(charset: string, length: number, limit = 1_000_000): PayloadSource {
  const chars = [...new Set([...charset])];
  const total = chars.length ** length;
  if (total > limit) {
    throw new Error(
      `brute force over ${chars.length} characters at length ${length} is ${total.toLocaleString()} ` +
        `values, above the ${limit.toLocaleString()} limit. Narrow the charset or shorten the length.`,
    );
  }
  return {
    name: `brute ${chars.length}^${length}`,
    length: total,
    *values() {
      const indices = new Array<number>(length).fill(0);
      for (let n = 0; n < total; n += 1) {
        yield indices.map((i) => chars[i] as string).join('');
        for (let pos = length - 1; pos >= 0; pos -= 1) {
          indices[pos] = (indices[pos] as number) + 1;
          if ((indices[pos] as number) < chars.length) break;
          indices[pos] = 0;
        }
      }
    },
  };
}

export function fileSource(contents: string, name = 'file'): PayloadSource {
  const lines = contents
    .split(/\r?\n/)
    .filter((l) => l.length > 0 && !l.startsWith('#'));
  return listSource(lines, name);
}

/**
 * Case permutations of one value.
 *
 * For filter bypasses where the check is case-sensitive and the sink is not,
 * which is a surprisingly durable bug in hand-written denylists.
 */
export function caseSource(value: string, limit = 4096): PayloadSource {
  const letters = [...value].map((c, i) => [c, i] as const).filter(([c]) => /[a-z]/i.test(c));
  const total = 2 ** letters.length;
  if (total > limit) {
    throw new Error(
      `${value} has ${letters.length} letters, giving ${total.toLocaleString()} case permutations, ` +
        `above the ${limit.toLocaleString()} limit`,
    );
  }
  return {
    name: `case permutations of ${value}`,
    length: total,
    *values() {
      for (let mask = 0; mask < total; mask += 1) {
        const chars = [...value];
        letters.forEach(([, index], bit) => {
          const c = chars[index] as string;
          chars[index] = (mask >> bit) & 1 ? c.toUpperCase() : c.toLowerCase();
        });
        yield chars.join('');
      }
    },
  };
}

// ---- processing -----------------------------------------------------------

export type Processor =
  | { readonly kind: 'url-encode'; readonly all?: boolean }
  | { readonly kind: 'url-encode-twice' }
  | { readonly kind: 'base64' }
  | { readonly kind: 'html-entity' }
  | { readonly kind: 'prefix'; readonly value: string }
  | { readonly kind: 'suffix'; readonly value: string }
  | { readonly kind: 'upper' }
  | { readonly kind: 'lower' }
  | { readonly kind: 'reverse' }
  | { readonly kind: 'hash'; readonly algorithm: 'md5' | 'sha1' | 'sha256' };

export function parseProcessor(text: string): Processor {
  const eq = text.indexOf('=');
  const kind = eq < 0 ? text : text.slice(0, eq);
  const value = eq < 0 ? undefined : text.slice(eq + 1);
  switch (kind) {
    case 'url-encode':
      return { kind: 'url-encode' };
    case 'url-encode-all':
      return { kind: 'url-encode', all: true };
    case 'url-encode-twice':
      return { kind: 'url-encode-twice' };
    case 'base64':
      return { kind: 'base64' };
    case 'html-entity':
      return { kind: 'html-entity' };
    case 'upper':
      return { kind: 'upper' };
    case 'lower':
      return { kind: 'lower' };
    case 'reverse':
      return { kind: 'reverse' };
    case 'prefix':
    case 'suffix': {
      if (value === undefined) throw new Error(`${kind} needs a value, as in ${kind}=../`);
      return kind === 'prefix' ? { kind: 'prefix', value } : { kind: 'suffix', value };
    }
    case 'md5':
    case 'sha1':
    case 'sha256':
      return { kind: 'hash', algorithm: kind };
    default:
      throw new Error(
        `unknown processor ${JSON.stringify(kind)}. Known: url-encode, url-encode-all, ` +
          'url-encode-twice, base64, html-entity, upper, lower, reverse, prefix=, suffix=, ' +
          'md5, sha1, sha256.',
      );
  }
}

export function applyProcessors(value: string, processors: readonly Processor[]): string {
  let out = value;
  for (const p of processors) out = applyProcessor(out, p);
  return out;
}

function applyProcessor(value: string, p: Processor): string {
  switch (p.kind) {
    case 'url-encode':
      return p.all === true ? encodeEveryByte(value) : encodeURIComponent(value);
    case 'url-encode-twice':
      return encodeURIComponent(encodeURIComponent(value));
    case 'base64':
      return Buffer.from(value, 'utf8').toString('base64');
    case 'html-entity':
      return [...value].map((c) => `&#${c.codePointAt(0) ?? 0};`).join('');
    case 'prefix':
      return p.value + value;
    case 'suffix':
      return value + p.value;
    case 'upper':
      return value.toUpperCase();
    case 'lower':
      return value.toLowerCase();
    case 'reverse':
      return [...value].reverse().join('');
    case 'hash':
      return createHash(p.algorithm).update(value, 'utf8').digest('hex');
    default: {
      const exhaustive: never = p;
      return exhaustive;
    }
  }
}

/** Percent-encode every byte, which defeats filters that decode once. */
function encodeEveryByte(value: string): string {
  return [...Buffer.from(value, 'utf8')]
    .map((b) => `%${b.toString(16).padStart(2, '0').toUpperCase()}`)
    .join('');
}

// ---- built-in sets --------------------------------------------------------

/**
 * A canary: a value unlikely to occur naturally, used to find out whether
 * input reaches the response at all. Everything else is a follow-up to this.
 */
export function canary(seed = ''): string {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const base = seed.length > 0 ? seed : Math.random().toString(36).slice(2, 8);
  let out = 'awb';
  for (const ch of base) out += alphabet[ch.charCodeAt(0) % alphabet.length] as string;
  return out.slice(0, 12);
}

export interface BuiltinSet {
  readonly id: string;
  readonly description: string;
  readonly values: readonly string[];
}

/**
 * The built-in probe sets.
 *
 * Each one answers a yes/no question about a parameter. None of them tries to
 * exploit anything, none writes data, and none is longer than it needs to be:
 * a 2,000-entry list makes a tool look thorough and makes a report look like
 * it was generated, because the interesting entry is lost among the rest.
 */
export const BUILTIN_SETS: readonly BuiltinSet[] = [
  {
    id: 'quote-probe',
    description:
      'Does a quote reach a query parser? A difference between the balanced and ' +
      'unbalanced forms is the signal; an error message is a bonus, not the test.',
    values: ["'", "''", '"', '""', "\\'", '`', "')", "'))", "' ", "'--"],
  },
  {
    id: 'boolean-probe',
    description:
      'Two values that should be equivalent and two that should not. A response that ' +
      'tracks the logic rather than the literal says the input reached a condition.',
    values: ["' AND '1'='1", "' AND '1'='2", ' AND 1=1', ' AND 1=2', "' OR '1'='1", "' OR '1'='2"],
  },
  {
    id: 'traversal-probe',
    description:
      'Is a path parameter resolved against a filesystem? The encodings are included ' +
      'because a filter that decodes once and a resolver that decodes twice disagree.',
    values: [
      '../',
      '../../',
      '....//',
      '..%2f',
      '%2e%2e%2f',
      '%252e%252e%252f',
      '..%c0%af',
      '/etc/passwd',
      'C:\\Windows\\win.ini',
    ],
  },
  {
    id: 'template-probe',
    description:
      'Server-side template evaluation. Each value is an arithmetic expression whose ' +
      'result in the response is unambiguous evidence, and which changes nothing.',
    values: ['{{7*7}}', '${7*7}', '#{7*7}', '{7*7}', '<%= 7*7 %>', '${{7*7}}', '@(7*7)', '#{ 7*7 }'],
  },
  {
    id: 'auth-bypass-headers',
    description:
      'Headers a reverse proxy may trust from the client. Sent as values a backend ' +
      'would treat as internal, to see whether an edge rule is doing the authorising.',
    values: [
      '127.0.0.1',
      'localhost',
      '[::1]',
      '127.0.0.1, 8.8.8.8',
      '0177.0.0.1',
      '2130706433',
    ],
  },
  {
    id: 'http-methods',
    description:
      'Methods other than the one observed. A route authorised for GET and reachable ' +
      'by PUT is an authorisation defect, and the check costs one request each.',
    values: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'PROPFIND'],
  },
  {
    id: 'null-and-empty',
    description:
      'The values that break assumptions about presence: absent, empty, null, an array ' +
      'where a scalar was expected, and the type confusions those enable.',
    values: ['', 'null', 'NULL', 'undefined', '0', 'false', '[]', '{}', '[null]'],
  },
  {
    id: 'content-types',
    description:
      'Alternative request content types for the same body, which frequently reach a ' +
      'different parser and therefore a different code path.',
    values: [
      'application/json',
      'application/x-www-form-urlencoded',
      'text/plain',
      'application/xml',
      'text/xml',
      'application/json; charset=utf-7',
      'application/x-www-form-urlencoded; charset=utf-8',
    ],
  },
];

export function builtinSet(id: string): PayloadSource {
  const found = BUILTIN_SETS.find((s) => s.id === id);
  if (found === undefined) {
    throw new Error(
      `unknown payload set ${JSON.stringify(id)}. Available: ${BUILTIN_SETS.map((s) => s.id).join(', ')}`,
    );
  }
  return listSource(found.values, found.id);
}

/**
 * Parse the CLI's payload shorthand.
 *
 *   list:a,b,c
 *   numbers:1-100
 *   numbers:0-1000:10
 *   brute:abc:3
 *   case:select
 *   set:traversal-probe
 *   file:/path/to/words.txt     (read by the caller and passed as `file:` text)
 */
export function parsePayloadSpec(
  spec: string,
  readFile?: (path: string) => string,
): PayloadSource {
  const colon = spec.indexOf(':');
  if (colon < 0) throw new Error(`payload spec ${JSON.stringify(spec)} needs a kind, as in set:quote-probe`);
  const kind = spec.slice(0, colon);
  const rest = spec.slice(colon + 1);

  switch (kind) {
    case 'list':
      return listSource(rest.split(',').map((v) => v.trim()));
    case 'numbers': {
      const parts = rest.split(':');
      const range = (parts[0] ?? '').split('-');
      const from = Number(range[0]);
      const to = Number(range[1]);
      if (!Number.isFinite(from) || !Number.isFinite(to)) {
        throw new Error(`numbers payload needs a range, as in numbers:1-100 (got ${JSON.stringify(rest)})`);
      }
      return numberSource(from, to, parts[1] === undefined ? 1 : Number(parts[1]));
    }
    case 'brute': {
      const parts = rest.split(':');
      const charset = parts[0] ?? '';
      const length = Number(parts[1] ?? 1);
      if (charset.length === 0 || !Number.isInteger(length)) {
        throw new Error('brute payload needs a charset and a length, as in brute:abc:3');
      }
      return bruteSource(charset, length);
    }
    case 'case':
      return caseSource(rest);
    case 'set':
      return builtinSet(rest);
    case 'file': {
      if (readFile === undefined) throw new Error('file: payloads are not available here');
      return fileSource(readFile(rest), `file:${rest}`);
    }
    default:
      throw new Error(
        `unknown payload kind ${JSON.stringify(kind)}. Known: list, numbers, brute, case, set, file.`,
      );
  }
}
