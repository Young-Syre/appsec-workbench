/**
 * Argument parsing.
 *
 * Node has `util.parseArgs` and it is almost right. What it does not do is
 * reject an unknown option: it either throws a message that does not say what
 * to use instead, or silently collects it as positional. For a tool whose
 * options decide whether traffic is sent to somebody's production service,
 * `--max-request 10` quietly meaning "no limit" is not acceptable, so this
 * knows its own option names and refuses anything else by name.
 */

export interface OptionSpec {
  readonly type: 'string' | 'boolean' | 'number';
  /** May be repeated; collected into an array. */
  readonly multiple?: boolean;
  readonly short?: string;
  readonly describe: string;
  readonly placeholder?: string;
}

export type Specs = Record<string, OptionSpec>;

export interface Parsed {
  readonly positionals: readonly string[];
  readonly options: Record<string, string | boolean | number | string[] | undefined>;
}

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

export function parse(argv: readonly string[], specs: Specs): Parsed {
  const byShort = new Map<string, string>();
  for (const [name, spec] of Object.entries(specs)) {
    if (spec.short !== undefined) byShort.set(spec.short, name);
  }

  const positionals: string[] = [];
  const options: Record<string, string | boolean | number | string[] | undefined> = {};
  let onlyPositionals = false;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i] as string;

    if (onlyPositionals) {
      positionals.push(arg);
      continue;
    }
    if (arg === '--') {
      onlyPositionals = true;
      continue;
    }
    if (!arg.startsWith('-') || arg === '-') {
      positionals.push(arg);
      continue;
    }

    let name: string;
    let inlineValue: string | undefined;

    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      name = eq < 0 ? arg.slice(2) : arg.slice(2, eq);
      inlineValue = eq < 0 ? undefined : arg.slice(eq + 1);
      // --no-foo turns a boolean off, which is how a default-on flag is
      // disabled without inventing a second name for it.
      if (!(name in specs) && name.startsWith('no-') && specs[name.slice(3)]?.type === 'boolean') {
        options[name.slice(3)] = false;
        continue;
      }
    } else {
      const short = arg.slice(1);
      const resolved = byShort.get(short);
      if (resolved === undefined) {
        throw new UsageError(`unknown option -${short}${suggest(short, specs)}`);
      }
      name = resolved;
    }

    const spec = specs[name];
    if (spec === undefined) {
      throw new UsageError(`unknown option --${name}${suggest(name, specs)}`);
    }

    if (spec.type === 'boolean') {
      if (inlineValue !== undefined) {
        if (inlineValue !== 'true' && inlineValue !== 'false') {
          throw new UsageError(`--${name} is a flag; it takes no value (got ${JSON.stringify(inlineValue)})`);
        }
        options[name] = inlineValue === 'true';
      } else {
        options[name] = true;
      }
      continue;
    }

    const raw = inlineValue ?? argv[i + 1];
    if (inlineValue === undefined) i += 1;
    if (raw === undefined || (inlineValue === undefined && raw.startsWith('-') && raw.length > 1)) {
      throw new UsageError(
        `--${name} needs a value${spec.placeholder === undefined ? '' : ` (${spec.placeholder})`}`,
      );
    }

    if (spec.type === 'number') {
      const value = Number(raw);
      if (!Number.isFinite(value)) {
        throw new UsageError(`--${name} must be a number, got ${JSON.stringify(raw)}`);
      }
      options[name] = value;
      continue;
    }

    if (spec.multiple === true) {
      const existing = options[name];
      options[name] = Array.isArray(existing) ? [...existing, raw] : [raw];
    } else {
      options[name] = raw;
    }
  }

  return { positionals, options };
}

/** A suggestion, so a typo gets corrected rather than merely rejected. */
function suggest(given: string, specs: Specs): string {
  const names = Object.keys(specs);
  let best: string | undefined;
  let bestDistance = Infinity;
  for (const name of names) {
    const distance = editDistance(given, name);
    if (distance < bestDistance) {
      bestDistance = distance;
      best = name;
    }
  }
  if (best !== undefined && bestDistance <= Math.max(2, Math.floor(best.length / 3))) {
    return `. Did you mean --${best}?`;
  }
  return names.length === 0 ? '' : `. Known options: ${names.map((n) => `--${n}`).join(', ')}`;
}

function editDistance(a: string, b: string): number {
  const rows = a.length + 1;
  const cols = b.length + 1;
  let previous = Array.from({ length: cols }, (_, i) => i);
  for (let i = 1; i < rows; i += 1) {
    const current = [i, ...new Array<number>(cols - 1).fill(0)];
    for (let j = 1; j < cols; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      current[j] = Math.min(
        (previous[j] as number) + 1,
        (current[j - 1] as number) + 1,
        (previous[j - 1] as number) + cost,
      );
    }
    previous = current;
  }
  return previous[cols - 1] as number;
}

// ---- typed accessors ------------------------------------------------------

export function str(parsed: Parsed, name: string): string | undefined {
  const value = parsed.options[name];
  if (value === undefined) return undefined;
  if (Array.isArray(value)) return value[value.length - 1];
  return String(value);
}

export function list(parsed: Parsed, name: string): string[] {
  const value = parsed.options[name];
  if (value === undefined) return [];
  if (Array.isArray(value)) return value;
  return [String(value)];
}

export function bool(parsed: Parsed, name: string, fallback = false): boolean {
  const value = parsed.options[name];
  return value === undefined ? fallback : value === true;
}

export function num(parsed: Parsed, name: string, fallback: number): number {
  const value = parsed.options[name];
  return typeof value === 'number' ? value : fallback;
}

/** Render the options of a command, for its help text. */
export function renderOptions(specs: Specs, indent = '  '): string {
  const rows = Object.entries(specs).map(([name, spec]) => {
    const flag =
      (spec.short === undefined ? '    ' : `-${spec.short}, `) +
      `--${name}` +
      (spec.type === 'boolean' ? '' : ` <${spec.placeholder ?? spec.type}>`);
    return [flag, spec.describe] as const;
  });
  const width = Math.min(34, Math.max(...rows.map(([flag]) => flag.length)));
  return rows
    .map(([flag, describe]) =>
      flag.length > width
        ? `${indent}${flag}\n${indent}${' '.repeat(width + 2)}${describe}`
        : `${indent}${flag.padEnd(width + 2)}${describe}`,
    )
    .join('\n');
}
