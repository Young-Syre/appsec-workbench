/**
 * The authorisation record, and why it is a file rather than a flag.
 *
 * Passive analysis reads traffic you already have. Active checks send
 * requests nobody asked for, at a system somebody owns, and the difference
 * between that being work and being an offence is a piece of paper.
 *
 * A `--yes-i-am-authorised` flag is worth nothing: it is typed once, in a
 * shell, and leaves no trace. So active modes require a record committed to
 * the project that names the engagement, who authorised it, when, and when
 * that authorisation expires -- and every finding the active checks produce
 * carries a reference to it. An expired record fails closed.
 *
 * None of this is a legal control. It is an operational one: it makes the
 * question "was this authorised, and by whom" answerable from the project
 * file months later, which is the question that actually gets asked.
 */

export interface Authorisation {
  /** What is being tested: a programme name, a client, an engagement code. */
  readonly engagement: string;
  /** Who granted it. A name and a contact, free-form. */
  readonly authorisedBy: string;
  /** ISO date the authorisation starts. */
  readonly from: string;
  /** ISO date it expires. Required: open-ended authorisation is not a thing. */
  readonly until: string;
  /** Where the paper lives: a URL, a ticket, a filename. */
  readonly reference: string;
  /** Anything the engagement restricts: rate, hours, excluded techniques. */
  readonly constraints?: readonly string[];
}

export interface AuthorisationStatus {
  readonly ok: boolean;
  readonly reason: string;
  readonly record?: Authorisation;
}

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

export function parseAuthorisation(input: unknown): Authorisation {
  if (typeof input !== 'object' || input === null) {
    throw new Error('authorisation record must be an object');
  }
  const o = input as Record<string, unknown>;
  const required = ['engagement', 'authorisedBy', 'from', 'until', 'reference'] as const;
  for (const key of required) {
    if (typeof o[key] !== 'string' || (o[key] as string).trim().length === 0) {
      throw new Error(`authorisation record is missing a non-empty ${key}`);
    }
  }
  for (const key of ['from', 'until'] as const) {
    if (!ISO_DATE.test(o[key] as string)) {
      throw new Error(`authorisation ${key} must be an ISO date (YYYY-MM-DD), got ${String(o[key])}`);
    }
  }
  const constraints = o['constraints'];
  if (constraints !== undefined && !Array.isArray(constraints)) {
    throw new Error('authorisation constraints must be a list of strings');
  }
  const record: Authorisation = {
    engagement: (o['engagement'] as string).trim(),
    authorisedBy: (o['authorisedBy'] as string).trim(),
    from: o['from'] as string,
    until: o['until'] as string,
    reference: (o['reference'] as string).trim(),
    ...(constraints === undefined
      ? {}
      : { constraints: (constraints as unknown[]).map((c) => String(c)) }),
  };
  if (record.until < record.from) {
    throw new Error(`authorisation expires (${record.until}) before it starts (${record.from})`);
  }
  return record;
}

/**
 * Is active testing permitted right now?
 *
 * `today` is injected so this is testable and so a run can be pinned to the
 * date it claims to have happened on.
 */
export function checkAuthorisation(
  record: Authorisation | undefined,
  today: string = new Date().toISOString().slice(0, 10),
): AuthorisationStatus {
  if (record === undefined) {
    return {
      ok: false,
      reason:
        'no authorisation record in this project. Active checks send requests ' +
        'nobody asked for; write one with `awb auth set` naming the engagement, ' +
        'who authorised it and when it expires.',
    };
  }
  if (today < record.from) {
    return {
      ok: false,
      reason: `authorisation for ${record.engagement} does not start until ${record.from} (today is ${today})`,
      record,
    };
  }
  if (today > record.until) {
    return {
      ok: false,
      reason:
        `authorisation for ${record.engagement} expired on ${record.until} (today is ${today}). ` +
        'Renew it before running active checks.',
      record,
    };
  }
  return {
    ok: true,
    reason: `authorised for ${record.engagement} by ${record.authorisedBy} until ${record.until}`,
    record,
  };
}

export class NotAuthorised extends Error {
  constructor(status: AuthorisationStatus) {
    super(status.reason);
    this.name = 'NotAuthorised';
  }
}

export function assertAuthorised(
  record: Authorisation | undefined,
  today?: string,
): Authorisation {
  const status = checkAuthorisation(record, today);
  if (!status.ok || status.record === undefined) throw new NotAuthorised(status);
  return status.record;
}

/** A one-line citation to put on every finding an active check produced. */
export function citation(record: Authorisation): string {
  return `${record.engagement} (authorised by ${record.authorisedBy}, ref ${record.reference}, valid ${record.from}..${record.until})`;
}
