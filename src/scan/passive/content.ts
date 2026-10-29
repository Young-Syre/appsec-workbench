/**
 * Checks about what a request carries and what a document pulls in.
 *
 * The theme is trust boundaries that are easy to cross by accident: a token
 * in a URL that ends up in a log and a Referer, a script loaded from somebody
 * else's origin with no integrity, a redirect whose destination came from the
 * query string, a GraphQL endpoint that will describe its own schema.
 */

import { get as getHeader } from '../../core/headers.js';
import { bodyText } from '../../core/encoding.js';
import {
  type FindingDraft,
  type PassiveCheck,
  isAuthenticated,
  isHtmlDocument,
} from '../check.js';

/** Query parameter names whose value should never be in a URL. */
const SENSITIVE_PARAMS =
  /^(?:access_?token|id_?token|refresh_?token|token|auth|authorization|api_?key|apikey|key|secret|client_?secret|password|passwd|pwd|session|sessionid|sid|jwt|code_verifier|otp|mfa_?code)$/i;

export const tokenInUrlCheck: PassiveCheck = {
  id: 'AWB-P040',
  title: 'Credential in a URL',
  description:
    'A URL is written to server logs, proxy logs and browser history, and is sent in ' +
    'the Referer header to whatever the page links to next. Nothing in that path treats ' +
    'it as a secret.',
  run(exchange) {
    let url: URL;
    try {
      url = new URL(exchange.request.url);
    } catch {
      return [];
    }

    const out: FindingDraft[] = [];
    const named: string[] = [];
    for (const [key, value] of url.searchParams) {
      if (value.length === 0) continue;
      if (SENSITIVE_PARAMS.test(key)) named.push(key);
    }

    // `code` is only interesting when it is an OAuth authorisation code, and
    // the way to tell is context: a `state` alongside it, or a path that says
    // callback. Treating every `code` parameter as a credential would fire on
    // country codes, promo codes and error codes, which is most of the web.
    const looksLikeOauthCallback =
      url.searchParams.has('state') || /\/(?:callback|cb|oauth2?|signin-\w+)(?:\/|$)/i.test(url.pathname);
    if (url.searchParams.has('code') && looksLikeOauthCallback) named.push('code');

    if (named.length > 0) {
      // An OAuth authorisation code in a redirect URI is the intended design,
      // so it is graded lower -- the exchange is single-use and short-lived.
      const authorisationCode = named.length === 1 && named[0] === 'code';
      out.push({
        check: this.id,
        title: `Credential-bearing parameter in the query string: ${named.join(', ')}`,
        severity: authorisationCode ? 'info' : 'medium',
        confidence: 'firm',
        detail:
          `The request URL carries ${named.join(', ')} as a query parameter. The value reaches ` +
          'every access log on the path, the browser history, and the Referer header on any ' +
          'outbound link or subresource from the resulting page.' +
          (authorisationCode
            ? ' An OAuth authorisation code here is the specified design; confirm it is ' +
              'single-use and short-lived, and that PKCE is in play.'
            : ''),
        remediation:
          'Move the value into a header or a POST body. Where a link has to carry a ' +
          'capability, make it single-use and short-lived.',
      });
    }

    // A JWT anywhere in the URL, including the path.
    if (/\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\./.test(exchange.request.url)) {
      out.push({
        check: this.id,
        title: 'JSON Web Token in the URL',
        severity: 'medium',
        confidence: 'certain',
        detail:
          'The request URL contains something with the three-part shape of a JWT. Even a ' +
          'short-lived token is long-lived compared to how long a log line survives.',
        remediation: 'Send the token in the Authorization header.',
      });
    }

    return out;
  },
};

export const referrerLeakCheck: PassiveCheck = {
  id: 'AWB-P041',
  title: 'Document leaks its URL to third parties through Referer',
  description:
    'Without a referrer policy, a page carrying anything sensitive in its URL hands ' +
    'that URL to every third-party origin it loads a resource from.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined || !isHtmlDocument(exchange)) return [];

    const policy = (getHeader(response.headers, 'referrer-policy') ?? '').toLowerCase();
    const safe = [
      'no-referrer',
      'same-origin',
      'strict-origin',
      'strict-origin-when-cross-origin',
      'no-referrer-when-downgrade',
      'origin',
      'origin-when-cross-origin',
    ];
    if (safe.some((p) => policy.includes(p))) return [];

    // The finding is only interesting if the URL has something to leak, or
    // the page loads something cross-origin.
    let hasQuery = false;
    try {
      hasQuery = new URL(exchange.request.url).search.length > 1;
    } catch {
      hasQuery = false;
    }
    const text = bodyText(response.headers, response.body);
    const crossOrigin = /(?:src|href)\s*=\s*["']https?:\/\//i.test(text);
    if (!hasQuery && !crossOrigin) return [];

    return [
      {
        check: this.id,
        title: policy.length === 0 ? this.title : `Referrer-Policy is ${policy}, which leaks the full URL`,
        severity: hasQuery ? 'low' : 'info',
        confidence: 'certain',
        detail:
          (policy.length === 0
            ? 'No Referrer-Policy is set, so the browser default applies and varies.'
            : `Referrer-Policy is ${JSON.stringify(policy)}, which sends the full URL.`) +
          (hasQuery ? ' This URL has a query string, so there is something to leak.' : '') +
          (crossOrigin ? ' The document loads at least one cross-origin resource.' : ''),
        remediation:
          'Send Referrer-Policy: strict-origin-when-cross-origin, which keeps the path and ' +
          'query inside your own origin and sends only the origin outward.',
      },
    ];
  },
};

export const subresourceIntegrityCheck: PassiveCheck = {
  id: 'AWB-P042',
  title: 'Third-party script loaded without integrity',
  description:
    'A script tag pointing at somebody else\'s origin executes whatever that origin ' +
    'serves, now and at every future page load.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined || !isHtmlDocument(exchange)) return [];

    let pageHost: string;
    try {
      pageHost = new URL(exchange.request.url).hostname.toLowerCase();
    } catch {
      return [];
    }

    const text = bodyText(response.headers, response.body);
    const out: FindingDraft[] = [];
    const offenders = new Set<string>();

    const tagPattern = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;
    let match: RegExpExecArray | null;
    while ((match = tagPattern.exec(text)) !== null && offenders.size < 10) {
      const tag = match[0];
      const src = match[1] as string;
      if (!/^https?:\/\//i.test(src)) continue;
      let host: string;
      try {
        host = new URL(src).hostname.toLowerCase();
      } catch {
        continue;
      }
      if (host === pageHost) continue;
      if (/\bintegrity\s*=/.test(tag)) continue;
      offenders.add(src);
    }

    if (offenders.size > 0) {
      out.push({
        check: this.id,
        title: this.title,
        severity: 'low',
        confidence: 'certain',
        detail:
          `This document loads ${offenders.size} script${offenders.size === 1 ? '' : 's'} from ` +
          'another origin with no integrity attribute: ' +
          `${[...offenders].slice(0, 5).join(', ')}. Whoever controls those origins controls ` +
          'code execution on this page.',
        remediation:
          'Add an integrity attribute with a hash, together with crossorigin="anonymous". ' +
          'Where the asset changes without warning, self-host it instead -- integrity and a ' +
          'rolling CDN URL cannot both work.',
      });
    }

    return out;
  },
};

export const mixedContentCheck: PassiveCheck = {
  id: 'AWB-P043',
  title: 'HTTPS document references plaintext resources',
  description:
    'A plaintext subresource on an HTTPS page is modifiable in transit, and if it is ' +
    'script, that is code execution on an origin the user believes is secure.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined || !isHtmlDocument(exchange)) return [];
    if (!exchange.request.url.startsWith('https://')) return [];

    const text = bodyText(response.headers, response.body);
    const active = new Set<string>();
    const passive = new Set<string>();

    const pattern = /<(script|link|iframe|img|audio|video|source|object|embed)\b[^>]*?(?:src|href|data)\s*=\s*["'](http:\/\/[^"']+)["']/gi;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text)) !== null) {
      const tag = (match[1] ?? '').toLowerCase();
      const url = match[2] as string;
      // Browsers block active mixed content outright and merely warn about
      // passive, so they are different findings with different severities.
      if (['script', 'link', 'iframe', 'object', 'embed'].includes(tag)) active.add(url);
      else passive.add(url);
      if (active.size + passive.size > 20) break;
    }

    const out: FindingDraft[] = [];
    if (active.size > 0) {
      out.push({
        check: this.id,
        title: 'Active mixed content on an HTTPS page',
        severity: 'medium',
        confidence: 'certain',
        detail:
          `${active.size} script, stylesheet or frame reference${active.size === 1 ? '' : 's'} ` +
          `use http://: ${[...active].slice(0, 4).join(', ')}. Browsers block these, so the page ` +
          'is also broken; where a browser does load them, an attacker on the path controls ' +
          'the code that runs.',
        remediation:
          'Serve every subresource over HTTPS. Add Content-Security-Policy: ' +
          'upgrade-insecure-requests while the references are being fixed.',
      });
    }
    if (passive.size > 0) {
      out.push({
        check: this.id,
        title: 'Passive mixed content on an HTTPS page',
        severity: 'info',
        confidence: 'certain',
        detail:
          `${passive.size} image or media reference${passive.size === 1 ? '' : 's'} use http://: ` +
          `${[...passive].slice(0, 4).join(', ')}. These are modifiable in transit and will show ` +
          'the user a degraded security indicator.',
        remediation: 'Serve them over HTTPS.',
      });
    }
    return out;
  },
};

export const openRedirectCandidateCheck: PassiveCheck = {
  id: 'AWB-P044',
  title: 'Redirect destination taken from the request',
  description:
    'A redirect whose target comes from a parameter is an open redirect if the target ' +
    'is not restricted, which makes a trustworthy link land anywhere.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined) return [];
    if (response.status < 300 || response.status >= 400) return [];

    const location = getHeader(response.headers, 'location');
    if (location === undefined || location.length === 0) return [];

    let url: URL;
    try {
      url = new URL(exchange.request.url);
    } catch {
      return [];
    }

    for (const [key, value] of url.searchParams) {
      if (value.length < 2) continue;
      const decoded = safeDecode(value);
      if (location === value || location === decoded || location.startsWith(decoded)) {
        const absolute = /^(?:https?:)?\/\//i.test(decoded);
        return [
          {
            check: this.id,
            title: absolute
              ? `Redirect to an absolute URL taken from the ${key} parameter`
              : `Redirect path taken from the ${key} parameter`,
            severity: absolute ? 'medium' : 'low',
            confidence: absolute ? 'firm' : 'tentative',
            detail:
              `The ${key} parameter was ${JSON.stringify(value)} and the response redirects to ` +
              `${JSON.stringify(location)}.` +
              (absolute
                ? ' The destination is an absolute URL, so if the application does not check it ' +
                  'against an allow-list this is an open redirect -- useful for phishing and ' +
                  'for stealing tokens out of an OAuth flow.'
                : ' The destination is a path, which bounds the damage, though a protocol- ' +
                  'relative value such as //evil.example would also look like a path here.') +
              ` Confirm it with \`awb replay ${exchange.id} --set query:${key}=https://awb-redirect-test.example\`.`,
            remediation:
              'Validate the destination against an allow-list of paths or hosts. Rejecting ' +
              'anything that parses as absolute is the simplest version and is usually enough.',
          },
        ];
      }
    }

    return [];
  },
};

export const graphqlIntrospectionCheck: PassiveCheck = {
  id: 'AWB-P045',
  title: 'GraphQL introspection is enabled',
  description:
    'Introspection returns the whole schema: every type, field, mutation and argument, ' +
    'including the ones no client uses and nobody has reviewed for authorisation.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined || response.status !== 200) return [];
    const text = bodyText(response.headers, response.body);
    if (!text.includes('__schema')) return [];
    // The response must be the introspection result, not a query that merely
    // mentioned it and was refused.
    if (!/"__schema"\s*:\s*\{/.test(text)) return [];

    const types = (text.match(/"kind"\s*:\s*"(?:OBJECT|INPUT_OBJECT|ENUM|INTERFACE|UNION)"/g) ?? []).length;
    const mutations = /"mutationType"\s*:\s*\{/.test(text);

    return [
      {
        check: this.id,
        title: this.title,
        severity: 'low',
        confidence: 'certain',
        detail:
          `This endpoint answered an introspection query with a schema describing roughly ` +
          `${types} types${mutations ? ' and a mutation root' : ''}. That is the complete ` +
          'attack surface of the API handed over in one request, and it frequently includes ' +
          'fields that exist for internal tooling.',
        remediation:
          'Disable introspection in production, or require authentication for it. Note that ' +
          'disabling it is defence in depth rather than a fix: the fields are still there and ' +
          'still have to be authorised individually.',
      },
    ];
  },
};

export const smugglingPreconditionCheck: PassiveCheck = {
  id: 'AWB-P046',
  title: 'Request framing is ambiguous',
  description:
    'Two hops that disagree about where a request ends is a desync, and the first ' +
    'requirement is a request whose length is expressible in more than one way.',
  run(exchange) {
    const request = exchange.request;
    const out: FindingDraft[] = [];

    const headerNames = request.headers.map(([k]) => k.toLowerCase());
    const lengthCount = headerNames.filter((n) => n === 'content-length').length;
    const hasTe = headerNames.includes('transfer-encoding');

    if (lengthCount > 1) {
      out.push({
        check: this.id,
        title: 'Request carried more than one Content-Length',
        severity: 'medium',
        confidence: 'certain',
        detail:
          `${lengthCount} Content-Length headers were present. RFC 9112 requires a recipient ` +
          'to reject this; one that takes the first and one that takes the last disagree about ' +
          'where the body ends, which is a request smuggling primitive.',
        remediation:
          'Reject requests with duplicate Content-Length at the edge, rather than normalising ' +
          'them and forwarding one value.',
      });
    }

    if (hasTe && lengthCount > 0) {
      out.push({
        check: this.id,
        title: 'Request carried both Transfer-Encoding and Content-Length',
        severity: 'medium',
        confidence: 'certain',
        detail:
          'Both framing headers were present. The specification says Transfer-Encoding wins, ' +
          'but implementations differ, and the difference between a front end that honours ' +
          'one and a back end that honours the other is a desync.',
        remediation:
          'Reject the combination at the edge. Confirm the front end and the back end agree ' +
          'by testing rather than by reading documentation.',
      });
    }

    for (const [name, value] of request.headers) {
      if (/[\r\n]/.test(value)) {
        out.push({
          check: this.id,
          title: `Header ${name} contained a carriage return or newline`,
          severity: 'high',
          confidence: 'certain',
          detail:
            `The value of ${name} contains CR or LF, which terminates a header. Whatever ` +
            'produced this value can inject headers, and in a request that reaches a cache or ' +
            'a second parser it can inject a whole request.',
          remediation:
            'Reject CR and LF in header values wherever they are constructed. This is almost ' +
            'always a missing validation at the point a value is copied into a header.',
        });
      }
    }

    return out;
  },
};

export const authOverPlaintextCheck: PassiveCheck = {
  id: 'AWB-P047',
  title: 'Credentials sent over plaintext HTTP',
  description:
    'Anything on the path reads this. There is no mitigation and no configuration that ' +
    'makes it acceptable.',
  run(exchange) {
    if (!exchange.request.url.startsWith('http://')) return [];
    if (!isAuthenticated(exchange)) return [];

    let host: string | undefined;
    try {
      host = new URL(exchange.request.url).hostname;
    } catch {
      host = undefined;
    }
    // Loopback is not on a network path, and flagging it trains the reader to
    // skip this check on the one occasion it matters.
    if (host !== undefined && /^(?:localhost|127(?:\.\d+){3}|\[::1\]|::1)$/i.test(host)) return [];

    const carried = exchange.request.headers
      .filter(([k]) => ['authorization', 'cookie', 'x-api-key'].includes(k.toLowerCase()))
      .map(([k]) => k);

    return [
      {
        check: this.id,
        title: this.title,
        severity: 'high',
        confidence: 'certain',
        detail:
          `This request went over plaintext HTTP carrying ${carried.join(', ')}. The credential ` +
          'is readable by anything on the network path, and replayable.',
        remediation:
          'Serve the application over HTTPS only, redirect HTTP to HTTPS, and send HSTS so ' +
          'the redirect is not needed a second time. Rotate anything that was sent this way.',
      },
    ];
  },
};

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export const CONTENT_CHECKS: readonly PassiveCheck[] = [
  tokenInUrlCheck,
  referrerLeakCheck,
  subresourceIntegrityCheck,
  mixedContentCheck,
  openRedirectCandidateCheck,
  graphqlIntrospectionCheck,
  smugglingPreconditionCheck,
  authOverPlaintextCheck,
];
