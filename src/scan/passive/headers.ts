/**
 * Response-header checks, graded by what the response actually is.
 *
 * The genre these belong to is the one that gives scanners a bad name: a list
 * of absent headers, every one a "medium", most of them irrelevant to the
 * endpoint they were reported on. The difference here is that each check
 * asks first whether the header could have done anything on this response,
 * and stays quiet when the answer is no.
 */

import { get as getHeader, getAll } from '../../core/headers.js';
import { bodyText } from '../../core/encoding.js';
import {
  type FindingDraft,
  type PassiveCheck,
  isAuthenticated,
  isHtmlDocument,
} from '../check.js';

export const hstsCheck: PassiveCheck = {
  id: 'AWB-P001',
  title: 'HTTPS response without Strict-Transport-Security',
  description:
    'Without HSTS, a browser that has not yet been told to use HTTPS will make its ' +
    'first request over HTTP, which is the request an attacker on the path needs.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined) return [];
    if (!exchange.request.url.startsWith('https://')) return [];
    // Only the top-level document can be the first request to the origin.
    if (!isHtmlDocument(exchange)) return [];

    const hsts = getHeader(response.headers, 'strict-transport-security');
    if (hsts === undefined) {
      return [
        {
          check: this.id,
          title: this.title,
          severity: 'low',
          confidence: 'certain',
          detail:
            'This HTTPS document carries no Strict-Transport-Security header. A browser ' +
            'with no prior knowledge of the origin will try HTTP first if the user types ' +
            'the host or follows an http:// link, and that request can be intercepted ' +
            'before the redirect to HTTPS happens.',
          remediation:
            'Send Strict-Transport-Security: max-age=31536000; includeSubDomains on HTTPS ' +
            'responses. Add preload only once you are certain every subdomain can serve HTTPS.',
        },
      ];
    }

    const maxAge = /max-age\s*=\s*"?(\d+)"?/i.exec(hsts);
    const seconds = maxAge ? Number(maxAge[1]) : undefined;
    if (seconds === undefined) {
      return [
        {
          check: this.id,
          title: 'Strict-Transport-Security without max-age',
          severity: 'low',
          confidence: 'certain',
          detail: `The header is present but carries no max-age, so it does nothing: ${hsts}`,
          remediation: 'Add max-age, for example max-age=31536000.',
        },
      ];
    }
    if (seconds < 86_400) {
      return [
        {
          check: this.id,
          title: 'Strict-Transport-Security with a very short max-age',
          severity: 'info',
          confidence: 'certain',
          detail:
            `max-age is ${seconds} seconds, under a day. The policy expires before it can ` +
            'protect a returning user, which is the case it exists for.',
          remediation: 'Raise max-age to at least 31536000 (one year) once HTTPS is reliable.',
        },
      ];
    }
    return [];
  },
};

export const cspCheck: PassiveCheck = {
  id: 'AWB-P002',
  title: 'Content-Security-Policy missing or permissive',
  description:
    'A CSP is the control that turns an injected script into a blocked script. ' +
    'The common misconfigurations give back exactly the capability it was added to remove.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined || !isHtmlDocument(exchange)) return [];

    const enforced = getHeader(response.headers, 'content-security-policy');
    const reportOnly = getHeader(response.headers, 'content-security-policy-report-only');

    if (enforced === undefined) {
      return [
        {
          check: this.id,
          title:
            reportOnly === undefined
              ? 'HTML document without Content-Security-Policy'
              : 'Content-Security-Policy is report-only, so nothing is enforced',
          severity: 'low',
          confidence: 'certain',
          detail:
            reportOnly === undefined
              ? 'This document is served without a Content-Security-Policy, so an injected ' +
                'script executes with the page it was injected into.'
              : 'Only Content-Security-Policy-Report-Only is set. Violations are reported ' +
                `and nothing is blocked. The policy observed was: ${reportOnly}`,
          remediation:
            'Serve an enforcing Content-Security-Policy. Start from default-src \'self\' and ' +
            'add what breaks, rather than starting permissive and tightening later.',
        },
      ];
    }

    const out: FindingDraft[] = [];
    const policy = enforced.toLowerCase();
    const directives = new Map<string, string>();
    for (const part of policy.split(';')) {
      const trimmed = part.trim();
      if (trimmed.length === 0) continue;
      const space = trimmed.indexOf(' ');
      if (space < 0) directives.set(trimmed, '');
      else directives.set(trimmed.slice(0, space), trimmed.slice(space + 1));
    }

    const scriptSrc = directives.get('script-src') ?? directives.get('default-src');
    if (scriptSrc !== undefined) {
      const hasNonce = /'nonce-/.test(scriptSrc);
      const hasHash = /'sha(?:256|384|512)-/.test(scriptSrc);

      if (scriptSrc.includes("'unsafe-inline'") && !hasNonce && !hasHash) {
        out.push({
          check: this.id,
          title: "Content-Security-Policy allows 'unsafe-inline' for scripts",
          severity: 'medium',
          confidence: 'certain',
          detail:
            "script-src includes 'unsafe-inline' with no nonce or hash alongside it, so " +
            'inline script executes. That is the capability an injected <script> needs, and ' +
            `it makes the rest of the policy decorative for script injection: ${enforced}`,
          remediation:
            "Remove 'unsafe-inline' and allow the inline scripts you need with a per-response " +
            "nonce or a hash. Note that 'unsafe-inline' is ignored when a nonce or hash is " +
            'present, so adding one is also how you make the removal safe to deploy.',
        });
      }

      if (scriptSrc.includes("'unsafe-eval'")) {
        out.push({
          check: this.id,
          title: "Content-Security-Policy allows 'unsafe-eval'",
          severity: 'low',
          confidence: 'certain',
          detail:
            "script-src includes 'unsafe-eval', so eval, new Function and the string forms of " +
            'setTimeout work. That turns a DOM sink that only reaches a string evaluator into ' +
            'script execution.',
          remediation:
            "Remove 'unsafe-eval'. Where a library needs it, find out which and replace or " +
            'isolate it; it is usually a template compiler that has a precompiled mode.',
        });
      }

      if (/(^|\s)\*(\s|$)/.test(scriptSrc) || scriptSrc.includes('http:') || scriptSrc.includes('https:')) {
        out.push({
          check: this.id,
          title: 'Content-Security-Policy allows scripts from any origin',
          severity: 'medium',
          confidence: 'firm',
          detail:
            `script-src is effectively unrestricted by source: ${scriptSrc}. An injected ` +
            '<script src> pointing anywhere will load.',
          remediation:
            'List the origins you actually load script from, or move to nonces so the policy ' +
            'does not depend on an allowlist at all.',
        });
      }
    }

    if (!directives.has('object-src') && !directives.has('default-src')) {
      out.push({
        check: this.id,
        title: 'Content-Security-Policy does not restrict object-src',
        severity: 'info',
        confidence: 'certain',
        detail:
          'Neither object-src nor default-src is set, so <object> and <embed> are unrestricted. ' +
          'Those elements can execute script in some configurations and are almost never needed.',
        remediation: "Add object-src 'none'.",
      });
    }

    if (!directives.has('frame-ancestors')) {
      out.push({
        check: this.id,
        title: 'Content-Security-Policy does not set frame-ancestors',
        severity: 'info',
        confidence: 'certain',
        detail:
          'frame-ancestors is absent, so framing is governed only by X-Frame-Options if that ' +
          'is present. frame-ancestors supersedes it and is the one modern browsers follow.',
        remediation: "Add frame-ancestors 'self', or 'none' for a document never meant to be framed.",
      });
    }

    return out;
  },
};

export const framingCheck: PassiveCheck = {
  id: 'AWB-P003',
  title: 'Document framable by any origin',
  description:
    'A page that can be framed cross-origin can be overlaid, which turns a one-click ' +
    'state-changing action into a click the user believed was somewhere else.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined || !isHtmlDocument(exchange)) return [];

    const xfo = getHeader(response.headers, 'x-frame-options');
    const csp = getHeader(response.headers, 'content-security-policy') ?? '';
    if (/frame-ancestors/i.test(csp)) return [];
    if (xfo !== undefined && /deny|sameorigin/i.test(xfo)) return [];

    const text = bodyText(response.headers, response.body);
    // A document with no form and no state-changing affordance is a much
    // weaker finding, and grading it the same is how this check becomes noise.
    const hasForm = /<form\b/i.test(text);
    const hasButton = /<button\b|type=["']submit["']/i.test(text);
    const interactive = hasForm || hasButton;

    return [
      {
        check: this.id,
        title: this.title,
        severity: interactive ? 'low' : 'info',
        confidence: 'certain',
        detail:
          (xfo === undefined
            ? 'Neither X-Frame-Options nor a CSP frame-ancestors directive is present'
            : `X-Frame-Options is ${JSON.stringify(xfo)}, which no longer restricts framing`) +
          (interactive
            ? ', and the document contains a form or submit control, so an overlay can direct a click into it.'
            : ', though the document contains no form or submit control, which limits what an overlay achieves.'),
        remediation:
          "Set Content-Security-Policy: frame-ancestors 'self' (or 'none'). X-Frame-Options is " +
          'the older equivalent and is still worth sending for very old clients.',
      },
    ];
  },
};

export const cacheCheck: PassiveCheck = {
  id: 'AWB-P004',
  title: 'Authenticated response is cacheable',
  description:
    'A response produced for one authenticated user that a shared cache may store will ' +
    'be served to the next person who asks for that URL.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined) return [];
    if (!isAuthenticated(exchange)) return [];
    if (response.status !== 200) return [];

    const cacheControl = (getHeader(response.headers, 'cache-control') ?? '').toLowerCase();
    const pragma = (getHeader(response.headers, 'pragma') ?? '').toLowerCase();

    // no-store is the only directive that reliably keeps it out of a shared
    // cache. private alone keeps it out of a *shared* one, which is usually
    // enough, so it is graded lower rather than reported as the same thing.
    if (cacheControl.includes('no-store')) return [];

    const hasPrivate = cacheControl.includes('private');
    const hasNoCache = cacheControl.includes('no-cache') || pragma.includes('no-cache');

    if (hasPrivate && hasNoCache) return [];

    const setsCookie = getAll(response.headers, 'set-cookie').length > 0;

    if (cacheControl.length === 0 && pragma.length === 0) {
      return [
        {
          check: this.id,
          title: this.title,
          severity: setsCookie ? 'medium' : 'low',
          confidence: 'firm',
          detail:
            'This response was produced for an authenticated request and carries no ' +
            'Cache-Control at all. Heuristic freshness applies, so an intermediary may ' +
            'store it and serve it to another user.' +
            (setsCookie
              ? ' It also sets a cookie, which would then be handed to whoever receives the cached copy.'
              : ''),
          remediation:
            'Send Cache-Control: no-store on authenticated responses. Where caching is wanted, ' +
            'use private together with a Vary that covers the credential.',
        },
      ];
    }

    if (!hasPrivate && !cacheControl.includes('no-cache')) {
      return [
        {
          check: this.id,
          title: 'Authenticated response is publicly cacheable',
          severity: setsCookie ? 'high' : 'medium',
          confidence: 'firm',
          detail:
            `Cache-Control is ${JSON.stringify(cacheControl)} on a response to an ` +
            'authenticated request, and says neither private nor no-store. A shared cache ' +
            'is permitted to store this and serve it to a different user.' +
            (setsCookie ? ' The response also sets a cookie.' : ''),
          remediation: 'Send Cache-Control: no-store, or private with an appropriate Vary.',
        },
      ];
    }

    return [];
  },
};

export const varyCheck: PassiveCheck = {
  id: 'AWB-P005',
  title: 'Cacheable response varies by a header it does not declare',
  description:
    'A cache keys on the URL plus the headers named in Vary. A response whose content ' +
    'depends on a header missing from Vary will be served to requests that sent a ' +
    'different value for it.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined || response.status !== 200) return [];

    const cacheControl = (getHeader(response.headers, 'cache-control') ?? '').toLowerCase();
    if (cacheControl.includes('no-store') || cacheControl.includes('private')) return [];
    if (cacheControl.length === 0) return [];
    if (!/max-age|s-maxage|public/.test(cacheControl)) return [];

    const vary = (getHeader(response.headers, 'vary') ?? '').toLowerCase();
    const varied = new Set(vary.split(',').map((v) => v.trim()).filter((v) => v.length > 0));
    if (varied.has('*')) return [];

    const out: FindingDraft[] = [];

    // Content negotiated by Origin but not keyed on it: the classic CORS
    // cache poisoning shape.
    if (getHeader(response.headers, 'access-control-allow-origin') !== undefined && !varied.has('origin')) {
      out.push({
        check: this.id,
        title: 'Cacheable CORS response does not Vary on Origin',
        severity: 'medium',
        confidence: 'firm',
        detail:
          'The response is cacheable and carries Access-Control-Allow-Origin, but Vary does ' +
          `not include Origin (Vary: ${vary || 'absent'}). A cache will reuse the ` +
          'Access-Control-Allow-Origin computed for one origin when answering another.',
        remediation:
          'Add Origin to Vary on every response whose Access-Control-Allow-Origin depends on ' +
          'the request, or return a static allow-list value.',
      });
    }

    if (isAuthenticated(exchange) && !varied.has('cookie') && !varied.has('authorization')) {
      out.push({
        check: this.id,
        title: 'Cacheable response to an authenticated request does not Vary on the credential',
        severity: 'high',
        confidence: 'firm',
        detail:
          `Cache-Control is ${JSON.stringify(cacheControl)} and Vary is ` +
          `${vary.length > 0 ? JSON.stringify(vary) : 'absent'}, so the cache key does not ` +
          'include the cookie or Authorization header that produced this content.',
        remediation:
          'Prefer Cache-Control: no-store for authenticated responses. If they must be cached, ' +
          'the credential has to be in the cache key.',
      });
    }

    return out;
  },
};

export const contentTypeCheck: PassiveCheck = {
  id: 'AWB-P006',
  title: 'Response invites content-type sniffing',
  description:
    'Without nosniff, a browser may disregard the declared type and run a response as ' +
    'script or render it as HTML, which turns an upload or a JSON endpoint into a sink.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined || response.body.length === 0) return [];
    if (response.status >= 300 && response.status < 400) return [];

    const nosniff = (getHeader(response.headers, 'x-content-type-options') ?? '').toLowerCase();
    if (nosniff.includes('nosniff')) return [];

    const declared = getHeader(response.headers, 'content-type');
    if (declared === undefined) {
      return [
        {
          check: this.id,
          title: 'Response has no Content-Type',
          severity: 'low',
          confidence: 'certain',
          detail:
            'The response declares no Content-Type, so the browser decides what it is by ' +
            'looking at the bytes. For anything attacker-influenced that is a path to ' +
            'rendering HTML where HTML was not intended.',
          remediation: 'Always declare Content-Type, and send X-Content-Type-Options: nosniff.',
        },
      ];
    }

    const ct = declared.toLowerCase();
    // Sniffing only matters where a wrong guess is dangerous: JSON that could
    // be read as HTML, and anything served as a generic byte stream.
    const risky =
      ct.startsWith('application/json') ||
      ct.startsWith('text/plain') ||
      ct.startsWith('application/octet-stream');
    if (!risky) return [];

    return [
      {
        check: this.id,
        title: this.title,
        severity: 'info',
        confidence: 'certain',
        detail:
          `Content-Type is ${JSON.stringify(declared)} and X-Content-Type-Options: nosniff is ` +
          'absent. Where the body contains attacker-influenced text, a browser navigating ' +
          'directly to this URL may render it rather than download it.',
        remediation:
          'Send X-Content-Type-Options: nosniff on every response. It costs nothing and ' +
          'removes a whole class of surprise.',
      },
    ];
  },
};

export const serverDisclosureCheck: PassiveCheck = {
  id: 'AWB-P007',
  title: 'Server or framework version disclosed',
  description:
    'A precise version tells an attacker which published vulnerabilities to try, and ' +
    'removes the step where they would have had to find that out noisily.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined) return [];

    const out: FindingDraft[] = [];
    const interesting = [
      'server',
      'x-powered-by',
      'x-aspnet-version',
      'x-aspnetmvc-version',
      'x-generator',
      'x-drupal-cache',
      'x-runtime-version',
    ];

    for (const name of interesting) {
      const value = getHeader(response.headers, name);
      if (value === undefined || value.trim().length === 0) continue;
      // A bare product name is not the finding; a version number is.
      const hasVersion = /\d+\.\d+/.test(value);
      out.push({
        check: this.id,
        title: hasVersion ? `${name} discloses a precise version` : `${name} discloses the software in use`,
        severity: hasVersion ? 'low' : 'info',
        confidence: 'certain',
        detail: `${name}: ${value}`,
        remediation:
          `Remove or flatten the ${name} header. On most stacks this is one configuration ` +
          'line, and it does not substitute for patching.',
      });
    }

    return out;
  },
};

export const HEADER_CHECKS: readonly PassiveCheck[] = [
  hstsCheck,
  cspCheck,
  framingCheck,
  cacheCheck,
  varyCheck,
  contentTypeCheck,
  serverDisclosureCheck,
];
