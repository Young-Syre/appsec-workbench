/**
 * CORS checks, graded by whether a browser would actually perform the read.
 *
 * CORS findings are where severity inflation is worst. `Access-Control-Allow-
 * Origin: *` is reported as high constantly, and on its own it is close to
 * harmless: the wildcard cannot be combined with credentials, so what an
 * attacker's page gets is the response an unauthenticated request would have
 * received -- which they could have fetched from their own server anyway.
 *
 * What matters is the combination. An origin reflected from the request
 * together with `Access-Control-Allow-Credentials: true` means any site can
 * read authenticated responses, and that is the finding worth the word
 * critical. These checks are written to tell those apart.
 */

import { get as getHeader } from '../../core/headers.js';
import { type FindingDraft, type PassiveCheck, isAuthenticated } from '../check.js';

export const corsCheck: PassiveCheck = {
  id: 'AWB-P020',
  title: 'Cross-origin resource sharing policy is exploitable',
  description:
    'A policy that allows credentialed reads from an origin the attacker controls lets ' +
    'any page read this response with the victim\'s session attached.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined) return [];

    const allowOrigin = getHeader(response.headers, 'access-control-allow-origin');
    if (allowOrigin === undefined) return [];

    const allowCredentials = (
      getHeader(response.headers, 'access-control-allow-credentials') ?? ''
    ).toLowerCase().trim() === 'true';
    const requestOrigin = getHeader(exchange.request.headers, 'origin');
    const vary = (getHeader(response.headers, 'vary') ?? '').toLowerCase();
    const out: FindingDraft[] = [];

    const value = allowOrigin.trim();

    if (value === '*') {
      if (allowCredentials) {
        // Browsers reject this combination outright, so it is a configuration
        // defect rather than an exploitable one -- and saying so is the
        // difference between a report somebody acts on and one they argue with.
        out.push({
          check: this.id,
          title: 'Access-Control-Allow-Origin is * alongside Allow-Credentials: true',
          severity: 'low',
          confidence: 'certain',
          detail:
            'The wildcard and credentials cannot be combined: a browser treats this as a ' +
            'failed CORS check and the read does not happen. So this is not directly ' +
            'exploitable -- but it does mean somebody intended credentialed cross-origin ' +
            'access and the next change to this configuration may well achieve it.',
          remediation:
            'Decide which it is. For public data, drop Allow-Credentials. For authenticated ' +
            'data, echo a specific allow-listed origin and add Origin to Vary.',
        });
      } else {
        out.push({
          check: this.id,
          title: 'Access-Control-Allow-Origin is *',
          severity: 'info',
          confidence: 'certain',
          detail:
            'Any origin may read this response, but without credentials -- so what is exposed ' +
            'is what an unauthenticated request already returns. Worth confirming that is ' +
            'true of this endpoint, and not a finding by itself.',
          remediation:
            'Confirm the endpoint returns nothing user-specific. If it does, replace the ' +
            'wildcard with an allow-list.',
        });
      }
      return out;
    }

    if (value.toLowerCase() === 'null') {
      out.push({
        check: this.id,
        title: 'Access-Control-Allow-Origin allows the null origin',
        severity: allowCredentials ? 'high' : 'medium',
        confidence: 'firm',
        detail:
          'The null origin is what a document in a sandboxed iframe sends. Allowing it means ' +
          'an attacker needs no domain at all: a page anywhere, including one on a site the ' +
          'victim already trusts, can embed <iframe sandbox="allow-scripts"> and read this ' +
          'response from inside it.' +
          (allowCredentials ? ' Credentials are allowed, so the read includes the session.' : ''),
        remediation:
          'Never allow-list null. Echo a specific origin from a list you control, and reject ' +
          'anything not on it.',
      });
      return out;
    }

    // A specific origin. The question is whether it came from the request.
    if (requestOrigin !== undefined && value.toLowerCase() === requestOrigin.toLowerCase()) {
      const authenticated = isAuthenticated(exchange);
      out.push({
        check: this.id,
        title: allowCredentials
          ? 'Access-Control-Allow-Origin reflects the request Origin with credentials allowed'
          : 'Access-Control-Allow-Origin reflects the request Origin',
        severity: allowCredentials ? (authenticated ? 'critical' : 'high') : 'low',
        confidence: allowCredentials ? 'firm' : 'tentative',
        detail:
          `The response echoes the Origin it was sent (${requestOrigin}). If that reflection ` +
          'is unconditional rather than checked against a list, any origin is allowed.' +
          (allowCredentials
            ? ' Access-Control-Allow-Credentials is true, so a page on any origin can read ' +
              'this response with the victim\'s cookies attached.'
            : ' Credentials are not allowed, which limits this to data available without a session.') +
          (authenticated
            ? ' This particular request was authenticated, so the response contains ' +
              'user-specific data.'
            : '') +
          ' Confirm it by replaying with an Origin the application has never seen: ' +
          '`awb replay <id> --set header:Origin=https://awb-not-allowed.example`.',
        remediation:
          'Compare Origin against an allow-list and echo only a value from that list. Add ' +
          'Origin to Vary so a cache cannot serve one origin the answer computed for another.',
      });

      if (!vary.includes('origin')) {
        out.push({
          check: this.id,
          title: 'Reflected Access-Control-Allow-Origin without Vary: Origin',
          severity: 'low',
          confidence: 'certain',
          detail:
            'The allowed origin depends on the request but Vary does not mention Origin, so ' +
            'any cache in front of this will reuse one origin\'s answer for another.',
          remediation: 'Add Origin to Vary.',
        });
      }
      return out;
    }

    // A fixed third-party origin: worth noting, not a finding on its own.
    if (allowCredentials) {
      out.push({
        check: this.id,
        title: `Credentialed cross-origin reads allowed from ${value}`,
        severity: 'info',
        confidence: 'certain',
        detail:
          `${value} may read this response with credentials. That is a deliberate-looking ` +
          'configuration; it is worth confirming that origin is one you control and that it ' +
          'is not, for example, a hostname that has been allowed to lapse.',
        remediation:
          'Keep the allow-list short, and confirm every entry still resolves to infrastructure ' +
          'you own.',
      });
    }

    return out;
  },
};

export const corsPreflightCheck: PassiveCheck = {
  id: 'AWB-P021',
  title: 'Preflight response is more permissive than it needs to be',
  description:
    'The headers and methods a preflight allows define what a cross-origin request may ' +
    'do, including whether it can send a content type that reaches a different parser.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined) return [];
    if (exchange.request.method.toUpperCase() !== 'OPTIONS') return [];

    const out: FindingDraft[] = [];
    const allowHeaders = getHeader(response.headers, 'access-control-allow-headers');
    const allowMethods = getHeader(response.headers, 'access-control-allow-methods');
    const credentials =
      (getHeader(response.headers, 'access-control-allow-credentials') ?? '').toLowerCase().trim() ===
      'true';
    const maxAge = getHeader(response.headers, 'access-control-max-age');

    if (allowHeaders !== undefined && allowHeaders.trim() === '*' && credentials) {
      out.push({
        check: this.id,
        title: 'Access-Control-Allow-Headers is * on a credentialed preflight',
        severity: 'medium',
        confidence: 'certain',
        detail:
          'The wildcard in Allow-Headers is ignored when credentials are allowed, so this ' +
          'preflight does not actually permit the headers it appears to. Requests that rely ' +
          'on it will fail, and the configuration suggests the intent was to allow anything.',
        remediation: 'List the headers the client genuinely sends.',
      });
    }

    if (allowMethods !== undefined && /\bTRACE\b/i.test(allowMethods)) {
      out.push({
        check: this.id,
        title: 'Preflight allows TRACE',
        severity: 'low',
        confidence: 'certain',
        detail:
          `Access-Control-Allow-Methods includes TRACE (${allowMethods}). TRACE echoes the ` +
          'request back, which historically combined with this to read headers script cannot.',
        remediation: 'Remove TRACE from the allowed methods, and disable it at the server.',
      });
    }

    if (maxAge !== undefined && Number(maxAge) > 86_400) {
      out.push({
        check: this.id,
        title: 'Preflight cached for longer than a day',
        severity: 'info',
        confidence: 'certain',
        detail:
          `Access-Control-Max-Age is ${maxAge} seconds. A tightening of the policy will not ` +
          'take effect for clients that already cached the old one, which makes the fix for ' +
          'any CORS finding slower to land than it looks.',
        remediation:
          'Keep Max-Age modest -- browsers cap it anyway (Chromium at 2 hours, Firefox at 24).',
      });
    }

    return out;
  },
};

export const CORS_CHECKS: readonly PassiveCheck[] = [corsCheck, corsPreflightCheck];
