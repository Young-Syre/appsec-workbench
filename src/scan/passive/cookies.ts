/**
 * Cookie checks.
 *
 * Every one of these is graded by what the cookie looks like it is for. A
 * missing `HttpOnly` on a session cookie is a real finding; the same on a
 * cookie called `theme` is not worth a line of anybody's report, and a tool
 * that grades them identically trains its user to skip the section.
 */

import { getAll } from '../../core/headers.js';
import {
  type FindingDraft,
  type PassiveCheck,
  looksLikeSessionCookie,
  parseSetCookie,
} from '../check.js';

export const cookieFlagsCheck: PassiveCheck = {
  id: 'AWB-P010',
  title: 'Cookie set without the attributes its contents require',
  description:
    'Secure keeps a cookie off plaintext requests, HttpOnly keeps it out of reach of ' +
    'script, and SameSite decides whether it rides along on a cross-site request.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined) return [];
    const https = exchange.request.url.startsWith('https://');
    const out: FindingDraft[] = [];

    for (const raw of getAll(response.headers, 'set-cookie')) {
      const cookie = parseSetCookie(raw);
      if (cookie === undefined) continue;
      const session = looksLikeSessionCookie(cookie.name);
      const attrs = cookie.attributes;

      // An expiry in the past is a deletion, and a deleted cookie's flags do
      // not matter. Reporting them is a classic false positive on logout.
      const expires = attrs.get('expires');
      const maxAge = attrs.get('max-age');
      const isDeletion =
        cookie.value.length === 0 ||
        maxAge === '0' ||
        (maxAge !== undefined && Number(maxAge) < 0) ||
        (expires !== undefined && Date.parse(expires) < Date.now());
      if (isDeletion) continue;

      if (!attrs.has('secure') && https) {
        out.push({
          check: this.id,
          title: `Cookie ${cookie.name} set without Secure`,
          severity: session ? 'medium' : 'low',
          confidence: 'certain',
          detail:
            `${cookie.name} was set over HTTPS without the Secure attribute, so the browser ` +
            'will also send it on a plaintext request to the same host. One http:// link, ' +
            'or one redirect that has not happened yet, is enough to put it on the wire.' +
            (session ? ' The name suggests it carries a session.' : ''),
          remediation: `Add Secure to ${cookie.name}.`,
        });
      }

      if (!attrs.has('httponly') && session) {
        out.push({
          check: this.id,
          title: `Session cookie ${cookie.name} set without HttpOnly`,
          severity: 'medium',
          confidence: 'firm',
          detail:
            `${cookie.name} is readable from JavaScript. Any script injection on this origin ` +
            'can read it and use it elsewhere, which turns a contained cross-site scripting ' +
            'bug into a session theft.',
          remediation:
            `Add HttpOnly to ${cookie.name}. If a script genuinely needs the value, that is ` +
            'usually a sign the value should be split into a readable part and a secret part.',
        });
      }

      const sameSite = (attrs.get('samesite') ?? '').toLowerCase();
      if (sameSite === '') {
        out.push({
          check: this.id,
          title: `Cookie ${cookie.name} set without SameSite`,
          severity: session ? 'low' : 'info',
          confidence: 'certain',
          detail:
            `${cookie.name} declares no SameSite. Chromium-based browsers default it to Lax, ` +
            'Firefox and Safari behave differently across versions, and relying on the ' +
            'default means the behaviour depends on the browser rather than on your intent.',
          remediation: `Declare SameSite explicitly on ${cookie.name}: Lax unless you need None.`,
        });
      } else if (sameSite === 'none' && !attrs.has('secure')) {
        out.push({
          check: this.id,
          title: `Cookie ${cookie.name} declares SameSite=None without Secure`,
          severity: 'medium',
          confidence: 'certain',
          detail:
            'SameSite=None requires Secure. Browsers reject the combination without it, so ' +
            `${cookie.name} is being dropped entirely -- which is a functional bug as well ` +
            'as a sign that the cross-site behaviour was not thought through.',
          remediation: 'Add Secure, and confirm the cookie really needs to be sent cross-site.',
        });
      } else if (sameSite === 'none' && session) {
        out.push({
          check: this.id,
          title: `Session cookie ${cookie.name} is sent on cross-site requests`,
          severity: 'low',
          confidence: 'firm',
          detail:
            `${cookie.name} declares SameSite=None, so it accompanies requests initiated by ` +
            'any site. That is the precondition for cross-site request forgery, and it means ' +
            'CSRF defence rests entirely on tokens or on Origin checking.',
          remediation:
            'Use SameSite=Lax unless a cross-site flow needs the cookie. Where None is ' +
            'required, verify that state-changing endpoints check a token or the Origin header.',
        });
      }

      const domain = attrs.get('domain');
      if (domain !== undefined && domain.length > 0) {
        const host = hostOf(exchange.request.url);
        const normalised = domain.startsWith('.') ? domain.slice(1) : domain;
        if (host !== undefined && normalised !== host && host.endsWith(normalised)) {
          out.push({
            check: this.id,
            title: `Cookie ${cookie.name} is scoped to a parent domain`,
            severity: session ? 'low' : 'info',
            confidence: 'certain',
            detail:
              `${cookie.name} was set by ${host} with Domain=${domain}, so every host under ` +
              `${normalised} receives it. Any one of them -- including a subdomain owned by a ` +
              'different team, or one that can be taken over -- can read it.',
            remediation:
              'Omit Domain so the cookie is host-only, unless sharing it across subdomains is ' +
              'a requirement you can name.',
          });
        }
      }

      if (!attrs.has('path')) {
        // Not a finding on its own; noted only for session cookies, where
        // path scoping is sometimes load-bearing.
        continue;
      }
    }

    return out;
  },
};

export const cookiePrefixCheck: PassiveCheck = {
  id: 'AWB-P011',
  title: 'Cookie name prefix contradicts its attributes',
  description:
    'The __Secure- and __Host- prefixes are enforced by the browser. A cookie whose ' +
    'name claims a guarantee its attributes do not meet is rejected outright.',
  run(exchange) {
    const response = exchange.response;
    if (response === undefined) return [];
    const out: FindingDraft[] = [];

    for (const raw of getAll(response.headers, 'set-cookie')) {
      const cookie = parseSetCookie(raw);
      if (cookie === undefined) continue;
      const attrs = cookie.attributes;

      if (cookie.name.startsWith('__Secure-') && !attrs.has('secure')) {
        out.push({
          check: this.id,
          title: `${cookie.name} uses the __Secure- prefix without Secure`,
          severity: 'low',
          confidence: 'certain',
          detail:
            'Browsers reject a __Secure- cookie that is not marked Secure, so this cookie is ' +
            'never stored. Whatever it was for is silently not happening.',
          remediation: 'Add Secure, or drop the prefix.',
        });
      }

      if (cookie.name.startsWith('__Host-')) {
        const problems: string[] = [];
        if (!attrs.has('secure')) problems.push('it is not marked Secure');
        if (attrs.has('domain')) problems.push('it sets a Domain attribute');
        if ((attrs.get('path') ?? '') !== '/') problems.push('its Path is not /');
        if (problems.length > 0) {
          out.push({
            check: this.id,
            title: `${cookie.name} uses the __Host- prefix but does not qualify`,
            severity: 'low',
            confidence: 'certain',
            detail:
              `A __Host- cookie must be Secure, must not set Domain, and must have Path=/. ` +
              `Here ${problems.join(', ')}, so the browser rejects it and the cookie is never ` +
              'stored.',
            remediation: 'Meet the prefix requirements, or use a name without the prefix.',
          });
        }
      }
    }

    return out;
  },
};

function hostOf(raw: string): string | undefined {
  try {
    return new URL(raw).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

export const COOKIE_CHECKS: readonly PassiveCheck[] = [cookieFlagsCheck, cookiePrefixCheck];
