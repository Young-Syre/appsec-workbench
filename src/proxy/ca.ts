/**
 * A local certificate authority, built with the openssl binary.
 *
 * Intercepting TLS means minting a certificate per host, which means a CA the
 * browser trusts. Node cannot create a certificate -- `crypto.X509Certificate`
 * parses, it does not issue -- so the usual answer is a dependency like
 * node-forge. openssl is already on every machine that runs this, it is the
 * reference implementation, and shelling out to it keeps the dependency count
 * at zero for the one piece of the tool a reader is most likely to want to
 * audit.
 *
 * Two deliberate choices:
 *
 *   - **EC P-256, not RSA.** Leaf certificates are minted on demand, once per
 *     host, in the TLS handshake path. RSA-2048 keygen takes tens to hundreds
 *     of milliseconds and the browser is waiting; P-256 is immediate.
 *   - **One leaf key for every host.** Only the certificate differs per host.
 *     The private key never leaves this machine, and generating a fresh key
 *     per host buys nothing while costing a keygen per new origin.
 *
 * The CA private key is the sensitive artefact here. Anyone holding it can
 * impersonate any site to a browser that trusts it, so it is written 0600, it
 * is gitignored, and `awb ca trust` prints what trusting it actually means
 * before it tells you how.
 */

import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { X509Certificate, createHash } from 'node:crypto';
import { isIP } from 'node:net';

export interface CaPaths {
  readonly dir: string;
  readonly caCert: string;
  readonly caKey: string;
  readonly leafKey: string;
}

export interface CertPair {
  readonly cert: string;
  readonly key: string;
}

/** How long a minted leaf is valid. Short, because they are free to remint. */
const LEAF_DAYS = 30;
/** How long the CA lives. A year: long enough to be convenient, short enough to expire. */
const CA_DAYS = 365;

export function opensslVersion(): string {
  try {
    return execFileSync('openssl', ['version'], { encoding: 'utf8' }).trim();
  } catch (err) {
    throw new Error(
      'openssl is not on PATH, and the proxy needs it to mint certificates. ' +
        'Install it (it ships with every mainstream distribution and with macOS) ' +
        `and try again. Underlying error: ${(err as Error).message}`,
    );
  }
}

function run(args: readonly string[], cwd?: string): void {
  try {
    execFileSync('openssl', args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      ...(cwd === undefined ? {} : { cwd }),
    });
  } catch (err) {
    const e = err as { stderr?: Buffer; message: string };
    const detail = e.stderr?.toString().trim();
    throw new Error(
      `openssl ${args[0]} failed${detail ? `: ${detail}` : ''} (${e.message})`,
    );
  }
}

export function caPaths(dir: string): CaPaths {
  return {
    dir,
    caCert: join(dir, 'ca.crt'),
    caKey: join(dir, 'ca.key'),
    leafKey: join(dir, 'leaf.key'),
  };
}

export function caExists(dir: string): boolean {
  const p = caPaths(dir);
  return existsSync(p.caCert) && existsSync(p.caKey) && existsSync(p.leafKey);
}

/**
 * Create the CA and the shared leaf key.
 *
 * The common name says what it is in plain words, because it is going to turn
 * up in somebody's keychain and they should be able to tell at a glance that
 * it is a local testing CA and not something that belongs there permanently.
 */
export function createCa(dir: string, label = 'appsec-workbench local CA'): CaPaths {
  opensslVersion();
  mkdirSync(dir, { recursive: true });
  const p = caPaths(dir);

  run([
    'req',
    '-x509',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:prime256v1',
    '-nodes',
    '-keyout',
    p.caKey,
    '-out',
    p.caCert,
    '-days',
    String(CA_DAYS),
    '-subj',
    `/CN=${label}/O=appsec-workbench/OU=local testing only`,
    '-addext',
    'basicConstraints=critical,CA:TRUE,pathlen:0',
    '-addext',
    'keyUsage=critical,keyCertSign,cRLSign',
    '-addext',
    'subjectKeyIdentifier=hash',
  ]);

  run(['ecparam', '-genkey', '-name', 'prime256v1', '-noout', '-out', p.leafKey]);

  chmodSync(p.caKey, 0o600);
  chmodSync(p.leafKey, 0o600);
  chmodSync(p.caCert, 0o644);
  return p;
}

export function ensureCa(dir: string, label?: string): CaPaths {
  return caExists(dir) ? caPaths(dir) : createCa(dir, label);
}

/**
 * The CA's SHA-256 fingerprint, for the human to compare against what their
 * trust store shows after they install it.
 */
export function caFingerprint(dir: string): string {
  const pem = readFileSync(caPaths(dir).caCert, 'utf8');
  const cert = new X509Certificate(pem);
  return cert.fingerprint256;
}

export function caSubject(dir: string): string {
  return new X509Certificate(readFileSync(caPaths(dir).caCert, 'utf8')).subject;
}

export function caValidTo(dir: string): string {
  return new X509Certificate(readFileSync(caPaths(dir).caCert, 'utf8')).validTo;
}

/**
 * A subjectAltName entry for a host, which is the only thing a modern client
 * looks at. Common Name has been ignored by Chrome since 58 and by Firefox
 * since 48, so a certificate that only sets CN simply does not work.
 */
function sanFor(host: string): string {
  const version = isIP(host);
  if (version !== 0) return `IP:${host}`;
  return `DNS:${host}`;
}

/**
 * Mint a leaf certificate for one host, signed by the CA.
 *
 * A wildcard is added alongside the exact name for ordinary hostnames so that
 * one certificate covers `app.example.com` and its siblings, which cuts the
 * number of handshake-time mints on a site that spreads assets over
 * subdomains.
 */
export function mintCert(paths: CaPaths, host: string): CertPair {
  const work = mkdtempSync(join(tmpdir(), 'awb-cert-'));
  try {
    const csr = join(work, 'leaf.csr');
    const crt = join(work, 'leaf.crt');
    const ext = join(work, 'leaf.ext');

    const names = [sanFor(host)];
    if (isIP(host) === 0) {
      const labels = host.split('.');
      if (labels.length > 2) names.push(`DNS:*.${labels.slice(1).join('.')}`);
    }

    writeFileSync(
      ext,
      [
        `subjectAltName=${names.join(',')}`,
        'basicConstraints=critical,CA:FALSE',
        'keyUsage=critical,digitalSignature,keyEncipherment',
        'extendedKeyUsage=serverAuth',
        'subjectKeyIdentifier=hash',
        'authorityKeyIdentifier=keyid,issuer',
        '',
      ].join('\n'),
    );

    run(['req', '-new', '-key', paths.leafKey, '-out', csr, '-subj', `/CN=${host}`]);
    run([
      'x509',
      '-req',
      '-in',
      csr,
      '-CA',
      paths.caCert,
      '-CAkey',
      paths.caKey,
      '-out',
      crt,
      '-days',
      String(LEAF_DAYS),
      '-sha256',
      '-extfile',
      ext,
      // A deterministic-but-unique serial. Reusing serials across certs from
      // one issuer makes some clients reject the second one.
      '-set_serial',
      `0x${serialFor(host)}`,
    ]);

    return { cert: readFileSync(crt, 'utf8'), key: readFileSync(paths.leafKey, 'utf8') };
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

function serialFor(host: string): string {
  // Positive 63-bit serial derived from the host, so reminting the same host
  // yields the same serial and a client that cached it is not surprised.
  const digest = createHash('sha256').update(host).digest('hex').slice(0, 16);
  const first = parseInt(digest.slice(0, 1), 16) & 0x7;
  return first.toString(16) + digest.slice(1);
}

/**
 * Certificates, minted once per host and kept for the life of the process.
 *
 * Bounded, because a crawl of an application that embeds third-party widgets
 * will ask about dozens of hosts and an unbounded cache in a long-running
 * proxy is a slow leak.
 */
export class CertCache {
  private readonly paths: CaPaths;
  private readonly cache = new Map<string, CertPair>();
  private readonly limit: number;
  /** Counted so the proxy can report how much work the handshake path did. */
  minted = 0;

  constructor(paths: CaPaths, limit = 256) {
    this.paths = paths;
    this.limit = limit;
  }

  for(host: string): CertPair {
    const key = host.toLowerCase();
    const hit = this.cache.get(key);
    if (hit !== undefined) {
      // Refresh recency: delete and reinsert, so the oldest key is evicted.
      this.cache.delete(key);
      this.cache.set(key, hit);
      return hit;
    }
    const pair = mintCert(this.paths, key);
    this.minted += 1;
    if (this.cache.size >= this.limit) {
      const oldest = this.cache.keys().next();
      if (!oldest.done) this.cache.delete(oldest.value);
    }
    this.cache.set(key, pair);
    return pair;
  }

  size(): number {
    return this.cache.size;
  }
}

/** Platform-specific instructions, printed rather than executed. */
export function trustInstructions(certPath: string): string {
  return [
    'Trusting this CA lets anything holding its private key impersonate any',
    'website to this machine. Install it only on a machine you use for',
    'testing, and remove it when you are done.',
    '',
    `  CA certificate: ${certPath}`,
    '',
    'Firefox (its own trust store, independent of the system one):',
    '  Settings -> Privacy & Security -> Certificates -> View Certificates',
    '  -> Authorities -> Import, then tick "Trust this CA to identify websites".',
    '',
    'Chrome and Chromium on Linux (NSS, per user):',
    `  certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n appsec-workbench -i ${certPath}`,
    '',
    'System trust store, Debian and Ubuntu:',
    `  sudo cp ${certPath} /usr/local/share/ca-certificates/appsec-workbench.crt`,
    '  sudo update-ca-certificates',
    '',
    'System trust store, Fedora and RHEL:',
    `  sudo cp ${certPath} /etc/pki/ca-trust/source/anchors/appsec-workbench.crt`,
    '  sudo update-ca-trust',
    '',
    'macOS:',
    `  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${certPath}`,
    '',
    'curl, for one command and no trust store changes at all:',
    `  curl --proxy http://127.0.0.1:8080 --cacert ${certPath} https://target.example/`,
    '',
    'The browser driven by `awb browse` needs none of this: it is launched',
    'with this CA passed in, and it trusts nothing else extra.',
  ].join('\n');
}
