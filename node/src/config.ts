/**
 * What a `Verifier` trusts and what time it thinks it is. Immutable.
 *
 * Roots default to the three bundled, pinned Apple roots; tests replace
 * them with their own. The clock answers "what time is it now?" and
 * nothing else, read at most once per call and only for the chain-validity
 * instant when a receipt or JWS states no signing date, and `request_date`
 * in the endpoint response.
 */
import { createHash } from 'node:crypto';
import { base64Decode } from './bytes.js';
import { normalizeRoots, type RootInput } from './chain.js';
import { APPLE_ROOT_DER_BASE64 } from './roots-data.js';
import { parseCertificate, type ParsedCertificate } from './x509.js';

export interface Config {
  readonly roots: readonly ParsedCertificate[];
  readonly clock: () => number;
}

/**
 * SHA-256 of each bundled root's DER encoding, Apple's published root
 * fingerprints. A resource that does not match one of them is not the root
 * this library pins, wherever it came from.
 */
const PINNED_FINGERPRINTS: readonly string[] = [
  'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024',
  'c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050',
  '63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179',
];

function loadDefaultRoots(): ParsedCertificate[] {
  const roots = APPLE_ROOT_DER_BASE64.map((b64, i) => {
    const der = base64Decode(b64);
    const actual = createHash('sha256').update(der).digest('hex');
    const expected = PINNED_FINGERPRINTS[i];
    if (actual !== expected) {
      throw new Error(
        `bundled Apple root ${i} has SHA-256 ${actual}, expected ${expected}: the pinned Apple roots have been replaced`,
      );
    }
    return parseCertificate(der);
  });
  const distinct = new Set(roots.map((r) => Buffer.from(r.raw).toString('hex')));
  if (distinct.size !== roots.length) {
    throw new Error(`expected ${roots.length} distinct Apple roots, got ${distinct.size}`);
  }
  return roots;
}

let cachedDefaultRoots: ParsedCertificate[] | null = null;

/** The three roots, parsed and fingerprint-checked once. */
function defaultRoots(): ParsedCertificate[] {
  cachedDefaultRoots ??= loadDefaultRoots();
  return cachedDefaultRoots;
}

export interface CreateConfigOptions {
  /** Replaces the trusted roots. Leaving it out means Apple's bundled roots. */
  readonly roots?: readonly RootInput[];
  /** Replaces the clock. Leaving it out means the system clock (`Date.now`). */
  readonly clock?: () => number;
}

/**
 * Apple's three pinned roots and the system clock.
 *
 * @throws {Error} if the bundled roots are missing, do not parse, or do not
 * match their pinned fingerprints.
 */
export function defaultConfig(): Config {
  return { roots: defaultRoots(), clock: () => Date.now() };
}

/** A config with explicit roots and/or clock; anything left out takes the default. */
export function createConfig(options: CreateConfigOptions = {}): Config {
  const roots = options.roots === undefined ? defaultRoots() : normalizeRoots(options.roots);
  const clock = options.clock ?? (() => Date.now());
  return { roots, clock };
}
