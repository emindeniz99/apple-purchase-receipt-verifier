/**
 * What a `Verifier` trusts and what time it thinks it is — the web build's
 * `Config`, async because loading the bundled roots checks their SHA-256
 * fingerprint through `crypto.subtle`.
 */
import { base64Decode } from '../bytes.js';
import { APPLE_ROOT_DER_BASE64 } from '../roots-data.js';
import { parseCertificate, type ParsedCertificate } from '../x509.js';
import { normalizeRoots, type RootInput } from './chain.js';
import { digest } from './crypto.js';

export interface Config {
  readonly roots: readonly ParsedCertificate[];
  readonly clock: () => number;
}

/** SHA-256 of each bundled root's DER encoding, Apple's published root fingerprints. */
const PINNED_FINGERPRINTS: readonly string[] = [
  'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024',
  'c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050',
  '63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179',
];

function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, '0');
  }
  return out;
}

let cachedDefaultRoots: ParsedCertificate[] | null = null;

async function loadDefaultRoots(): Promise<ParsedCertificate[]> {
  const roots: ParsedCertificate[] = [];
  for (let i = 0; i < APPLE_ROOT_DER_BASE64.length; i++) {
    const der = base64Decode(APPLE_ROOT_DER_BASE64[i]!);
    // oxlint-disable-next-line no-await-in-loop
    const actual = toHex(await digest('sha256', der));
    const expected = PINNED_FINGERPRINTS[i];
    if (actual !== expected) {
      throw new Error(
        `bundled Apple root ${i} has SHA-256 ${actual}, expected ${expected}: the pinned Apple roots have been replaced`,
      );
    }
    roots.push(parseCertificate(der));
  }
  const distinct = new Set(roots.map((r) => toHex(r.raw)));
  if (distinct.size !== roots.length) {
    throw new Error(`expected ${roots.length} distinct Apple roots, got ${distinct.size}`);
  }
  return roots;
}

async function defaultRoots(): Promise<ParsedCertificate[]> {
  cachedDefaultRoots ??= await loadDefaultRoots();
  return cachedDefaultRoots;
}

export interface CreateConfigOptions {
  readonly roots?: readonly RootInput[];
  readonly clock?: () => number;
}

/**
 * Apple's three pinned roots and the system clock.
 *
 * @throws {Error} if the bundled roots are missing, do not parse, or do not
 * match their pinned fingerprints.
 */
export async function defaultConfig(): Promise<Config> {
  return { roots: await defaultRoots(), clock: () => Date.now() };
}

/** A config with explicit roots and/or clock; anything left out takes the default. */
export async function createConfig(options: CreateConfigOptions = {}): Promise<Config> {
  const roots = options.roots === undefined ? await defaultRoots() : normalizeRoots(options.roots);
  const clock = options.clock ?? (() => Date.now());
  return { roots, clock };
}
