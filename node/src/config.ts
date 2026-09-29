/**
 * What a `Verifier` trusts and what time it thinks it is. Immutable.
 *
 * Roots default to Apple's three published roots, which are compiled into
 * aprv.wasm and pinned there; tests replace them with their own. The clock
 * answers "what time is it now?" and nothing else. It is read once per
 * verify call, before the input is looked at, and the module uses the
 * value only for the chain-validity instant when a receipt or JWS states
 * no usable signing date, and for `request_date` in the endpoint response.
 *
 * Nothing here parses a certificate: a root is handed to the module as its
 * DER bytes, and a root the module cannot read fails `createVerifier`.
 */

/** Accepted trust-root inputs: DER bytes, or a PEM certificate. */
export type RootInput = Uint8Array | string;

export interface Config {
  /**
   * The DER of each trusted root, in the caller's order, or `null` for
   * Apple's three roots pinned inside aprv.wasm.
   */
  readonly roots: readonly Uint8Array[] | null;
  readonly clock: () => number;
}

export interface CreateConfigOptions {
  /** Replaces the trusted roots. Leaving it out means Apple's pinned roots. */
  readonly roots?: readonly RootInput[];
  /** Replaces the clock. Leaving it out means the system clock (`Date.now`). */
  readonly clock?: () => number;
}

const PEM_BEGIN = '-----BEGIN CERTIFICATE-----';
const PEM_END = '-----END CERTIFICATE-----';

/**
 * The DER inside the first certificate block of a PEM string. Found with
 * two `indexOf` calls rather than a regular expression, which is quadratic
 * on many BEGIN lines with no END. The body goes through the platform's
 * `atob`; whether the bytes are a certificate is the module's call.
 */
function pemToDer(text: string): Uint8Array {
  const begin = text.indexOf(PEM_BEGIN);
  const end = begin < 0 ? -1 : text.indexOf(PEM_END, begin + PEM_BEGIN.length);
  if (end < 0) {
    throw new TypeError('a string trust root must be a PEM certificate');
  }
  let binary: string;
  try {
    binary = atob(text.slice(begin + PEM_BEGIN.length, end).replace(/\s+/g, ''));
  } catch {
    throw new TypeError('a PEM trust root must hold base64 between its BEGIN and END lines');
  }
  const der = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    der[i] = binary.charCodeAt(i);
  }
  return der;
}

function toDer(root: RootInput): Uint8Array {
  if (typeof root === 'string') {
    return pemToDer(root);
  }
  if (root instanceof Uint8Array) {
    // A copy, so a caller's later write to their buffer changes nothing here.
    return new Uint8Array(root);
  }
  throw new TypeError('a trust root must be a Uint8Array of DER or a PEM string');
}

function normalizeRoots(roots: readonly RootInput[]): readonly Uint8Array[] {
  if (!Array.isArray(roots) || roots.length === 0) {
    throw new TypeError('trustedRoots must be a non-empty array');
  }
  return Object.freeze(roots.map(toDer));
}

const systemClock = (): number => Date.now();

/** Apple's three pinned roots and the system clock. */
export function defaultConfig(): Config {
  return Object.freeze({ roots: null, clock: systemClock });
}

/** A config with explicit roots and/or clock; anything left out takes the default. */
export function createConfig(options: CreateConfigOptions = {}): Config {
  return Object.freeze({
    roots: options.roots === undefined ? null : normalizeRoots(options.roots),
    clock: options.clock ?? systemClock,
  });
}
