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

/**
 * A trust root: the certificate's DER bytes. A PEM string is not accepted;
 * in Node, `new X509Certificate(pem).raw` from `node:crypto` is its DER.
 */
export type RootInput = Uint8Array;

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

/**
 * The `TypeError` for a string root. It names the fix, which is why
 * test/no-logic.test.js lets this one literal name `node:crypto`.
 */
const PEM_ROOT_MESSAGE =
  'a trust root must be the DER bytes of a certificate, not a string: for a PEM certificate, pass new X509Certificate(pem).raw (X509Certificate is in node:crypto), or base64-decode the text between its BEGIN and END lines';

function toDer(root: RootInput): Uint8Array {
  if (typeof root === 'string') {
    throw new TypeError(PEM_ROOT_MESSAGE);
  }
  if (root instanceof Uint8Array) {
    // A copy, so a caller's later write to their buffer changes nothing here.
    return new Uint8Array(root);
  }
  throw new TypeError('a trust root must be a Uint8Array of DER');
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
