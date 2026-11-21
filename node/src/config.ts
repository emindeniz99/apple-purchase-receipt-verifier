/**
 * What a `Verifier` trusts, what it refuses, and what time it thinks it is.
 * Immutable.
 *
 * Roots default to Apple's three published roots, which are compiled into
 * aprv.wasm and pinned there; tests replace them with their own. The clock
 * answers "what time is it now?" and nothing else. It is read once per
 * verify call, before the input is looked at, and the module uses the
 * value only for the chain-validity instant when a receipt or JWS states
 * no usable signing date, for `request_date` in the endpoint response, and
 * to judge whether a list holding a `certificateHold` entry is still fresh.
 *
 * Nothing here parses a certificate or a revocation list: a root, an
 * issuer and a list are handed to the module as the bytes the caller gave,
 * and anything the module cannot use fails `createVerifier`
 * (docs/design/revocation.md §4).
 */

/**
 * A trust root: the certificate's bytes, DER or PEM (a PEM bundle of several
 * certificates is one root entry). A string is refused: pass PEM text as its
 * bytes.
 */
export type RootInput = Uint8Array;

/**
 * A revocation key to refuse: the issuer id (64 hex digits, SHA-256 over the
 * issuing certificate's subject and subjectPublicKeyInfo as encoded) and the
 * revoked certificate's serial in hex. Either letter case. The module checks
 * both strings when the `Verifier` is built.
 */
export interface RevokedCertificate {
  readonly issuer: string;
  readonly serial: string;
}

export interface Config {
  /**
   * The bytes of each trusted root as given (DER or PEM), in the caller's
   * order, or `null` for Apple's three roots pinned inside aprv.wasm.
   */
  readonly roots: readonly Uint8Array[] | null;
  readonly clock: () => number;
  /** Revocation lists (CRL files exactly as downloaded, DER), in the caller's order. */
  readonly revocationLists: readonly Uint8Array[];
  /** CA certificates (DER or PEM) that sign lists, added to the built-in WWDR G5 and G6. */
  readonly revocationIssuers: readonly Uint8Array[];
  /** Revocation keys to refuse whatever the lists say. */
  readonly distrust: readonly RevokedCertificate[];
}

export interface CreateConfigOptions {
  /** Replaces the trusted roots. Leaving it out means Apple's pinned roots. */
  readonly roots?: readonly RootInput[];
  /** Replaces the clock. Leaving it out means the system clock (`Date.now`). */
  readonly clock?: () => number;
  /**
   * Apple's revocation lists, downloaded by the caller from the URLs
   * `Verifier.revocationUrls()` names (README, "Revocation"). Default none.
   */
  readonly revocationLists?: readonly Uint8Array[];
  /** Issuers of lists beyond the built-in ones, in the same form as `roots`. Default none. */
  readonly revocationIssuers?: readonly RootInput[];
  /** Revocation keys to refuse. Default none; at most 1,000. */
  readonly distrust?: readonly RevokedCertificate[];
}

function toBytes(root: RootInput): Uint8Array {
  if (!(root instanceof Uint8Array)) {
    throw new TypeError(
      'a trust root must be a Uint8Array of DER or PEM bytes; pass a PEM string as new TextEncoder().encode(pem) (see README, custom roots)',
    );
  }
  // A copy, so a caller's later write to their buffer changes nothing here.
  return new Uint8Array(root);
}

function normalizeRoots(roots: readonly RootInput[]): readonly Uint8Array[] {
  if (!Array.isArray(roots) || roots.length === 0) {
    throw new TypeError('roots must be a non-empty array');
  }
  return Object.freeze(roots.map(toBytes));
}

/** Copies of `items`, each a Uint8Array; `name` says which option was wrong. */
function normalizeBytes(
  items: readonly Uint8Array[] | undefined,
  name: string,
): readonly Uint8Array[] {
  if (items === undefined) {
    return Object.freeze([]);
  }
  if (!Array.isArray(items)) {
    throw new TypeError(`${name} must be an array`);
  }
  return Object.freeze(
    items.map((item) => {
      if (!(item instanceof Uint8Array)) {
        throw new TypeError(`each of ${name} must be a Uint8Array`);
      }
      return new Uint8Array(item);
    }),
  );
}

function normalizeDistrust(
  entries: readonly RevokedCertificate[] | undefined,
): readonly RevokedCertificate[] {
  if (entries === undefined) {
    return Object.freeze([]);
  }
  if (!Array.isArray(entries)) {
    throw new TypeError('distrust must be an array');
  }
  return Object.freeze(
    entries.map((entry: unknown) => {
      const { issuer, serial } = (entry ?? {}) as Record<string, unknown>;
      if (typeof issuer !== 'string' || typeof serial !== 'string') {
        throw new TypeError('each distrust entry must be { issuer: string, serial: string }');
      }
      // The strings as given: the module checks and normalises them.
      return Object.freeze({ issuer, serial });
    }),
  );
}

const systemClock = (): number => Date.now();

/**
 * The one way to build a config. Anything left out takes the default, so
 * `createConfig()` is Apple's three pinned roots, the system clock, and no
 * revocation setting beyond the list built into aprv.wasm.
 */
export function createConfig(options: CreateConfigOptions = {}): Config {
  return Object.freeze({
    roots: options.roots === undefined ? null : normalizeRoots(options.roots),
    clock: options.clock ?? systemClock,
    revocationLists: normalizeBytes(options.revocationLists, 'revocationLists'),
    revocationIssuers: normalizeBytes(options.revocationIssuers, 'revocationIssuers'),
    distrust: normalizeDistrust(options.distrust),
  });
}
