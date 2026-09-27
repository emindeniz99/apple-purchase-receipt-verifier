package io.github.emindeniz99.applepurchasereceiptverifier;

/**
 * Why verification failed. The same values, with the same meaning, in every
 * port. Ordinals are not stable across 0.x releases: switch on the constant
 * or persist its {@link #name()}, never its {@link #ordinal()}.
 */
public enum Reason {
    /**
     * The base64, ASN.1, CMS or JWS structure is broken, or a structural
     * bound was exceeded (JSON nesting, embedded certificates, SignerInfos;
     * see "Resource bounds" in the README). Decided before any signature is
     * checked.
     */
    MALFORMED,
    /**
     * The input is over its fixed size cap (see "Resource bounds" in the
     * README). Decided before anything is decoded.
     */
    TOO_LARGE,
    /** The signature does not match the signed content. */
    INVALID_SIGNATURE,
    /** The certificate chain does not reach a pinned root, or is longer than the chain-length bound. */
    UNTRUSTED_CHAIN,
    /**
     * A certificate the check depends on does not decode, or is expired or
     * not yet valid at the signing instant.
     */
    INVALID_CERTIFICATE,
    /**
     * A certificate that chains to a pinned root but is of the wrong kind:
     * the leaf lacks Apple's signing marker OID or the intermediate lacks
     * Apple's WWDR marker OID. Developer certificates chain to the same roots,
     * so this is what keeps them from signing receipts or JWS payloads.
     */
    INVALID_CERTIFICATE_PURPOSE,
    /**
     * The signature and chain verified, so the payload bytes are Apple's, but
     * they do not parse. {@link Failure#cause()} carries the parser's
     * exception. Deterministic for the same input: alert, do not retry.
     */
    UNREADABLE_PAYLOAD,
    /**
     * The library itself failed before it could decide, for example a
     * runtime missing an algorithm. {@link Failure#cause()} carries the
     * exception. Deterministic for the same input: alert, do not retry.
     */
    INTERNAL_ERROR
}
