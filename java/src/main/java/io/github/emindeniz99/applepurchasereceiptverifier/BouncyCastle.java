package io.github.emindeniz99.applepurchasereceiptverifier;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * The one BouncyCastle provider instance this library names. Every
 * certificate decode, chain build or validation, signature check and digest
 * asks this instance, never the JVM's provider list, so neither the provider
 * order nor {@code jdk.certpath.disabledAlgorithms} decides which
 * certificates, chains and signatures are accepted. The one JVM service
 * BouncyCastle does use is the default {@code SecureRandom}, drawn from
 * when an RSA public key is first decoded; a default that throws makes a
 * genuine receipt answer {@code UNTRUSTED_CHAIN} ({@code java/README.md},
 * "One platform caveat").
 *
 * <p>BouncyCastle still reads settings of its own. Some
 * {@code org.bouncycastle.*} properties are looked up in
 * {@code java.security}, then a thread-local override, then the system
 * properties: the ASN.1 nesting bound, INTEGER, time, extension and
 * certificate encoding strictness, RSA and EC key bounds, and the path
 * builder's and validator's node bounds. Its PKIX builder and validator
 * also use a {@code BouncyCastleProvider} registered with {@code Security}
 * as "BC" when one exists, and their own otherwise. None of these can make a signature verify that does not. They
 * change which encodings parse and how much work is allowed. A host can
 * therefore make this library refuse genuine input (a nesting bound below 9
 * refuses every genuine receipt, which {@link Verifier#create} checks for),
 * or accept an unusual encoding of content that a valid signature covers.
 * {@code java/README.md} lists them.</p>
 */
final class BouncyCastle {

    /**
     * Used as an instance, never registered with Security.addProvider, so this
     * library never changes the JVM's global provider list. One instance
     * because building the provider is not free.
     */
    static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    private BouncyCastle() {}
}
