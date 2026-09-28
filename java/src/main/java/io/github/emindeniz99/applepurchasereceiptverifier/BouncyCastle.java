package io.github.emindeniz99.applepurchasereceiptverifier;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * The one BouncyCastle provider instance this library uses, and the only
 * provider it uses: every certificate decode, chain build or validation,
 * signature check and digest goes through it, so the JVM's provider list and
 * {@code java.security} policy cannot change a verdict.
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
