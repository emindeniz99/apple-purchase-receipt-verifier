package io.github.emindeniz99.applepurchasereceiptverifier.internal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * The one BouncyCastle provider instance this library uses, and the only
 * provider it uses: every certificate decode, chain build or validation,
 * signature check and digest goes through it, so the JVM's provider list and
 * {@code java.security} policy cannot change a verdict.
 *
 * <p>This package is an implementation detail of the library. It is public
 * only because Java packages are not nested, and the classes that need it sit
 * in two different packages; nothing in it is API and it may change in any
 * release.
 */
public final class BouncyCastle {

    /**
     * Used as an instance, never registered with Security.addProvider, so this
     * library never changes the JVM's global provider list. One instance
     * because building the provider is not free.
     */
    public static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    private BouncyCastle() {}
}
