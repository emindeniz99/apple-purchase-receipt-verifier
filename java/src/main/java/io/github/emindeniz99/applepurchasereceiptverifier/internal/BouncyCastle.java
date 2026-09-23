package io.github.emindeniz99.applepurchasereceiptverifier.internal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * The one BouncyCastle provider instance this library uses, shared by the
 * receipt verifier's CMS check and the JWS verifier's ES256 check.
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
