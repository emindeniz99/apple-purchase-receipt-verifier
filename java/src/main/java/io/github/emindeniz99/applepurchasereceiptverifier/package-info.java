/**
 * Offline verification of Apple in-app purchase data against pinned Apple
 * roots: legacy PKCS#7 app receipts, StoreKit 2 JWS, and a local stand-in for
 * Apple's verifyReceipt endpoint. Start at {@link
 * io.github.emindeniz99.applepurchasereceiptverifier.Verifier}.
 *
 * <p>Only the API types are public; the implementation classes are
 * package-private and may change in any release.</p>
 *
 * <p>{@link org.jspecify.annotations.NullMarked}: every type in this package
 * is non-null unless it carries
 * {@link org.jspecify.annotations.Nullable}. The annotation jar is an
 * {@code optional} dependency; it is not needed at run time.
 */
@NullMarked
package io.github.emindeniz99.applepurchasereceiptverifier;

import org.jspecify.annotations.NullMarked;
