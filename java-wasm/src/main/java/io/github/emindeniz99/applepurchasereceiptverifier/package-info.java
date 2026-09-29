/**
 * Offline verification of Apple in-app purchase data against pinned Apple
 * roots: legacy PKCS#7 app receipts, StoreKit 2 JWS, and a local stand-in for
 * Apple's verifyReceipt endpoint. Start at {@link
 * io.github.emindeniz99.applepurchasereceiptverifier.Verifier}.
 *
 * <p>This is the {@code apple-purchase-receipt-verifier-wasm} artifact: the
 * same API as the main {@code apple-purchase-receipt-verifier} artifact,
 * answered by the shared Rust core ({@code aprv.wasm}) instead of the Java
 * implementation. {@link io.github.emindeniz99.applepurchasereceiptverifier.Engine}
 * says which engine runs it. Depend on exactly one of the two artifacts.</p>
 *
 * <p>Only the API types are public; the implementation classes are
 * package-private, and the {@code .endive} subpackage holds classes Endive
 * generated from the module. Both may change in any release.</p>
 *
 * <p>{@link org.jspecify.annotations.NullMarked}: every type in this package
 * is non-null unless it carries
 * {@link org.jspecify.annotations.Nullable}. The annotation jar is an
 * {@code optional} dependency; it is not needed at run time.
 */
@NullMarked
package io.github.emindeniz99.applepurchasereceiptverifier;

import org.jspecify.annotations.NullMarked;
