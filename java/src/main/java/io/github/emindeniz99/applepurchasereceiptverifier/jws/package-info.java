/**
 * StoreKit 2 / App Store Server JWS verification and the payload models it
 * returns.
 *
 * <p>{@link org.jspecify.annotations.NullMarked}: every type in this package
 * is non-null unless it carries {@link org.jspecify.annotations.Nullable}.
 * Every claim accessor on {@link
 * io.github.emindeniz99.applepurchasereceiptverifier.jws.TransactionPayload}
 * and {@link
 * io.github.emindeniz99.applepurchasereceiptverifier.jws.AppTransactionPayload}
 * is {@code @Nullable}, because Apple omits claims that do not apply and an
 * absent claim reads as {@code null}.
 */
@NullMarked
package io.github.emindeniz99.applepurchasereceiptverifier.jws;

import org.jspecify.annotations.NullMarked;
