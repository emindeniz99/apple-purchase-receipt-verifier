/**
 * Legacy PKCS#7 app-receipt verification, the models it returns, and the
 * drop-in replacement for Apple's {@code verifyReceipt} endpoint.
 *
 * <p>{@link org.jspecify.annotations.NullMarked}: every type in this package
 * is non-null unless it carries {@link org.jspecify.annotations.Nullable}.
 * Every attribute accessor on {@link
 * io.github.emindeniz99.applepurchasereceiptverifier.receipt.AppReceipt} and
 * {@link
 * io.github.emindeniz99.applepurchasereceiptverifier.receipt.InAppPurchase}
 * is {@code @Nullable}, because a receipt carries only the attributes that
 * apply to it and an absent attribute reads as {@code null}.
 */
@NullMarked
package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import org.jspecify.annotations.NullMarked;
