/**
 * Helpers shared by the verifiers. Public only because a Java 8 jar has no
 * module system to hide a package behind; nothing here is API, and nothing
 * here is kept stable between releases.
 *
 * <p>{@link org.jspecify.annotations.NullMarked}: every type in this package
 * is non-null unless it carries {@link org.jspecify.annotations.Nullable}.
 */
@NullMarked
package io.github.emindeniz99.applepurchasereceiptverifier.internal;

import org.jspecify.annotations.NullMarked;
