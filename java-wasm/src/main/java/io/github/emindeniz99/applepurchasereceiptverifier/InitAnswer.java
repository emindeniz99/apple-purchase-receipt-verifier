package io.github.emindeniz99.applepurchasereceiptverifier;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import org.jspecify.annotations.Nullable;

/**
 * What the module's {@code init} answered for a configuration it accepted
 * ({@code rust/bindings/wire/schema/init-result.schema.json}), read by the
 * Endive engine from the module and by the server engine from
 * {@code GET /v1/info}, which passes the same values on. Nothing here is
 * computed from a certificate or a list.
 */
final class InitAnswer {

    /** The most bytes of one input the module needs (DECISIONS.md R42). */
    final int maxInputBytes;
    /** The lists the configuration expects, in the module's order; unmodifiable. */
    final List<String> revocationUrls;
    /** The earliest {@code nextUpdate} of the lists held, or null (docs/design/revocation.md §7). */
    final @Nullable Long revocationValidUntilMs;

    InitAnswer(int maxInputBytes, List<String> revocationUrls, @Nullable Long revocationValidUntilMs) {
        this.maxInputBytes = maxInputBytes;
        this.revocationUrls = Collections.unmodifiableList(revocationUrls);
        this.revocationValidUntilMs = revocationValidUntilMs;
    }

    @Nullable
    Instant revocationValidUntil() {
        return revocationValidUntilMs == null ? null : Instant.ofEpochMilli(revocationValidUntilMs);
    }
}
