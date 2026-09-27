package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;

/**
 * The Jackson reader constraints both JSON readers use (JWS segments and the
 * verifyReceipt request body).
 */
final class BoundedJson {

    /**
     * How deep a JSON structure may nest. Both readers parse input no
     * signature has vouched for yet. Jackson 2.15 and later default to 1000,
     * but that is a default: a host BOM that pins an older Jackson 2 links
     * cleanly and silently loses the guard, so the constraint is stated here
     * instead of inherited. Apple's payloads and a verifyReceipt body are flat
     * objects, so 64 is far above anything real.
     */
    static final int MAX_NESTING_DEPTH = 64;

    /**
     * The longest member name, in characters. Jackson's own default, stated
     * for the same reason as {@link #MAX_NESTING_DEPTH}.
     */
    static final int MAX_NAME_LENGTH = 50_000;

    /** The longest number, in characters. Jackson's own default, stated likewise. */
    static final int MAX_NUMBER_LENGTH = 1000;

    private BoundedJson() {}

    /**
     * A factory whose reader enforces {@link #MAX_NESTING_DEPTH},
     * {@link #MAX_NAME_LENGTH} and {@link #MAX_NUMBER_LENGTH}, and bounds
     * every string and the whole document to {@code maxLength}, stated rather
     * than inherited from whatever Jackson the host resolved.
     * {@link StreamReadConstraints} needs Jackson 2.15, and
     * {@code maxDocumentLength} and {@code maxNameLength} need 2.16; below
     * that floor this call fails with a {@link LinkageError} in the static
     * initialiser of the class that calls it, which {@link Verifier#create}
     * runs and reports as an {@link IllegalStateException}, instead of
     * leaving the library running with guards it believes it set.
     */
    static JsonFactory factory(int maxLength) {
        return JsonFactory.builder()
                .streamReadConstraints(StreamReadConstraints.builder()
                        .maxNestingDepth(MAX_NESTING_DEPTH)
                        .maxNameLength(MAX_NAME_LENGTH)
                        .maxNumberLength(MAX_NUMBER_LENGTH)
                        .maxStringLength(maxLength)
                        .maxDocumentLength(maxLength)
                        .build())
                .build();
    }
}
