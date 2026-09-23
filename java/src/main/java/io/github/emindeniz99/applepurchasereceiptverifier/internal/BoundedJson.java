package io.github.emindeniz99.applepurchasereceiptverifier.internal;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;

/**
 * The Jackson reader constraints both JSON readers use (JWS segments and the
 * verifyReceipt request body). An implementation detail, public only because
 * the two readers sit in different packages; see {@link SafeText}.
 */
public final class BoundedJson {

    /**
     * How deep a JSON structure may nest. Both readers parse input no
     * signature has vouched for yet. Jackson 2.15 and later default to 1000,
     * but that is a default: a host BOM that pins an older Jackson 2 links
     * cleanly and silently loses the guard, so the constraint is stated here
     * instead of inherited. Apple's payloads and a verifyReceipt body are flat
     * objects, so 64 is far above anything real.
     */
    public static final int MAX_NESTING_DEPTH = 64;

    private BoundedJson() {}

    /**
     * A factory whose reader enforces {@link #MAX_NESTING_DEPTH} and bounds
     * every string and the whole document to {@code maxLength}, stated rather
     * than inherited from whatever Jackson the host resolved.
     * {@link StreamReadConstraints} needs Jackson 2.15 and
     * {@code maxDocumentLength} needs 2.16; below that floor this call fails
     * loudly at construction instead of leaving the library running with
     * guards it believes it set.
     */
    public static JsonFactory factory(int maxLength) {
        return JsonFactory.builder()
                .streamReadConstraints(StreamReadConstraints.builder()
                        .maxNestingDepth(MAX_NESTING_DEPTH)
                        .maxStringLength(maxLength)
                        .maxDocumentLength(maxLength)
                        .build())
                .build();
    }
}
