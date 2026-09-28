package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;

/**
 * The Jackson reader constraints both JSON readers use (JWS segments and the
 * verifyReceipt request body).
 */
final class BoundedJson {

    /** Stated rather than inherited, like the two below: a host can pin a Jackson with other defaults. */
    static final int MAX_NESTING_DEPTH = 64;

    /** In characters; Jackson's own default. */
    static final int MAX_NAME_LENGTH = 50_000;

    /** In characters; Jackson's own default. */
    static final int MAX_NUMBER_LENGTH = 1000;

    private BoundedJson() {}

    /**
     * A factory enforcing the bounds above, with every string and the whole
     * document held to {@code maxLength}. Below Jackson 2.16 this throws a
     * {@link LinkageError}, which {@link Verifier#create} reports.
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
