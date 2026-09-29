package io.github.emindeniz99.applepurchasereceiptverifier;

import org.junit.jupiter.api.Tag;

/** The conformance cases on the Endive engine: every case must pass. */
@Tag("endive")
class ConformanceCasesTest extends ConformanceCases {

    @Override
    String engineName() {
        return "Endive";
    }

    @Override
    Verifier verifier(Config config) {
        return Verifier.create(config, Engine.endive());
    }
}
