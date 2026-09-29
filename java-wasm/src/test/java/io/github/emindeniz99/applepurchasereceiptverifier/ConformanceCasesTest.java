package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.Set;
import org.junit.jupiter.api.Tag;

/**
 * The conformance cases on the Endive engine. While the module compiled in
 * is the round-13 stand-in, its differences are listed in
 * {@code stand-in-differences.txt}.
 */
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

    @Override
    Set<String> standInDifferences() throws Exception {
        return StandIn.differences();
    }

    @Override
    String standInFile() {
        return StandIn.FILE;
    }
}
