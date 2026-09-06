package smoke;

import java.nio.file.Path;
import java.nio.file.Paths;

/** Locates the repository's shared fixtures: {@code -Dfixtures.dir} or the checkout-relative default. */
final class Fixtures {
    private Fixtures() {}

    static Path dir() {
        String override = System.getProperty("fixtures.dir");
        if (override != null) {
            return Paths.get(override);
        }
        return Paths.get("..", "..", "..", "fixtures").toAbsolutePath().normalize();
    }
}
