package smoke;

import io.github.emindeniz99.applepurchasereceiptverifier.Config;
import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedHashSet;
import java.util.Set;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/** The smallest Spring Boot service that owns the verifier as a singleton bean. */
@SpringBootApplication
public class SmokeApplication {
    public static void main(String[] args) {
        SpringApplication.run(SmokeApplication.class, args);
    }

    /**
     * The bundled Apple roots, which also proves they load on a Boot
     * classpath, plus the repository's generated JWS fixture root, so the
     * shared sandbox JWS fixtures verify. A real service uses
     * {@code Config.defaults()} alone.
     */
    @Bean
    Verifier verifier() throws IOException, CertificateException {
        Set<X509Certificate> roots = new LinkedHashSet<>(Config.defaults().roots());
        roots.add(fixtureRoot("jws-root.der"));
        return Verifier.create(Config.builder().roots(roots).build());
    }

    private static X509Certificate fixtureRoot(String name) throws IOException, CertificateException {
        try (InputStream in = Files.newInputStream(Fixtures.dir().resolve("generated").resolve(name))) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }
}
