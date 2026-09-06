package smoke;

import io.github.emindeniz99.applepurchasereceiptverifier.AppleRootCerts;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.VerifyReceiptEndpoint;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/** The smallest Spring Boot service that owns the verifiers as singleton beans. */
@SpringBootApplication
public class SmokeApplication {
    public static void main(String[] args) {
        SpringApplication.run(SmokeApplication.class, args);
    }

    /**
     * Anchored on the repository's generated fixture root, not Apple's, so the
     * shared sandbox JWS fixtures verify. A real service passes
     * {@code AppleRootCerts.jwsRoots()} here instead.
     */
    @Bean
    JwsVerifier jwsVerifier() throws IOException, CertificateException {
        Set<X509Certificate> roots = Collections.singleton(fixtureRoot("jws-root.der"));
        return new JwsVerifier(roots, "com.example.app", EnumSet.of(Environment.SANDBOX), 123456789L, null);
    }

    /** Anchored on the bundled Apple roots: this bean also proves the anchors load on a Boot classpath. */
    @Bean
    ReceiptVerifier receiptVerifier() {
        return new ReceiptVerifier(AppleRootCerts.receiptRoots(), "dev.bonzer.weeka.app");
    }

    @Bean
    VerifyReceiptEndpoint verifyReceiptEndpoint() {
        return new VerifyReceiptEndpoint(AppleRootCerts.receiptRoots(), Environment.SANDBOX);
    }

    private static X509Certificate fixtureRoot(String name) throws IOException, CertificateException {
        try (InputStream in = Files.newInputStream(Fixtures.dir().resolve("generated").resolve(name))) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }
}
