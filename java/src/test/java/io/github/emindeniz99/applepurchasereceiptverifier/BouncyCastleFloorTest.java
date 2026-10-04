package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Provider;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * What {@link Verifier#create} demands of BouncyCastle beyond its classes
 * loading: bcprov 1.86 or later, and an ASN.1 nesting bound that lets a
 * genuine receipt parse.
 *
 * <p>A unit test cannot swap the bcprov jar, so the version check is driven
 * through stand-in providers that report a version, the way BouncyCastle's
 * own provider reports its release. The nesting tests set
 * {@code org.bouncycastle.asn1.max_cons_depth} and restore it in a
 * {@code finally}. BouncyCastle reads that property each time it opens an
 * ASN.1 stream and caches nothing, and this suite runs its test classes one
 * at a time in one JVM (the pom configures no parallel execution), so no
 * other test sees the lowered value.</p>
 */
class BouncyCastleFloorTest {

    private static final String MAX_CONS_DEPTH = "org.bouncycastle.asn1.max_cons_depth";

    private static Provider reporting(double version) {
        return new Provider("BC", version, "reports a BouncyCastle release") {
            private static final long serialVersionUID = 1L;
        };
    }

    /**
     * 1.81 throws StackOverflowError out of verifyReceipt on a deeply nested
     * receipt, 1.84 has the nesting bound but not the 1.85 CVE fixes; every
     * one of these links, so only the version can refuse them.
     */
    @Test
    void aBcprovBelowTheFloorIsRefusedByName() {
        for (double old : new double[] {1.70, 1.81, 1.84, 1.85}) {
            IllegalStateException e = assertThrows(
                    IllegalStateException.class, () -> DefaultVerifier.requireBouncyCastle(reporting(old)));
            assertTrue(e.getMessage().startsWith("BouncyCastle bcprov " + old + " "), e.getMessage());
            assertTrue(e.getMessage().contains("1.86 or later"), e.getMessage());
            assertTrue(e.getMessage().contains("CVE-2026-13506"), e.getMessage());
            assertTrue(e.getMessage().contains("CVE-2026-12860"), e.getMessage());
        }
    }

    @Test
    void theFloorAndLaterReleasesPass() {
        for (double version : new double[] {1.86, 1.87, 2.0}) {
            DefaultVerifier.requireBouncyCastle(reporting(version));
        }
    }

    /**
     * The jar this build resolves is the one create checks, and the pom's pin
     * may never fall below the floor the code enforces.
     */
    @Test
    void thePinnedBouncyCastleMeetsTheFloorAndCreateAcceptsIt() throws Exception {
        String pom = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        Matcher pin = Pattern.compile("<bouncycastle.version>([^<]+)</bouncycastle.version>")
                .matcher(pom);
        assertTrue(pin.find(), "no bouncycastle.version in pom.xml");
        double pinned = Double.parseDouble(pin.group(1));
        assertTrue(pinned >= DefaultVerifier.BOUNCY_CASTLE_FLOOR, "pom pins BouncyCastle " + pinned);
        assertEquals(pinned, BouncyCastle.PROVIDER.getVersion());
        DefaultVerifier.requireBouncyCastle(BouncyCastle.PROVIDER);
        assertNotNull(Verifier.create(Config.defaults()));
    }

    /**
     * Nine is the exact need: at 8 the genuine receipt is MALFORMED and
     * create refuses, at 9 both pass. Without the probe the lowered bound
     * would show up only as MALFORMED on every genuine receipt.
     */
    @Test
    void createRefusesANestingBoundGenuineReceiptsDoNotFit() throws Exception {
        String legacy = new String(
                        Files.readAllBytes(TestFixtures.publicReceipts().resolve("receipt-sandbox-legacy.b64")),
                        StandardCharsets.US_ASCII)
                .trim();
        Verifier before = Verifier.create(Config.defaults());
        String previous = System.getProperty(MAX_CONS_DEPTH);
        try {
            System.setProperty(MAX_CONS_DEPTH, String.valueOf(DefaultVerifier.RECEIPT_NESTING - 1));
            assertEquals(
                    Reason.MALFORMED, before.verifyReceipt(legacy).failure().reason());
            IllegalStateException e =
                    assertThrows(IllegalStateException.class, () -> Verifier.create(Config.defaults()));
            assertTrue(e.getMessage().contains(MAX_CONS_DEPTH + " is set below 9"), e.getMessage());
            assertNotNull(e.getCause());

            System.setProperty(MAX_CONS_DEPTH, String.valueOf(DefaultVerifier.RECEIPT_NESTING));
            assertTrue(Verifier.create(Config.defaults()).verifyReceipt(legacy).verified());
        } finally {
            if (previous == null) {
                System.clearProperty(MAX_CONS_DEPTH);
            } else {
                System.setProperty(MAX_CONS_DEPTH, previous);
            }
        }
        assertTrue(before.verifyReceipt(legacy).verified());
    }
}
