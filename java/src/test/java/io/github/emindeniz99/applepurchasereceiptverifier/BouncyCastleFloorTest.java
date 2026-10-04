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

    /** A provider built as BouncyCastle builds its own: the release as a double and in the info string. */
    private static Provider reporting(double version, String info) {
        return new Provider("BC", version, info) {
            private static final long serialVersionUID = 1L;
        };
    }

    private static Provider release(double version, String release) {
        return reporting(version, "BouncyCastle Security Provider v" + release);
    }

    /**
     * 1.81 throws StackOverflowError out of verifyReceipt on a deeply nested
     * receipt, 1.84 has the nesting bound but not the 1.85 fixes; every one
     * of these links, so only the version can refuse them. BouncyCastle
     * encodes a patch release in the double (1.81.1 is 1.8101), so the
     * message names the info string rather than that number.
     */
    @Test
    void aBcprovBelowTheFloorIsRefusedByName() {
        Provider[] old = {
            release(1.70, "1.70"),
            release(1.81, "1.81"),
            release(1.8101, "1.81.1"),
            release(1.84, "1.84"),
            release(1.85, "1.85"),
            release(1.8502, "1.85.2"),
            reporting(1.85, "no release named here"),
        };
        for (Provider provider : old) {
            IllegalStateException e =
                    assertThrows(IllegalStateException.class, () -> DefaultVerifier.requireBouncyCastle(provider));
            assertTrue(
                    e.getMessage().startsWith("BouncyCastle bcprov on the classpath is \"" + provider.getInfo() + "\""),
                    e.getMessage());
            assertTrue(e.getMessage().contains("1.86 or later"), e.getMessage());
            assertTrue(e.getMessage().contains("CVE-2026-12860"), e.getMessage());
        }
    }

    /** Compared by parts: 1.100 is later than 1.86, though the double 1.1 is not. */
    @Test
    void theFloorAndLaterReleasesPass() {
        Provider[] current = {
            release(1.86, "1.86"),
            release(1.8601, "1.86.1"),
            release(1.87, "1.87"),
            release(1.1, "1.100"),
            release(2.0, "2.0"),
            reporting(1.86, "no release named here"),
        };
        for (Provider provider : current) {
            DefaultVerifier.requireBouncyCastle(provider);
        }
    }

    /**
     * The jar this build resolves is the one create checks, and the pom's pin
     * may never fall below the floor the code enforces. Compared as text and
     * by parts, since a patch pin such as 1.86.1 is not a number.
     */
    @Test
    void thePinnedBouncyCastleMeetsTheFloorAndCreateAcceptsIt() throws Exception {
        String pom = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        Matcher pin = Pattern.compile("<bouncycastle.version>(\\d+)\\.(\\d+)(\\.\\d+)?</bouncycastle.version>")
                .matcher(pom);
        assertTrue(pin.find(), "no major.minor(.patch) bouncycastle.version in pom.xml");
        int major = Integer.parseInt(pin.group(1));
        int minor = Integer.parseInt(pin.group(2));
        assertTrue(major > 1 || (major == 1 && minor >= 86), "pom pins BouncyCastle " + pin.group());
        String pinned = pin.group(1) + "." + pin.group(2) + (pin.group(3) != null ? pin.group(3) : "");
        assertEquals("BouncyCastle Security Provider v" + pinned, BouncyCastle.PROVIDER.getInfo());
        DefaultVerifier.requireBouncyCastle(BouncyCastle.PROVIDER);
        assertNotNull(Verifier.create(Config.defaults()));
    }

    /**
     * Nine is the exact need: at 8 the genuine receipt is MALFORMED and
     * create refuses, with the runtime probe on or off; at 9 both pass.
     * Without the check the lowered bound would show up only as MALFORMED
     * on every genuine receipt.
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
            // runtimeProbe(false) turns off the engine probe only.
            assertThrows(
                    IllegalStateException.class,
                    () -> Verifier.create(Config.builder().runtimeProbe(false).build()));

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
