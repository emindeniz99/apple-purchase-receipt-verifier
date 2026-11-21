package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * One {@link Config.Builder#distrust distrust} entry: a certificate to
 * refuse, named by the certificate that issued it and its serial number.
 * Immutable.
 *
 * <p>{@code issuer} is the issuer id: 64 hex digits, the SHA-256 of the
 * issuing certificate's {@code subject} Name followed by its
 * {@code subjectPublicKeyInfo}, both exactly as encoded in that
 * certificate. Name and key together, so two CAs that share a key under
 * different names are different issuers. {@code serial} is the revoked
 * certificate's serial number in hex. Either letter case and an odd number
 * of digits are accepted ({@code "2"}, {@code "02"} and {@code "0002"} name
 * one serial).</p>
 *
 * <p>The strings are kept exactly as given. {@link Verifier#create} checks
 * and normalises them, and refuses the configuration, naming the entry's
 * index, when the issuer is not 64 hex digits or the serial is not one or
 * more hex digits.</p>
 */
public final class RevokedCertificate {

    private final String issuer;
    private final String serial;

    /**
     * @param issuer the issuer id, 64 hex digits
     * @param serial the serial number in hex
     * @throws NullPointerException if either is null
     */
    public RevokedCertificate(String issuer, String serial) {
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.serial = Objects.requireNonNull(serial, "serial");
    }

    /** The issuer id, as given. */
    public String issuer() {
        return issuer;
    }

    /** The serial number in hex, as given. */
    public String serial() {
        return serial;
    }

    /** Equal when both strings are, as given. */
    @Override
    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof RevokedCertificate)) {
            return false;
        }
        RevokedCertificate that = (RevokedCertificate) other;
        return issuer.equals(that.issuer) && serial.equals(that.serial);
    }

    @Override
    public int hashCode() {
        return Objects.hash(issuer, serial);
    }

    @Override
    public String toString() {
        return issuer + ":" + serial;
    }
}
