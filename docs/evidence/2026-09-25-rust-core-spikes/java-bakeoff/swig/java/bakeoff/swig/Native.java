package bakeoff.swig;

import java.util.List;
import java.util.Map;

/** Plumbing shared by every verifier class: converting a {@code List<byte[]>}
 *  of root certificates into what the SWIG layer expects, and turning a
 *  nonzero {@code AprvReason} status plus its error JSON into the right
 *  exception type. No verification decision is made here. */
final class Native {
    private Native() {}

    static byte[][] toArray(List<byte[]> roots) {
        return roots == null ? null : roots.toArray(new byte[roots.size()][]);
    }

    /** {@code status} is an {@code AprvReason} value that was not 0. Throws
     *  {@link VerificationException} for the 1..12 verdict band, or
     *  {@link ConfigurationException} for the 100+ call-level band. */
    static void throwVerification(int status, Map<String, Object> errorJson) throws VerificationException {
        String detail = Json.getString(errorJson, "message");
        if (status >= 1 && status <= 12) {
            throw new VerificationException(Reason.fromAbiCode(status), detail);
        }
        String token = Json.getString(errorJson, "reason");
        throw new ConfigurationException("AprvReason " + status + " (" + token + "): " + detail);
    }
}
