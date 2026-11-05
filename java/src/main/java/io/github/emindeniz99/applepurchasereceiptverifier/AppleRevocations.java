package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.jspecify.annotations.Nullable;

/**
 * The built-in revocation list, {@code certs/revocations.json}, and the two
 * built-in issuers of Apple's lists that are not roots, WWDR G5 and G6
 * ({@code certs/revocation-issuers/}). Compiled in, like
 * {@link AppleRootCerts}, so no resource on the classpath can stand in for
 * them. {@code AppleRevocationsTest} pins each constant byte for byte to its
 * file in {@code certs/} and the certificates to their SHA-256
 * fingerprints. {@code tools/refresh-apple-revocations.mjs} rewrites
 * {@code certs/revocations.json}; copy it here by hand, line for line (the
 * test prints the constant when they differ). Append-only, like the file.
 */
final class AppleRevocations {

    private AppleRevocations() {}

    /** {@code certs/revocations.json}, as UTF-8 bytes. */
    static byte[] json() {
        StringBuilder json = new StringBuilder();
        for (String line : JSON_LINES) {
            json.append(line).append('\n');
        }
        return json.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * The DER of the certificate the built-in list names by its repository
     * path, or null for a path it does not know.
     */
    static byte @Nullable [] certificate(String path) {
        if ("certs/revocation-issuers/AppleWWDRCAG5.cer".equals(path)) {
            return Base64.getDecoder().decode(APPLE_WWDR_CA_G5);
        }
        if ("certs/revocation-issuers/AppleWWDRCAG6.cer".equals(path)) {
            return Base64.getDecoder().decode(APPLE_WWDR_CA_G6);
        }
        return null;
    }

    /**
     * {@code certs/revocations.json}, one string per line, each line ending
     * in a line feed. An array rather than one string constant: a constant
     * is capped at 65,535 bytes, and the file only grows.
     */
    private static final String[] JSON_LINES = {
        "{",
        "  \"comment\": \"Certificates Apple has revoked on the lists of the issuers below, compiled into the core and into Java and always checked (docs/design/revocation.md). Written by tools/refresh-apple-revocations.mjs, never by hand. Append-only: an entry stays when Apple drops it from a later list, and then gains a delisted member naming the first list without it. certificateHold and removeFromCRL entries are not added. Serials and CRL Numbers are uppercase hex, an even number of digits, no leading 00 pair.\",",
        "  \"issuers\": [",
        "    {",
        "      \"id\": \"0274fe858b04726bb2c6fd7ba73fe4c63a1d076f6eff78373bdb81498151c86e\",",
        "      \"name\": \"Apple Root CA\",",
        "      \"certificate\": null,",
        "      \"list\": \"http://crl.apple.com/root.crl\",",
        "      \"newest\": {",
        "        \"crlNumber\": null,",
        "        \"thisUpdate\": \"2026-08-25T00:06:52Z\"",
        "      }",
        "    },",
        "    {",
        "      \"id\": \"e691a373c3e637bf2d2e0abc6056ea4e5413c90414b47b0b0133ad3cb757be57\",",
        "      \"name\": \"Apple Root CA - G3\",",
        "      \"certificate\": null,",
        "      \"list\": \"http://crl.apple.com/applerootcag3.crl\",",
        "      \"newest\": {",
        "        \"crlNumber\": \"38\",",
        "        \"thisUpdate\": \"2026-08-25T00:08:08Z\"",
        "      }",
        "    },",
        "    {",
        "      \"id\": \"c4c7a18465d55f4f7d20ff2a525bceafb55d860fc3b59a1981b04783fd74f96b\",",
        "      \"name\": \"Apple Worldwide Developer Relations Certification Authority G5\",",
        "      \"certificate\": \"certs/revocation-issuers/AppleWWDRCAG5.cer\",",
        "      \"list\": \"http://crl.apple.com/wwdrg5.crl\",",
        "      \"newest\": {",
        "        \"crlNumber\": \"076B\",",
        "        \"thisUpdate\": \"2026-11-04T21:46:46Z\"",
        "      }",
        "    },",
        "    {",
        "      \"id\": \"ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee\",",
        "      \"name\": \"Apple Worldwide Developer Relations Certification Authority G6\",",
        "      \"certificate\": \"certs/revocation-issuers/AppleWWDRCAG6.cer\",",
        "      \"list\": \"http://crl.apple.com/wwdrg6.crl\",",
        "      \"newest\": {",
        "        \"crlNumber\": \"0857\",",
        "        \"thisUpdate\": \"2026-11-05T13:36:46Z\"",
        "      }",
        "    }",
        "  ],",
        "  \"revoked\": [",
        "    {",
        "      \"issuer\": \"0274fe858b04726bb2c6fd7ba73fe4c63a1d076f6eff78373bdb81498151c86e\",",
        "      \"serial\": \"3EDF4E5729AECD39\",",
        "      \"reason\": \"cessationOfOperation\",",
        "      \"revocationDate\": \"2024-12-12T21:48:43Z\",",
        "      \"crlNumber\": null",
        "    },",
        "    {",
        "      \"issuer\": \"ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee\",",
        "      \"serial\": \"37D34791D02A56160329892A81C5A0EA\",",
        "      \"reason\": \"keyCompromise\",",
        "      \"revocationDate\": \"2026-03-06T23:59:00Z\",",
        "      \"crlNumber\": \"0857\"",
        "    },",
        "    {",
        "      \"issuer\": \"ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee\",",
        "      \"serial\": \"60B6E8776CFE8C8E0710E521ADCC2C6F\",",
        "      \"reason\": \"keyCompromise\",",
        "      \"revocationDate\": \"2026-07-01T09:16:00Z\",",
        "      \"crlNumber\": \"0857\"",
        "    },",
        "    {",
        "      \"issuer\": \"ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee\",",
        "      \"serial\": \"4B6F88DE48E5822739E368CBD31CE9E5\",",
        "      \"reason\": \"keyCompromise\",",
        "      \"revocationDate\": \"2026-04-15T17:41:01Z\",",
        "      \"crlNumber\": \"0857\"",
        "    },",
        "    {",
        "      \"issuer\": \"ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee\",",
        "      \"serial\": \"375229468211E66808CDD808A28FC2A3\",",
        "      \"reason\": \"keyCompromise\",",
        "      \"revocationDate\": \"2026-03-10T20:41:01Z\",",
        "      \"crlNumber\": \"0857\"",
        "    },",
        "    {",
        "      \"issuer\": \"ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee\",",
        "      \"serial\": \"6FAFF74C8A3FAE56DF44F8355EFF65DC\",",
        "      \"reason\": \"keyCompromise\",",
        "      \"revocationDate\": \"2026-08-13T21:05:00Z\",",
        "      \"crlNumber\": \"0857\"",
        "    },",
        "    {",
        "      \"issuer\": \"ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee\",",
        "      \"serial\": \"1E06A88C9A5E1FDC2072E5BE9AF3FCF7\",",
        "      \"reason\": \"keyCompromise\",",
        "      \"revocationDate\": \"2026-08-13T21:05:00Z\",",
        "      \"crlNumber\": \"0857\"",
        "    },",
        "    {",
        "      \"issuer\": \"ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee\",",
        "      \"serial\": \"766930566FF29A587D8BE196BC4F00C5\",",
        "      \"reason\": \"keyCompromise\",",
        "      \"revocationDate\": \"2026-05-04T15:03:00Z\",",
        "      \"crlNumber\": \"0857\"",
        "    },",
        "    {",
        "      \"issuer\": \"ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee\",",
        "      \"serial\": \"1AB313C1E745231DE19F33ED595D0A72\",",
        "      \"reason\": \"keyCompromise\",",
        "      \"revocationDate\": \"2026-03-28T18:37:00Z\",",
        "      \"crlNumber\": \"0857\"",
        "    },",
        "    {",
        "      \"issuer\": \"ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee\",",
        "      \"serial\": \"1737BF8D15406B20CBEA8828A33BD79F\",",
        "      \"reason\": \"keyCompromise\",",
        "      \"revocationDate\": \"2026-09-15T01:30:00Z\",",
        "      \"crlNumber\": \"0857\"",
        "    },",
        "    {",
        "      \"issuer\": \"ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee\",",
        "      \"serial\": \"54884CB34A766BF5418AD35CF603032E\",",
        "      \"reason\": \"keyCompromise\",",
        "      \"revocationDate\": \"2026-02-09T12:39:00Z\",",
        "      \"crlNumber\": \"0857\"",
        "    },",
        "    {",
        "      \"issuer\": \"ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee\",",
        "      \"serial\": \"42092A8296424852A12D24CCDBC8CA0B\",",
        "      \"reason\": \"keyCompromise\",",
        "      \"revocationDate\": \"2026-02-09T13:54:00Z\",",
        "      \"crlNumber\": \"0857\"",
        "    },",
        "    {",
        "      \"issuer\": \"ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee\",",
        "      \"serial\": \"48E58537C0319BD157F1049E61936002\",",
        "      \"reason\": \"keyCompromise\",",
        "      \"revocationDate\": \"2026-04-16T23:12:00Z\",",
        "      \"crlNumber\": \"0857\"",
        "    },",
        "    {",
        "      \"issuer\": \"ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee\",",
        "      \"serial\": \"5D63F49A8AF94ED7CF7FC93AFB26CC91\",",
        "      \"reason\": \"keyCompromise\",",
        "      \"revocationDate\": \"2026-06-24T15:52:00Z\",",
        "      \"crlNumber\": \"0857\"",
        "    },",
        "    {",
        "      \"issuer\": \"ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee\",",
        "      \"serial\": \"4889DD7445B574454F49F9259571A30F\",",
        "      \"reason\": \"keyCompromise\",",
        "      \"revocationDate\": \"2026-08-01T03:32:00Z\",",
        "      \"crlNumber\": \"0857\"",
        "    },",
        "    {",
        "      \"issuer\": \"ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee\",",
        "      \"serial\": \"5610AC1F192184591CF3E60348248E91\",",
        "      \"reason\": \"keyCompromise\",",
        "      \"revocationDate\": \"2026-08-14T11:03:51Z\",",
        "      \"crlNumber\": \"0857\"",
        "    },",
        "    {",
        "      \"issuer\": \"ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee\",",
        "      \"serial\": \"6F39270AEA7D013322DCD61AC31AA4D0\",",
        "      \"reason\": \"keyCompromise\",",
        "      \"revocationDate\": \"2026-10-22T10:55:00Z\",",
        "      \"crlNumber\": \"0857\"",
        "    },",
        "    {",
        "      \"issuer\": \"ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee\",",
        "      \"serial\": \"535555D671233C535C0D93C542134143\",",
        "      \"reason\": \"keyCompromise\",",
        "      \"revocationDate\": \"2026-10-22T10:49:00Z\",",
        "      \"crlNumber\": \"0857\"",
        "    },",
        "    {",
        "      \"issuer\": \"ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee\",",
        "      \"serial\": \"21F4EE77681AA4D6C0547468875A0AA9\",",
        "      \"reason\": \"keyCompromise\",",
        "      \"revocationDate\": \"2026-10-21T10:50:00Z\",",
        "      \"crlNumber\": \"0857\"",
        "    }",
        "  ]",
        "}",
    };

    // certs/revocation-issuers/AppleWWDRCAG5.cer.
    private static final String APPLE_WWDR_CA_G5 =
            "MIIEVTCCAz2gAwIBAgIUO36ACu7TAqHm7NuX2cqsKJzxaZQwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UE"
                    + "BhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxlIENlcnRpZmljYXRpb24gQXV0"
                    + "aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBSb290IENBMB4XDTIwMTIxNjE5Mzg1NloXDTMwMTIxMDAwMDAw"
                    + "MFowdTFEMEIGA1UEAww7QXBwbGUgV29ybGR3aWRlIERldmVsb3BlciBSZWxhdGlvbnMgQ2VydGlmaWNh"
                    + "dGlvbiBBdXRob3JpdHkxCzAJBgNVBAsMAkc1MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJV"
                    + "UzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ9d2h/7+rzQSyI8x9Ym+hf39J8ePmQRZprv"
                    + "Xr6rNL2qLCFu1h6UIYUsdMEOEGGqPGNKfkrjyHXWz8KcCEh7arkpsclm/ciKFtGyBDyCuoBs4v8Kcuus"
                    + "/jtvSL6eixFNlX2ye5AvAhxO/Em+12+1T754xtress3J2WYRO1rpCUVziVDUTuJoBX7adZxLAa7a489t"
                    + "dE3eU9DVGjiCOtCd410pe7GB6iknC/tgfIYS+/BiTwbnTNEf2W2e7XPaeCENnXDZRleQX2eEwXN3Cqhi"
                    + "YraucIa7dSOJrXn25qTU/YMmMgo7JJJbIKGc0S+AGJvdPAvntf3sgFcPF54/K4cnu/cCAwEAAaOB7zCB"
                    + "7DASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaAFCvQaUeUdgn+9GuNLkCm90dNfwheMEQGCCsG"
                    + "AQUFBwEBBDgwNjA0BggrBgEFBQcwAYYoaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwMy1hcHBsZXJv"
                    + "b3RjYTAuBgNVHR8EJzAlMCOgIaAfhh1odHRwOi8vY3JsLmFwcGxlLmNvbS9yb290LmNybDAdBgNVHQ4E"
                    + "FgQUGYuXjUpbYXhX9KVcNRKKOQjjsHUwDgYDVR0PAQH/BAQDAgEGMBAGCiqGSIb3Y2QGAgEEAgUAMA0G"
                    + "CSqGSIb3DQEBCwUAA4IBAQBaxDWi2eYKnlKiAIIid81yL5D5Iq8UJcyqCkJgksK9dR3rTMoV5X5rQBBe"
                    + "+1tFdA3wen2Ikc7eY4tCidIY30GzWJ4GCIdI3UCvI9Xt6yxg5eukfxzpnIPWlF9MYjmKTq4TjX1DuNxe"
                    + "rL4YQPLmDyxdE5Pxe2WowmhI3v+0lpsM+zI2np4NlV84CouW0hJst4sLjtc+7G8Bqs5NRWDbhHFmYuUZ"
                    + "ZTDNiv9FU/tu+4h3Q8NIY/n3UbNyXnniVs+8u4S5OFp4rhFIUrsNNYuU3sx0mmj1SWCUrPKosxWGkNDM"
                    + "MEOG0+VwAlG0gcCol9Tq6rCMCUDvOJOyzSID62dDZchF";

    // certs/revocation-issuers/AppleWWDRCAG6.cer.
    private static final String APPLE_WWDR_CA_G6 =
            "MIIDFjCCApygAwIBAgIUIsGhRwp0c2nvU4YSycafPTjzbNcwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwS"
                    + "QXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTET"
                    + "MBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMjEwMzE3MjAzNzEwWhcNMzYwMzE5MDAw"
                    + "MDAwWjB1MUQwQgYDVQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZp"
                    + "Y2F0aW9uIEF1dGhvcml0eTELMAkGA1UECwwCRzYxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYT"
                    + "AlVTMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEbsQKC94PrlWmZXnXgtxzdVJL8T0SGYngDRGpngn3N6PT"
                    + "8JMEb7FDi4bBmPhCnZ3/sq6PF/cGcKXWsL5vOteRhyJ45x3ASP7cOB+aao90fcpxSv/EZFbniAbNgZGh"
                    + "IhpIo4H6MIH3MBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUu7DeoVgziJqkipnevr3rr9rL"
                    + "JKswRgYIKwYBBQUHAQEEOjA4MDYGCCsGAQUFBzABhipodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAz"
                    + "LWFwcGxlcm9vdGNhZzMwNwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL2NybC5hcHBsZS5jb20vYXBwbGVy"
                    + "b290Y2FnMy5jcmwwHQYDVR0OBBYEFD8vlCNR01DJmig97bB85c+lkGKZMA4GA1UdDwEB/wQEAwIBBjAQ"
                    + "BgoqhkiG92NkBgIBBAIFADAKBggqhkjOPQQDAwNoADBlAjBAXhSq5IyKogMCPtw490BaB677CaEGJXuf"
                    + "QB/EqZGd6CSjiCtOnuMTbXVXmxxcxfkCMQDTSPxarZXvNrkxU3TkUMI33yzvFVVRT4wxWJC994OsdcZ4"
                    + "+RGNsYDyR5gmdr0nDGg=";
}
