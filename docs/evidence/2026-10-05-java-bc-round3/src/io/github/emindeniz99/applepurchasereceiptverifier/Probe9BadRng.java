package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** Probe9: a first-listed SecureRandom provider that fails; what do genuine inputs answer? */
public class Probe9BadRng {
    public static class BadSpi extends SecureRandomSpi {
        @Override protected void engineSetSeed(byte[] seed) { }
        @Override protected void engineNextBytes(byte[] bytes) { throw new ProviderException("entropy source unavailable"); }
        @Override protected byte[] engineGenerateSeed(int n) { throw new ProviderException("entropy source unavailable"); }
    }
    public static class Bad extends Provider {
        public Bad() { super("BadRNG", "1", "broken SecureRandom"); put("SecureRandom.Bad", BadSpi.class.getName()); }
    }
    public static void main(String[] a) throws Exception {
        String src = new String(Files.readAllBytes(Paths.get(System.getenv("REPO") + "/fixtures/public-receipts/receipt-sandbox-g5.b64")), StandardCharsets.US_ASCII).trim();
        boolean install = a.length > 0 && a[0].equals("bad");
        if (install) Security.insertProviderAt(new Bad(), 1);
        System.out.println("default SecureRandom: " + new SecureRandom().getAlgorithm() + " provider=" + new SecureRandom().getProvider().getName());
        try { Verifier.create(Config.defaults()); System.out.println("create with probe: ok"); } catch (Throwable t) { System.out.println("create with probe: " + t.getClass().getSimpleName() + ": " + String.valueOf(t.getMessage()).substring(0, Math.min(90, String.valueOf(t.getMessage()).length()))); }
        Verifier v = Verifier.create(Config.builder().runtimeProbe(false).build());
        VerificationResult<ReceiptPayload> r = v.verifyReceipt(src);
        System.out.println("genuine receipt, probe off: " + (r.verified() ? "ok" : r.failure().reason() + " / " + r.failure().message()));
        System.out.println("endpoint: " + v.verifyReceiptEndpoint(Environment.SANDBOX, "{\"receipt-data\":\"" + src + "\"}").replaceAll("^(.{20}).*$", "$1"));
    }
}
