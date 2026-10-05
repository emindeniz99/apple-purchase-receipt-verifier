package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Probe8: does create/verify draw from any SecureRandom, or consult Security.getProviders() for algorithms? */
public class Probe8Rng {
    static final AtomicInteger calls = new AtomicInteger();
    static final AtomicInteger lookups = new AtomicInteger();
    public static class CountingSpi extends SecureRandomSpi {
                @Override protected void engineSetSeed(byte[] seed) { }
        @Override protected void engineNextBytes(byte[] bytes) { if (calls.incrementAndGet() <= 3) { for (StackTraceElement e : new Throwable().getStackTrace()) { String c = e.toString(); if (c.contains("bouncycastle") || c.contains("applepurchase")) System.out.println("RNG-STACK " + c); } System.out.println("RNG-STACK ----"); } new Random().nextBytes(bytes); }
        @Override protected byte[] engineGenerateSeed(int n) { calls.incrementAndGet(); return new byte[n]; }
    }
    public static class Counting extends Provider {
        public Counting() { super("CountingRNG", "1", "counts SecureRandom use"); put("SecureRandom.Counting", CountingSpi.class.getName()); }
        @Override public synchronized Service getService(String type, String algorithm) { lookups.incrementAndGet(); StackTraceElement[] st = new Throwable().getStackTrace(); if (type.equals("SecureRandom") || System.getProperty("probe.trace") != null) System.out.println("LOOKUP " + type + "." + algorithm + " from " + st[1] + " / " + st[2]); return super.getService(type, algorithm); }
    }
    public static void main(String[] a) throws Exception {
        String src = new String(Files.readAllBytes(Paths.get(System.getenv("REPO") + "/fixtures/public-receipts/receipt-sandbox-g5.b64")), StandardCharsets.US_ASCII).trim();
        TestPki pki = TestPki.jws();
        String jws = pki.signJws(TestPki.claims("signedDate", System.currentTimeMillis(), "environment", "Sandbox"));
        Security.insertProviderAt(new Counting(), 1);
        int before = lookups.get();
        Verifier v = Verifier.create(Config.defaults());
        Verifier v2 = Verifier.create(Config.builder().roots(Collections.singleton(pki.root)).build());
        System.out.println("receipt " + v.verifyReceipt(src).verified() + " jws " + v2.verifySignedData(jws).verified());
        int c0 = calls.get(); v.verifyReceipt(src); int c1 = calls.get(); v2.verifySignedData(jws); int c2 = calls.get();
        System.out.println("per verifyReceipt (RSA chain) draws=" + (c1 - c0) + " per EC JWS draws=" + (c2 - c1));
        System.out.println("SecureRandom bytes requested from first provider: " + calls.get() + "; provider service lookups at position 1 during (create+verify): " + (lookups.get() - before));
    }
}
