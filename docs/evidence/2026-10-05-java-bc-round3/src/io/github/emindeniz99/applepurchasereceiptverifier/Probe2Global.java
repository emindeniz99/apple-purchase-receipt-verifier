package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** Probe2: does create/verify touch Security providers, Security properties, System properties, default Locale/TimeZone? */
public class Probe2Global {
    static Map<String,String> sysProps() { Map<String,String> m = new TreeMap<>(); for (String k : System.getProperties().stringPropertyNames()) m.put(k, System.getProperty(k)); return m; }
    static List<String> providers() { List<String> l = new ArrayList<>(); for (Provider p : Security.getProviders()) l.add(p.getName() + "@" + System.identityHashCode(p)); return l; }
    static Map<String,String> secProps() { Map<String,String> m = new TreeMap<>(); for (String k : new String[]{"jdk.certpath.disabledAlgorithms","jdk.tls.disabledAlgorithms","securerandom.source","securerandom.strongAlgorithms","keystore.type","org.bouncycastle.asn1.max_cons_depth","org.bouncycastle.x509.enableCRLDP","ocsp.enable","com.sun.security.enableCRLDP"}) m.put(k, String.valueOf(Security.getProperty(k))); return m; }
    public static void main(String[] a) throws Exception {
        Locale loc = Locale.getDefault(); TimeZone tz = TimeZone.getDefault();
        Map<String,String> s0 = sysProps(); List<String> p0 = providers(); Map<String,String> sp0 = secProps();
        Verifier v = Verifier.create(Config.defaults());
        String src = new String(Files.readAllBytes(Paths.get(System.getenv("REPO") + "/fixtures/public-receipts/receipt-sandbox-g5.b64")), StandardCharsets.US_ASCII).trim();
        System.out.println("verify: " + v.verifyReceipt(src).verified());
        TestPki pki = TestPki.jws();
        Verifier v2 = Verifier.create(Config.builder().roots(Collections.singleton(pki.root)).build());
        System.out.println("jws: " + v2.verifySignedData(pki.signJws(TestPki.claims("signedDate", System.currentTimeMillis(), "environment", "Sandbox"))).verified());
        System.out.println("endpoint: " + v.verifyReceiptEndpoint(Environment.SANDBOX, "{\"receipt-data\":\"" + src + "\"}").substring(0, 40));
        Map<String,String> s1 = sysProps(); List<String> p1 = providers(); Map<String,String> sp1 = secProps();
        System.out.println("providers unchanged: " + p0.equals(p1) + " " + p1);
        System.out.println("sysprops unchanged: " + s0.equals(s1));
        if (!s0.equals(s1)) { for (String k : s1.keySet()) if (!Objects.equals(s0.get(k), s1.get(k))) System.out.println("  sysprop delta " + k + "=" + s1.get(k)); }
        System.out.println("secprops unchanged: " + sp0.equals(sp1));
        System.out.println("locale/tz unchanged: " + loc.equals(Locale.getDefault()) + " " + tz.equals(TimeZone.getDefault()));
        System.out.println("SecureRandom/Random used? provider list size " + Security.getProviders().length);
    }
}
