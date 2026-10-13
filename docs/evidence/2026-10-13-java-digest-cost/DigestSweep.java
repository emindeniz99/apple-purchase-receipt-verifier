import java.io.OutputStream;
import java.security.Provider;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * DigestDenylistCostTest's measurement, standalone, with a fixed round count:
 * every OID-shaped string in the BouncyCastle provider's entries, offered with
 * no parameters and then with INTEGER 512 to the calculator provider the CMS
 * verifier builds; each one that resolves is timed over the same random bytes,
 * interleaved, best of the measured rounds. Prints the JDK, the count, the wall
 * time and the eleven highest ratios to SHA-256.
 *
 * <p>Args: bufferKiB warmRounds measuredRounds.
 */
public class DigestSweep {
  public static void main(String[] a) throws Exception {
    int bytes = Integer.parseInt(a[0]) << 10;
    int warm = Integer.parseInt(a[1]);
    int measured = Integer.parseInt(a[2]);
    Provider bc = new BouncyCastleProvider();
    DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder().setProvider(bc).build();
    Pattern p = Pattern.compile("[0-2](\\.[0-9]+)+");
    TreeSet<String> cands = new TreeSet<>();
    for (Map.Entry<Object, Object> e : bc.entrySet()) {
      for (Object o : new Object[] {e.getKey(), e.getValue()}) {
        Matcher m = p.matcher(String.valueOf(o));
        while (m.find()) cands.add(m.group());
      }
    }
    List<AlgorithmIdentifier> ids = new ArrayList<>();
    for (String c : cands) {
      ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.tryFromID(c); if (oid == null) continue;
      for (AlgorithmIdentifier id : new AlgorithmIdentifier[] {new AlgorithmIdentifier(oid), new AlgorithmIdentifier(oid, new ASN1Integer(512))}) {
        try { dcp.get(id); ids.add(id); break; } catch (Exception e) {}
      }
    }
    byte[] data = new byte[bytes];
    new Random(1).nextBytes(data);
    long t0 = System.nanoTime();
    Map<String, Long> best = new TreeMap<>();
    for (int round = 0; round < warm + measured; round++) {
      for (AlgorithmIdentifier id : ids) {
        DigestCalculator c = dcp.get(id);
        long t = System.nanoTime();
        OutputStream os = c.getOutputStream(); os.write(data); os.close(); c.getDigest();
        long ns = System.nanoTime() - t;
        if (round >= warm) best.merge(id.getAlgorithm().getId(), ns, Math::min);
      }
    }
    long total = (System.nanoTime() - t0) / 1_000_000;
    double sha = best.get("2.16.840.1.101.3.4.2.1");
    List<Map.Entry<String, Long>> rows = new ArrayList<>(best.entrySet());
    rows.sort((x, y) -> Long.compare(y.getValue(), x.getValue()));
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < 11; i++) {
      Map.Entry<String, Long> r = rows.get(i);
      sb.append(String.format("%s=%.2f ", short_(r.getKey()), r.getValue() / sha));
    }
    System.out.println(System.getProperty("java.specification.version") + " n=" + ids.size() + " " + total + "ms " + sb);
  }
  static String short_(String oid) {
    switch (oid) {
      case "1.2.643.2.2.9": return "GOST94";
      case "1.2.840.113549.2.2": return "MD2";
      case "1.0.10118.3.0.55": return "WHIRL";
      case "1.2.643.7.1.1.2.2": return "STB256";
      case "1.2.643.7.1.1.2.3": return "STB512";
      case "1.2.804.2.1.1.1.1.2.2.1": return "DSTU256";
      case "1.2.804.2.1.1.1.1.2.2.2": return "DSTU384";
      case "1.2.804.2.1.1.1.1.2.2.3": return "DSTU512";
      case "1.3.36.3.2.1": return "RMD160";
      default: return oid;
    }
  }
}
