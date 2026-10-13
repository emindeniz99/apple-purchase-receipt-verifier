import java.security.MessageDigest;
import java.security.Provider;
import java.util.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** Times every MessageDigest BouncyCastle registers over 8 MiB, best of 3 warm runs, ratio to SHA-256. */
public class DigestSurvey {
  public static void main(String[] a) throws Exception {
    Provider bc = new BouncyCastleProvider();
    byte[] data = new byte[8 << 20];
    new Random(1).nextBytes(data);
    // canonical names (dedupe aliases by the implementing class)
    Map<String, String> byClass = new TreeMap<>();
    for (Provider.Service s : bc.getServices()) {
      if (!s.getType().equals("MessageDigest")) continue;
      byClass.putIfAbsent(s.getClassName(), s.getAlgorithm());
    }
    long sha256 = 0;
    List<String[]> rows = new ArrayList<>();
    for (String name : byClass.values()) {
      MessageDigest md;
      try { md = MessageDigest.getInstance(name, bc); } catch (Exception e) { continue; }
      long best = Long.MAX_VALUE;
      try {
        for (int i = 0; i < 4; i++) {
          long t = System.nanoTime();
          md.reset(); md.update(data); md.digest();
          long ms = (System.nanoTime() - t) / 1_000_000;
          if (i > 0) best = Math.min(best, ms);
        }
      } catch (Throwable e) { rows.add(new String[]{name, "error " + e}); continue; }
      if (name.equals("SHA-256")) sha256 = best;
      rows.add(new String[]{name, Long.toString(best)});
    }
    rows.sort((x, y) -> Long.compare(parse(y[1]), parse(x[1])));
    for (String[] r : rows) {
      long ms = parse(r[1]);
      System.out.printf("%-22s %6s ms  %5.1fx%n", r[0], r[1], sha256 == 0 ? 0 : (double) ms / sha256);
    }
  }
  static long parse(String s) { try { return Long.parseLong(s); } catch (Exception e) { return -1; } }
}
