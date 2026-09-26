package spikeboot;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.nio.file.*;
@SpringBootApplication @RestController
public class App implements CommandLineRunner {
  static String b64() throws Exception { return Files.readString(Path.of("$REPO/fixtures/public-receipts/receipt-sandbox-g5.b64")).replaceAll("\\s", ""); }
  static String verify() throws Exception { String b64 = b64(); try (bakeoff.jni.ReceiptVerifier v = new bakeoff.jni.ReceiptVerifier("dev.bonzer.weeka.app")) { return v.verifyBase64(b64).bundleId(); } }
  public static void main(String[] a) { SpringApplication.run(App.class, a); }
  @Override public void run(String... a) throws Exception { System.out.println("RUNNER bundleId=" + verify() + " loader=" + App.class.getClassLoader().getClass().getName()); }
  @GetMapping("/verify") String get() throws Exception { return "HTTP bundleId=" + verify(); }
}
