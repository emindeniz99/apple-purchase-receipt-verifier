import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectMethod;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;

/** Runs test classes (or Class#method) in the order given, one class at a time, and prints each test's outcome. */
public class OrderedRun {
    static int failedTotal = 0;
    static int traces = 0;

    static long up() {
        return java.lang.management.ManagementFactory.getRuntimeMXBean().getUptime();
    }

    public static void main(String[] args) throws Exception {
        String pkg = "io.github.emindeniz99.applepurchasereceiptverifier.";
        Launcher launcher = LauncherFactory.create();
        String prev = "start";
        for (String arg : args) {
            if (arg.equals("DIAG")) {
                Class.forName(pkg + "Diag").getMethod("run", String.class).invoke(null, "after " + prev);
                continue;
            }
            prev = arg;
            final String cls = arg.contains(".") ? arg : pkg + arg;
            LauncherDiscoveryRequest request;
            if (cls.contains("#")) {
                request = LauncherDiscoveryRequestBuilder.request().selectors(selectMethod(cls)).build();
            } else {
                request = LauncherDiscoveryRequestBuilder.request().selectors(selectClass(Class.forName(cls))).build();
            }
            final int[] counts = new int[2];
            final long t0 = System.nanoTime();
            launcher.execute(request, new TestExecutionListener() {
                @Override
                public void executionStarted(TestIdentifier id) {
                    if (id.isTest() && Boolean.getBoolean("verbose"))
                        System.out.println("  start t=" + up() + " " + id.getDisplayName());
                }

                @Override
                public void executionFinished(TestIdentifier id, TestExecutionResult result) {
                    if (!id.isTest() && result.getStatus() == TestExecutionResult.Status.SUCCESSFUL) return;
                    if (id.isTest()) counts[0]++;
                    if (result.getStatus() != TestExecutionResult.Status.SUCCESSFUL) {
                        counts[1]++;
                        failedTotal++;
                        String name = id.getDisplayName();
                        System.out.println("  FAIL t=" + up() + " " + name);
                        if (traces < Integer.getInteger("traces", 3) && result.getThrowable().isPresent()) {
                            traces++;
                            StringWriter sw = new StringWriter();
                            result.getThrowable().get().printStackTrace(new PrintWriter(sw));
                            System.out.println(sw);
                        }
                    } else if (Boolean.getBoolean("verbose")) {
                        System.out.println("  ok   t=" + up() + " " + id.getDisplayName());
                    }
                }
            });
            System.out.printf("CLASS %s tests=%d failed=%d %.1fs%n",
                    cls.substring(cls.lastIndexOf('.') + 1), counts[0], counts[1], (System.nanoTime() - t0) / 1e9);
        }
        System.out.println("TOTAL_FAILED " + failedTotal);
    }
}
