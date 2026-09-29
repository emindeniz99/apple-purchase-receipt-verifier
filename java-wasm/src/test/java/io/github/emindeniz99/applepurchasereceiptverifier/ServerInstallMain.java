package io.github.emindeniz99.applepurchasereceiptverifier;

import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Not a test: a second JVM for {@link ServerDownloadTest}, whose four
 * threads install the same binary into the same cache directory as the test
 * JVM's four. Prints {@code READY}, then {@code INSTALLED <path>} per thread.
 */
public final class ServerInstallMain {

    private ServerInstallMain() {}

    public static void main(String[] args) throws Exception {
        Path directory = Paths.get(args[0]);
        URI uri = URI.create(args[1]);
        String sha256 = args[2];
        ExecutorService pool = Executors.newFixedThreadPool(4);
        List<Future<Path>> installs = new ArrayList<>();
        System.out.println("READY");
        System.out.flush();
        for (int i = 0; i < 4; i++) {
            installs.add(
                    pool.submit(() -> ServerBinary.install(directory, sha256, () -> ServerBinary.download(uri, true))));
        }
        for (Future<Path> install : installs) {
            System.out.println("INSTALLED " + install.get());
        }
        System.out.flush();
        pool.shutdown();
    }
}
