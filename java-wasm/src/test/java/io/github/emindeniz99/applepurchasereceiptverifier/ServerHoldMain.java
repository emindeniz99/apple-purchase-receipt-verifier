package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.file.Paths;

/**
 * Not a test: a JVM that owns a server-engine verifier, for
 * {@link ServerLifecycleTest}. Prints {@code CHILD <pid>} for the managed
 * child, then: {@code exit} calls {@code System.exit} without closing
 * anything; {@code sleep} waits to be killed; {@code gc} drops the verifier,
 * collects, and waits.
 */
public final class ServerHoldMain {

    private ServerHoldMain() {}

    public static void main(String[] args) throws Exception {
        ServerVerifier verifier = (ServerVerifier)
                Verifier.create(Config.defaults(), Engine.server(ServerSource.executable(Paths.get(args[0]))));
        System.out.println("CHILD " + verifier.connection().process().pid());
        System.out.flush();
        if (args[1].equals("exit")) {
            System.exit(0);
        }
        if (args[1].equals("gc")) {
            verifier = null;
            for (int i = 0; i < 20; i++) {
                System.gc();
                Thread.sleep(100);
            }
            System.out.println("COLLECTED");
            System.out.flush();
        }
        Thread.sleep(600_000);
    }
}
