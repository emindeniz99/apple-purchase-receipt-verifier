package spikeweb;
final class Impl { static String verify(String b64) throws Exception {
    try (uniffi.aprv_uniffi.ReceiptVerifier v = new uniffi.aprv_uniffi.ReceiptVerifier("dev.bonzer.weeka.app", null)) {
        return v.verifyBase64(b64).getBundleId();
    } } }
