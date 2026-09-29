package spikeweb;
final class Impl { static String verify(String b64) throws Exception {
    try (bakeoff.jni.ReceiptVerifier v = new bakeoff.jni.ReceiptVerifier("dev.bonzer.weeka.app")) {
        return v.verifyBase64(b64).bundleId();
    } } }
