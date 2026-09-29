//! Spike: hand-written JNI over the core. The Java class owns the API; Rust
//! only converts. `unsafe` is confined to the handle round-trip.
use jni::objects::{JClass, JString};
use jni::sys::{jlong, jstring};
use jni::JNIEnv;

fn throw(env: &mut JNIEnv, reason: &str, detail: &str) {
    let _ = env.throw_new("spike/jni/VerificationException", format!("{reason}: {detail}"));
}

#[no_mangle]
pub extern "system" fn Java_spike_jni_ReceiptVerifier_create(mut env: JNIEnv, _c: JClass, bundle_id: JString) -> jlong {
    let bid: String = match env.get_string(&bundle_id) { Ok(s) => s.into(), Err(_) => return 0 };
    match aprv::ReceiptVerifier::builder().bundle_id(bid).trusted_roots(aprv::apple_receipt_roots().to_vec()).build() {
        Ok(v) => Box::into_raw(Box::new(v)) as jlong,
        Err(e) => { throw(&mut env, "CONFIG", e.detail()); 0 }
    }
}

#[no_mangle]
pub extern "system" fn Java_spike_jni_ReceiptVerifier_verifyBase64(mut env: JNIEnv, _c: JClass, handle: jlong, b64: JString) -> jstring {
    // SAFETY: handle came from create() and the Java side guards against use after destroy.
    let v = unsafe { &*(handle as *const aprv::ReceiptVerifier) };
    let s: String = match env.get_string(&b64) { Ok(s) => s.into(), Err(_) => return std::ptr::null_mut() };
    match v.verify_base64(&s) {
        Ok(r) => env.new_string(r.bundle_id.unwrap_or_default()).map(|j| j.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(e) => { throw(&mut env, e.reason().as_str(), e.detail()); std::ptr::null_mut() }
    }
}

#[no_mangle]
pub extern "system" fn Java_spike_jni_ReceiptVerifier_destroy(_env: JNIEnv, _c: JClass, handle: jlong) {
    if handle != 0 {
        // SAFETY: called once by close().
        drop(unsafe { Box::from_raw(handle as *mut aprv::ReceiptVerifier) });
    }
}
