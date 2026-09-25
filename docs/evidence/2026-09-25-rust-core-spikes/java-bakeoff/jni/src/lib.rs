//! Bake-off: a hand-written jni-rs adapter over the canonical core.
//! Conversion only: every verification decision is made by `aprv`.
//!
//! Shape: static natives on `bakeoff.jni.Native`; verifiers and results are
//! opaque `long` handles (a leaked `Box`); records cross the boundary as one
//! `byte[]` in a tiny length-prefixed encoding that `Native.java` decodes, so
//! no Java object is built from Rust except the exception.
use std::time::{SystemTime, UNIX_EPOCH};

use jni::errors::{Error as JniError, ErrorPolicy};
use jni::objects::{JByteArray, JClass, JObjectArray, JString, JThrowable};
use jni::strings::JNIString;
use jni::sys::{jboolean, jint, jlong};
use jni::{jni_sig, jni_str, native_method, Env, JValue, NativeMethod};

// ---------------------------------------------------------------- errors

/// Everything a native method can fail with.
enum Fail {
    Jni(JniError),
    Verify(aprv::VerificationError),
    Config(String),
}
impl From<JniError> for Fail {
    fn from(e: JniError) -> Self { Self::Jni(e) }
}
impl From<aprv::VerificationError> for Fail {
    fn from(e: aprv::VerificationError) -> Self { Self::Verify(e) }
}
impl From<aprv::ConfigError> for Fail {
    fn from(e: aprv::ConfigError) -> Self { Self::Config(e.detail().to_owned()) }
}

/// Maps `Fail` to the spec's Java exceptions and a panic to
/// `IllegalStateException`. `with_env` already wrapped the body in
/// `catch_unwind`, so nothing unwinds into the JVM.
struct ThrowMapped;

impl<T: Default> ErrorPolicy<T, Fail> for ThrowMapped {
    type Captures<'a: 'b, 'b> = ();

    fn on_error<'a: 'b, 'b>(env: &mut Env<'a>, _: &mut (), err: Fail) -> jni::errors::Result<T> {
        if env.exception_check() {
            return Ok(T::default()); // a Java exception is already pending
        }
        let thrown = match err {
            Fail::Jni(e) => env.throw((jni_str!("java/lang/IllegalStateException"), JNIString::from(format!("JNI: {e}")))),
            Fail::Config(d) => env.throw((jni_str!("bakeoff/jni/ConfigurationException"), JNIString::from(d))),
            Fail::Verify(e) => {
                let token = env.new_string(e.reason().as_str())?;
                let detail = env.new_string(e.detail())?;
                let obj = env.new_object(
                    jni_str!("bakeoff/jni/VerificationException"),
                    jni_sig!((reason: JString, detail: JString) -> void),
                    &[JValue::from(&token), JValue::from(&detail)],
                )?;
                let ex = env.cast_local::<JThrowable>(obj)?;
                env.throw(ex)
            }
        };
        match thrown {
            Ok(()) | Err(JniError::JavaException) => Ok(T::default()),
            Err(e) => Err(e),
        }
    }

    fn on_panic<'a: 'b, 'b>(env: &mut Env<'a>, _: &mut (), p: Box<dyn std::any::Any + Send>) -> jni::errors::Result<T> {
        let msg = p.downcast_ref::<&str>().map(|s| s.to_string())
            .or_else(|| p.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic".into());
        std::mem::forget(p); // dropping a payload may itself panic
        let _ = env.throw((jni_str!("java/lang/IllegalStateException"), JNIString::from(format!("Rust panic: {msg}"))));
        Ok(T::default())
    }
}

type R<T> = Result<T, Fail>;

// ---------------------------------------------------------------- handles

fn into_handle<T>(v: T) -> jlong { Box::into_raw(Box::new(v)) as jlong }

/// Borrows a live handle. Java guarantees it is non-zero, of type `T`, and
/// not freed while the call runs (read lock held across the call).
fn handle<'a, T>(h: jlong) -> &'a T {
    assert!(h != 0, "null handle");
    unsafe { &*(h as *const T) }
}

fn free<T>(h: jlong) {
    if h != 0 {
        drop(unsafe { Box::from_raw(h as *mut T) });
    }
}

// ---------------------------------------------------------------- inputs

fn string(env: &Env, s: &JString) -> R<String> { Ok(s.try_to_string(env)?) }

fn environment(i: jint) -> R<aprv::Environment> {
    Ok(match i {
        0 => aprv::Environment::Production,
        1 => aprv::Environment::Sandbox,
        2 => aprv::Environment::Xcode,
        3 => aprv::Environment::LocalTesting,
        _ => return Err(Fail::Config(format!("unknown environment ordinal {i}"))),
    })
}

/// `null` means Apple's pinned roots.
fn anchors(env: &mut Env, roots: &JObjectArray<JByteArray>, apple: &[aprv::TrustAnchor]) -> R<Vec<aprv::TrustAnchor>> {
    if roots.is_null() {
        return Ok(apple.to_vec());
    }
    let mut out = Vec::new();
    for i in 0..roots.len(env)? {
        let el = roots.get_element(env, i)?;
        let der = env.convert_byte_array(&el)?;
        out.push(aprv::TrustAnchor::from_der(&der)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------- outputs

/// Length-prefixed, big-endian; mirrored by `Native.Reader`.
#[derive(Default)]
struct Enc(Vec<u8>);
impl Enc {
    fn bytes(&mut self, v: Option<&[u8]>) {
        match v {
            None => self.0.push(0),
            Some(b) => {
                self.0.push(1);
                self.0.extend((b.len() as u32).to_be_bytes());
                self.0.extend_from_slice(b);
            }
        }
    }
    fn str(&mut self, v: Option<&str>) { self.bytes(v.map(str::as_bytes)) }
    fn long(&mut self, v: Option<i64>) {
        match v {
            None => self.0.push(0),
            Some(n) => { self.0.push(1); self.0.extend(n.to_be_bytes()); }
        }
    }
}

fn ms(t: Option<SystemTime>) -> Option<i64> {
    t.and_then(|t| t.duration_since(UNIX_EPOCH).ok()).and_then(|d| i64::try_from(d.as_millis()).ok())
}

fn enc_receipt(r: &aprv::AppReceipt) -> Vec<u8> {
    let mut e = Enc::default();
    e.str(r.receipt_type.as_deref());
    e.str(r.bundle_id.as_deref());
    e.str(r.app_version.as_deref());
    e.str(r.original_app_version.as_deref());
    e.bytes(r.opaque_value.as_deref());
    e.bytes(r.sha1_hash.as_deref());
    e.long(ms(r.creation_date));
    e.0.extend((r.in_app_purchases.len() as u32).to_be_bytes());
    for p in &r.in_app_purchases {
        e.str(p.product_id.as_deref());
        e.str(p.transaction_id.as_deref());
        e.str(p.original_transaction_id.as_deref());
        e.long(p.quantity);
        e.long(ms(p.purchase_date));
        e.long(ms(p.expires_date));
    }
    e.0
}

fn enc_payload(p: &aprv::TransactionPayload) -> Vec<u8> {
    let mut e = Enc::default();
    e.str(p.bundle_id.as_deref());
    e.str(p.environment.as_deref());
    e.str(p.product_id.as_deref());
    e.str(p.transaction_id.as_deref());
    e.long(p.signed_date);
    e.long(p.purchase_date);
    e.str(Some(&aprv::serde_json::to_string(&p.claims).unwrap_or_default()));
    e.0
}

// ---------------------------------------------------------------- natives

macro_rules! export {
    ($($sig:tt)*) => {
        const _: NativeMethod = native_method! {
            java_type = "bakeoff.jni.Native",
            error_policy = ThrowMapped,
            static extern $($sig)*
        };
    };
}

export!(fn rv_new(bundle_id: JString, roots: jbyte[][]) -> jlong);
fn rv_new<'l>(env: &mut Env<'l>, _: JClass<'l>, bundle_id: JString<'l>, roots: JObjectArray<'l, JByteArray<'l>>) -> R<jlong> {
    let v = aprv::ReceiptVerifier::builder()
        .bundle_id(string(env, &bundle_id)?)
        .trusted_roots(anchors(env, &roots, aprv::apple_receipt_roots())?)
        .build()?;
    Ok(into_handle(v))
}

export!(fn rv_free(h: jlong));
fn rv_free<'l>(_: &mut Env<'l>, _: JClass<'l>, h: jlong) -> R<()> { free::<aprv::ReceiptVerifier>(h); Ok(()) }

export!(fn rv_verify(h: jlong, der: jbyte[]) -> jbyte[]);
fn rv_verify<'l>(env: &mut Env<'l>, _: JClass<'l>, h: jlong, der: JByteArray<'l>) -> R<JByteArray<'l>> {
    let der = env.convert_byte_array(&der)?;
    let r = handle::<aprv::ReceiptVerifier>(h).verify(&der)?;
    Ok(env.byte_array_from_slice(&enc_receipt(&r))?)
}

export!(fn rv_verify_base64(h: jlong, b64: JString) -> jbyte[]);
fn rv_verify_base64<'l>(env: &mut Env<'l>, _: JClass<'l>, h: jlong, b64: JString<'l>) -> R<JByteArray<'l>> {
    let b64 = string(env, &b64)?;
    let r = handle::<aprv::ReceiptVerifier>(h).verify_base64(&b64)?;
    Ok(env.byte_array_from_slice(&enc_receipt(&r))?)
}

export!(fn jv_new(bundle_id: JString, env_mask: jint, has_app_id: jboolean, app_id: jlong, roots: jbyte[][]) -> jlong);
fn jv_new<'l>(env: &mut Env<'l>, _: JClass<'l>, bundle_id: JString<'l>, env_mask: jint, has_app_id: jboolean,
              app_id: jlong, roots: JObjectArray<'l, JByteArray<'l>>) -> R<jlong> {
    let envs = (0..4).filter(|i| env_mask & (1 << i) != 0).map(environment).collect::<R<Vec<_>>>()?;
    let mut b = aprv::JwsVerifier::builder()
        .bundle_id(string(env, &bundle_id)?)
        .accepted_environments(envs)
        .trusted_roots(anchors(env, &roots, aprv::apple_jws_roots())?);
    if has_app_id {
        b = b.app_apple_id(u64::try_from(app_id).map_err(|_| Fail::Config("appAppleId must be positive".into()))?);
    }
    Ok(into_handle(b.build()?))
}

export!(fn jv_free(h: jlong));
fn jv_free<'l>(_: &mut Env<'l>, _: JClass<'l>, h: jlong) -> R<()> { free::<aprv::JwsVerifier>(h); Ok(()) }

export!(fn jv_verify_transaction(h: jlong, jws: JString) -> jbyte[]);
fn jv_verify_transaction<'l>(env: &mut Env<'l>, _: JClass<'l>, h: jlong, jws: JString<'l>) -> R<JByteArray<'l>> {
    let jws = string(env, &jws)?;
    let p = handle::<aprv::JwsVerifier>(h).verify_transaction(&jws)?;
    Ok(env.byte_array_from_slice(&enc_payload(&p))?)
}

export!(fn ep_new(environment: jint) -> jlong);
fn ep_new<'l>(_: &mut Env<'l>, _: JClass<'l>, e: jint) -> R<jlong> {
    let ep = aprv::VerifyReceiptEndpoint::builder()
        .environment(environment(e)?)
        .trusted_roots(aprv::apple_receipt_roots().to_vec())
        .build()?;
    Ok(into_handle(ep))
}

export!(fn ep_free(h: jlong));
fn ep_free<'l>(_: &mut Env<'l>, _: JClass<'l>, h: jlong) -> R<()> { free::<aprv::VerifyReceiptEndpoint>(h); Ok(()) }

export!(fn ep_verify_json(h: jlong, body: JString) -> JString);
fn ep_verify_json<'l>(env: &mut Env<'l>, _: JClass<'l>, h: jlong, body: JString<'l>) -> R<JString<'l>> {
    let body = string(env, &body)?;
    let out = handle::<aprv::VerifyReceiptEndpoint>(h).verify_receipt_json(&body);
    Ok(env.new_string(out)?)
}

export!(fn ep_verify_result(h: jlong, body: JString) -> jlong);
fn ep_verify_result<'l>(env: &mut Env<'l>, _: JClass<'l>, h: jlong, body: JString<'l>) -> R<jlong> {
    let body = string(env, &body)?;
    Ok(into_handle(handle::<aprv::VerifyReceiptEndpoint>(h).verify_receipt_result_from_json(&body)))
}

export!(fn res_free(h: jlong));
fn res_free<'l>(_: &mut Env<'l>, _: JClass<'l>, h: jlong) -> R<()> { free::<aprv::VerifyReceiptResult>(h); Ok(()) }

export!(fn res_status(h: jlong) -> jlong);
fn res_status<'l>(_: &mut Env<'l>, _: JClass<'l>, h: jlong) -> R<jlong> {
    Ok(handle::<aprv::VerifyReceiptResult>(h).status())
}

export!(fn res_verified(h: jlong) -> jboolean);
fn res_verified<'l>(_: &mut Env<'l>, _: JClass<'l>, h: jlong) -> R<jboolean> {
    Ok(handle::<aprv::VerifyReceiptResult>(h).verified())
}

// `null` when there is no receipt.
export!(fn res_receipt(h: jlong) -> jbyte[]);
fn res_receipt<'l>(env: &mut Env<'l>, _: JClass<'l>, h: jlong) -> R<JByteArray<'l>> {
    match handle::<aprv::VerifyReceiptResult>(h).receipt() {
        Some(r) => Ok(env.byte_array_from_slice(&enc_receipt(r))?),
        None => Ok(JByteArray::default()),
    }
}

// The reason token, or `null` on success.
export!(fn res_failure_reason(h: jlong) -> JString);
fn res_failure_reason<'l>(env: &mut Env<'l>, _: JClass<'l>, h: jlong) -> R<JString<'l>> {
    match handle::<aprv::VerifyReceiptResult>(h).failure_reason() {
        Some(r) => Ok(env.new_string(r.as_str())?),
        None => Ok(JString::default()),
    }
}

export!(fn res_to_json(h: jlong) -> JString);
fn res_to_json<'l>(env: &mut Env<'l>, _: JClass<'l>, h: jlong) -> R<JString<'l>> {
    let s = handle::<aprv::VerifyReceiptResult>(h).to_json();
    Ok(env.new_string(s)?)
}

export!(fn res_to_json_in(h: jlong, environment: jint) -> JString);
fn res_to_json_in<'l>(env: &mut Env<'l>, _: JClass<'l>, h: jlong, e: jint) -> R<JString<'l>> {
    let s = handle::<aprv::VerifyReceiptResult>(h).to_json_in(environment(e)?)?;
    Ok(env.new_string(s)?)
}
