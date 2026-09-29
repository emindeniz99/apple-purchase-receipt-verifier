//! Spike: thin wasm-bindgen adapter over the canonical core. No verification logic.
use wasm_bindgen::prelude::*;
use std::time::UNIX_EPOCH;

fn verification_error(e: &aprv::VerificationError) -> JsValue {
    let err = js_sys::Error::new(e.detail());
    let _ = js_sys::Reflect::set(&err, &"reason".into(), &e.reason().as_str().into());
    err.into()
}
fn config_error(e: &aprv::ConfigError) -> JsValue { js_sys::TypeError::new(e.detail()).into() }

fn anchors(roots: Option<Vec<js_sys::Uint8Array>>, default: &[aprv::TrustAnchor]) -> Result<Vec<aprv::TrustAnchor>, JsValue> {
    match roots {
        None => Ok(default.to_vec()),
        Some(v) => v.iter().map(|u| aprv::TrustAnchor::from_der(&u.to_vec()).map_err(|e| config_error(&e))).collect(),
    }
}

fn ms(t: Option<std::time::SystemTime>) -> String {
    t.and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map_or("null".into(), |d| d.as_millis().to_string())
}

#[wasm_bindgen]
pub struct ReceiptVerifier { inner: aprv::ReceiptVerifier }

#[wasm_bindgen]
impl ReceiptVerifier {
    #[wasm_bindgen(constructor)]
    pub fn new(bundle_id: String, trusted_roots: Option<Vec<js_sys::Uint8Array>>) -> Result<ReceiptVerifier, JsValue> {
        let inner = aprv::ReceiptVerifier::builder()
            .bundle_id(bundle_id)
            .trusted_roots(anchors(trusted_roots, aprv::apple_receipt_roots())?)
            .build().map_err(|e| config_error(&e))?;
        Ok(Self { inner })
    }

    /// Returns a JSON summary (spike only; the real adapter returns objects).
    #[wasm_bindgen(js_name = verifyBase64)]
    pub fn verify_base64(&self, receipt: &str) -> Result<String, JsValue> {
        let r = self.inner.verify_base64(receipt).map_err(|e| verification_error(&e))?;
        Ok(format!(r#"{{"bundleId":{:?},"iaps":{},"creationDateMs":{}}}"#, r.bundle_id.unwrap_or_default(), r.in_app_purchases.len(), ms(r.creation_date)))
    }

    pub fn verify(&self, receipt: &[u8]) -> Result<String, JsValue> {
        let r = self.inner.verify(receipt).map_err(|e| verification_error(&e))?;
        Ok(format!(r#"{{"bundleId":{:?},"iaps":{},"creationDateMs":{}}}"#, r.bundle_id.unwrap_or_default(), r.in_app_purchases.len(), ms(r.creation_date)))
    }
}

#[wasm_bindgen]
pub struct JwsVerifier { inner: aprv::JwsVerifier }

#[wasm_bindgen]
impl JwsVerifier {
    #[wasm_bindgen(constructor)]
    pub fn new(bundle_id: String, environments: Vec<String>, trusted_roots: Option<Vec<js_sys::Uint8Array>>) -> Result<JwsVerifier, JsValue> {
        let envs = environments.iter().map(|s| s.parse::<aprv::Environment>().map_err(|e| config_error(&e))).collect::<Result<Vec<_>, _>>()?;
        let inner = aprv::JwsVerifier::builder()
            .bundle_id(bundle_id).accepted_environments(envs)
            .trusted_roots(anchors(trusted_roots, aprv::apple_jws_roots())?)
            .build().map_err(|e| config_error(&e))?;
        Ok(Self { inner })
    }

    /// Returns every claim as JSON text.
    #[wasm_bindgen(js_name = verifyTransaction)]
    pub fn verify_transaction(&self, jws: &str) -> Result<String, JsValue> {
        let p = self.inner.verify_transaction(jws).map_err(|e| verification_error(&e))?;
        Ok(aprv::serde_json::to_string(&p.claims).unwrap_or_default())
    }
}
