//! Spike: a pointer+length ABI for pure-Go wasm hosts (wazero). JSON out.
//! Not the design; only proves the path. Unsafe is confined to this adapter.
#![allow(clippy::missing_safety_doc)]

#[no_mangle]
pub extern "C" fn aprv_alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len);
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

#[no_mangle]
pub unsafe extern "C" fn aprv_dealloc(ptr: *mut u8, cap: usize) {
    drop(Vec::from_raw_parts(ptr, 0, cap));
}

fn out(s: String) -> u64 {
    let mut b = s.into_bytes();
    b.shrink_to_fit();
    let (p, l) = (b.as_mut_ptr() as u64, b.len() as u64);
    std::mem::forget(b);
    (p << 32) | l
}

/// Verifies a base64 receipt against Apple's pinned roots. Returns packed (ptr<<32|len) JSON.
#[no_mangle]
pub unsafe extern "C" fn aprv_verify_receipt_b64(bid: *const u8, bid_len: usize, r: *const u8, r_len: usize) -> u64 {
    let bid = std::str::from_utf8(std::slice::from_raw_parts(bid, bid_len)).unwrap_or("");
    let rec = std::str::from_utf8(std::slice::from_raw_parts(r, r_len)).unwrap_or("");
    let v = match aprv::ReceiptVerifier::builder().bundle_id(bid).trusted_roots(aprv::apple_receipt_roots().to_vec()).build() {
        Ok(v) => v,
        Err(e) => return out(format!(r#"{{"config":{:?}}}"#, e.detail())),
    };
    out(match v.verify_base64(rec) {
        Ok(a) => format!(r#"{{"ok":true,"bundleId":{:?},"iaps":{}}}"#, a.bundle_id.unwrap_or_default(), a.in_app_purchases.len()),
        Err(e) => format!(r#"{{"ok":false,"reason":"{}"}}"#, e.reason().as_str()),
    })
}
