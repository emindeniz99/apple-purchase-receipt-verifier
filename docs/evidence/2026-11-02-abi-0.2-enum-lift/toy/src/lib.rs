mod bindings {
    wit_bindgen::generate!({ path: "wit", world: "aprv" });
}
use bindings::exports::aprv::verifier::verify::{Environment, Guest};

struct S;
impl Guest for S {
    fn verify_receipt_endpoint(env: Environment, now_ms: i64, request_json: Vec<u8>) -> String {
        let e = match env {
            Environment::Production => "production",
            Environment::Sandbox => "sandbox",
        };
        format!("{e} {now_ms} {}", request_json.len())
    }
}
bindings::export!(S with_types_in bindings);
