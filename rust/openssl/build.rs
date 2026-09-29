//! Compiles `payload.c`, the receipt payload grammar as OpenSSL ASN.1
//! templates, against the headers of the OpenSSL that openssl-sys links
//! (its `include` metadata), for the same target and with the C compiler
//! the `cc` crate picks for it (`CC_<target>` and `CFLAGS_<target>` for
//! wasm32-wasip1).

fn main() {
    println!("cargo:rerun-if-changed=payload.c");
    // The adapter is written and tested against OpenSSL 4.0: it calls 4.0
    // API (ASN1_BIT_STRING_get_length) and relies on 4.0's inclusive
    // notAfter. An older OpenSSL is refused here rather than linked and
    // left to answer differently.
    let version = std::env::var("DEP_OPENSSL_VERSION_NUMBER")
        .ok()
        .and_then(|hex| u64::from_str_radix(&hex, 16).ok());
    if version.is_none_or(|version| version < 0x4000_0000) {
        println!(
            "cargo:warning=aprv-openssl needs OpenSSL 4.0 or later; openssl-sys found {}. \
             Build with the `vendored` feature inside this repository's workspace, or set \
             OPENSSL_DIR to an OpenSSL 4 installation.",
            std::env::var("DEP_OPENSSL_VERSION_NUMBER").unwrap_or_else(|_| "none".to_owned())
        );
        std::process::exit(1);
    }
    let Some(include) = std::env::var_os("DEP_OPENSSL_INCLUDE") else {
        // openssl-sys always exports it; without it the templates would be
        // compiled against whatever headers the C compiler finds first.
        println!("cargo:warning=openssl-sys exported no include directory");
        std::process::exit(1);
    };
    cc::Build::new()
        .file("payload.c")
        .include(include)
        .warnings(true)
        .extra_warnings(true)
        .compile("aprv_payload");
}
