// Turns openssl-sys's link metadata into three cfgs, so the adapter can
// count its own backend-specific lines: aprv_libressl, aprv_awslc and
// aprv_openssl (OpenSSL proper).
fn main() {
    println!("cargo::rustc-check-cfg=cfg(aprv_libressl)");
    println!("cargo::rustc-check-cfg=cfg(aprv_awslc)");
    println!("cargo::rustc-check-cfg=cfg(aprv_openssl)");
    let libressl = std::env::var("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER").is_ok();
    let awslc = std::env::var("DEP_OPENSSL_AWSLC").is_ok();
    if libressl {
        println!("cargo:rustc-cfg=aprv_libressl");
    } else if awslc {
        println!("cargo:rustc-cfg=aprv_awslc");
    } else {
        println!("cargo:rustc-cfg=aprv_openssl");
    }
}
