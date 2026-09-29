//! The adapter reads no OpenSSL configuration, trust store or module from
//! the environment.
//!
//! Every check runs in a child process: this test binary run again with
//! only the `child` test selected and `APRV_ISOLATION_CHILD` naming what it
//! does. The parent plants, in the child's environment,
//!
//! - `SSL_CERT_FILE` and `SSL_CERT_DIR` holding the root that issued the
//!   fixture receipt's chain, so a default trust store would anchor it;
//! - `OPENSSL_CONF`, a configuration that sets the default property query
//!   to a provider that does not exist, so that every algorithm fetch, and
//!   with it every signature check, fails if the file is ever loaded;
//! - `OPENSSL_MODULES` and `OPENSSL_ENGINES`, directories a provider or
//!   engine load would look in.
//!
//! The isolated child must still verify the chain under its real anchor,
//! refuse it under an unrelated one, and verify the receipt's signature.
//! When `strace` can run, the parent also traces the child's file and
//! network system calls and asserts that it touched none of the planted
//! paths nor the library's OPENSSLDIR, and opened no socket. Setting
//! `APRV_REQUIRE_STRACE` makes a missing or unusable `strace` a failure
//! rather than a skipped trace (CI sets it).
//!
//! Two controls prove the detectors bite: a child that asks OpenSSL to
//! load its configuration before the adapter's first call must fail to
//! verify, and must be seen opening the planted file; and the planted
//! trust store, loaded explicitly through rust-openssl, must anchor the
//! chain the isolated child refused.

use aprv_openssl::{Certificate, PathProblemKind, SignedData};
use std::path::{Path, PathBuf};
use std::process::Command;

extern "C" {
    fn OPENSSL_init_crypto(opts: u64, settings: *const std::ffi::c_void) -> std::ffi::c_int;
}

/// `OPENSSL_INIT_LOAD_CONFIG` (crypto.h). Named explicitly: a build
/// configured with `no-autoload-config` (the wasm32-wasip1 one) loads no
/// configuration on OpenSSL's implicit initialisation at all.
const OPENSSL_INIT_LOAD_CONFIG: u64 = 0x0000_0040;

/// 2024-08-06, inside every fixture certificate's validity.
const AT: i64 = 1_722_945_600;

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/generated")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

/// The receipt's signer and its intermediate, told apart by the adapter
/// alone: the leaf may not issue certificates, and the root (left out)
/// issued itself.
fn chain(cms: &SignedData) -> (Certificate, Certificate) {
    let certificates = cms.certificates();
    let leaf = certificates
        .iter()
        .find(|c| !c.may_issue_certificates())
        .expect("no leaf")
        .clone();
    let intermediate = certificates
        .iter()
        .find(|c| c.may_issue_certificates() && !c.issued_by(c))
        .expect("no intermediate")
        .clone();
    (leaf, intermediate)
}

/// What the child does, by `APRV_ISOLATION_CHILD`. Without it, nothing:
/// run directly, this is an empty test.
#[test]
fn child() {
    let Ok(mode) = std::env::var("APRV_ISOLATION_CHILD") else {
        return;
    };
    if mode == "control" {
        // SAFETY: the documented initialisation call with a null settings
        // pointer, made before any adapter call, as a host that initialised
        // OpenSSL with its configuration first would.
        unsafe { OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, std::ptr::null()) };
    }
    // The adapter's first call: it must initialise OpenSSL itself.
    let limits = aprv_openssl::EnvelopeLimits {
        depth: 32,
        nodes: 100_000,
        signer_infos: 4,
        certificates: 10,
        crls: 10,
    };
    let mut cms = SignedData::parse(&fixture("receipt.der"), &limits).expect("fixture receipt");
    let (leaf, intermediate) = chain(&cms);
    let root = Certificate::from_der(&fixture("receipt-root.der")).unwrap();
    let unrelated = Certificate::from_der(&fixture("jws-root.der")).unwrap();

    let anchored =
        aprv_openssl::verify_path(&leaf, std::slice::from_ref(&intermediate), &[root], AT, 4);
    let signed = cms.verify_signer(0, &leaf);
    if mode == "control" {
        assert!(
            !anchored.passed() && !signed,
            "the planted configuration was loaded and did not bite: the detector is blind"
        );
        return;
    }
    assert!(anchored.passed(), "{:?}", anchored.problems);
    assert!(signed, "the receipt's signature does not verify");
    let refused = aprv_openssl::verify_path(&leaf, &[intermediate], &[unrelated], AT, 4);
    assert!(!refused.passed());
    assert!(
        refused
            .problems
            .iter()
            .any(|problem| problem.kind == PathProblemKind::NoIssuer),
        "{:?}",
        refused.problems
    );
}

/// The planted files, under a directory of their own.
struct Planted {
    dir: PathBuf,
}

impl Planted {
    fn new(name: &str) -> Planted {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("aprv-isolation-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("certs")).unwrap();
        std::fs::create_dir_all(dir.join("modules")).unwrap();
        std::fs::create_dir_all(dir.join("engines")).unwrap();
        let root = openssl::x509::X509::from_der(&fixture("receipt-root.der")).unwrap();
        let pem = root.to_pem().unwrap();
        std::fs::write(dir.join("cert.pem"), &pem).unwrap();
        let hash = root.subject_name_hash();
        std::fs::write(dir.join("certs").join(format!("{hash:08x}.0")), &pem).unwrap();
        std::fs::write(
            dir.join("openssl.cnf"),
            "openssl_conf = openssl_init\n\
             \n\
             [openssl_init]\n\
             alg_section = evp_properties\n\
             \n\
             [evp_properties]\n\
             default_properties = \"provider=aprv-isolation-nonexistent\"\n",
        )
        .unwrap();
        Planted { dir }
    }

    fn apply(&self, command: &mut Command) {
        command
            .env("SSL_CERT_FILE", self.dir.join("cert.pem"))
            .env("SSL_CERT_DIR", self.dir.join("certs"))
            .env("OPENSSL_CONF", self.dir.join("openssl.cnf"))
            .env("OPENSSL_MODULES", self.dir.join("modules"))
            .env("OPENSSL_ENGINES", self.dir.join("engines"));
    }
}

impl Drop for Planted {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Whether `strace` can trace a child here: installed, and ptrace allowed.
fn strace_usable() -> bool {
    let usable = Command::new("strace")
        .args(["-f", "-qq", "-o", "/dev/null", "true"])
        .status()
        .is_ok_and(|status| status.success());
    if !usable {
        assert!(
            std::env::var_os("APRV_REQUIRE_STRACE").is_none(),
            "APRV_REQUIRE_STRACE is set, but strace is missing or cannot trace here"
        );
        eprintln!("strace is missing or cannot trace here: the system-call trace is skipped");
    }
    usable
}

/// Runs the child in `mode` with `planted` in its environment, under
/// `strace` when `trace` names a log file. Returns whether it passed.
fn run_child(mode: &str, planted: &Planted, trace: Option<&Path>) -> bool {
    let exe = std::env::current_exe().unwrap();
    let mut command = match trace {
        Some(log) => {
            let mut strace = Command::new("strace");
            strace
                .args(["-f", "-qq", "-e", "trace=%file,%network", "-o"])
                .arg(log)
                .arg(&exe);
            strace
        }
        None => Command::new(&exe),
    };
    command
        .args(["child", "--exact", "--nocapture", "--test-threads=1"])
        .env("APRV_ISOLATION_CHILD", mode);
    planted.apply(&mut command);
    let output = command.output().unwrap();
    if !output.status.success() {
        eprintln!(
            "child {mode}:\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    output.status.success()
}

/// The directory OpenSSL was configured to read its files from.
fn openssldir() -> String {
    let reported = openssl::version::dir();
    let quoted = reported.split('"').nth(1).unwrap_or_default();
    assert!(
        !quoted.is_empty(),
        "OpenSSL reports no OPENSSLDIR: {reported}"
    );
    quoted.to_owned()
}

/// The trace lines that touch `path` or anything under it.
fn touching<'a>(log: &'a str, path: &str) -> Vec<&'a str> {
    let exact = format!("\"{path}\"");
    let under = format!("\"{}/", path.trim_end_matches('/'));
    log.lines()
        .filter(|line| line.contains(&exact) || line.contains(&under))
        .collect()
}

#[test]
fn a_planted_trust_store_configuration_and_module_path_are_ignored() {
    let planted = Planted::new("isolated");
    assert!(
        run_child("isolated", &planted, None),
        "the adapter's answers changed under the planted environment"
    );
    if !strace_usable() {
        return;
    }
    let log_path = planted.dir.with_extension("strace");
    assert!(
        run_child("isolated", &planted, Some(&log_path)),
        "the child failed under strace"
    );
    let log = std::fs::read_to_string(&log_path).unwrap();
    let _ = std::fs::remove_file(&log_path);
    let openssldir = openssldir();
    eprintln!(
        "traced {} file and network system calls of the isolated child; OPENSSLDIR {openssldir}",
        log.lines().count()
    );
    let planted_dir = planted.dir.to_string_lossy().into_owned();
    for (what, path) in [
        ("a planted path", &planted_dir),
        ("OPENSSLDIR", &openssldir),
    ] {
        let lines = touching(&log, path);
        assert!(
            lines.is_empty(),
            "the child touched {what}:\n{}",
            lines.join("\n")
        );
    }
    let sockets: Vec<&str> = log
        .lines()
        .filter(|line| line.contains("socket(") || line.contains("connect("))
        .collect();
    assert!(
        sockets.is_empty(),
        "the child opened a socket:\n{}",
        sockets.join("\n")
    );
}

#[test]
fn the_detectors_see_a_loaded_configuration_and_a_loaded_trust_store() {
    let planted = Planted::new("control");
    // The configuration, loaded before the adapter's first call, bites.
    let trace = strace_usable().then(|| planted.dir.with_extension("strace"));
    assert!(
        run_child("control", &planted, trace.as_deref()),
        "the control child did not see the planted configuration break verification"
    );
    if let Some(log_path) = trace {
        let log = std::fs::read_to_string(&log_path).unwrap();
        let _ = std::fs::remove_file(&log_path);
        let conf = planted
            .dir
            .join("openssl.cnf")
            .to_string_lossy()
            .into_owned();
        assert!(
            !touching(&log, &conf).is_empty(),
            "the trace does not show the planted configuration being read: the trace is blind"
        );
    }

    // The planted trust file and directory, loaded explicitly, anchor the
    // chain the isolated child refuses under an unrelated root.
    let der = fixture("receipt.der");
    let pkcs7 = openssl::pkcs7::Pkcs7::from_der(&der).unwrap();
    let signed = pkcs7.signed().unwrap();
    let certificates = signed.certificates().unwrap();
    let leaf = certificates
        .iter()
        .find(|c| {
            c.subject_name()
                .entries()
                .any(|e| e.data().as_slice() == b"Fake Receipt Signing")
        })
        .unwrap();
    let mut untrusted = openssl::stack::Stack::new().unwrap();
    for certificate in certificates {
        untrusted.push(certificate.to_owned()).unwrap();
    }
    for (file, dir) in [(Some("cert.pem"), None), (None, Some("certs"))] {
        let mut store = openssl::x509::store::X509StoreBuilder::new().unwrap();
        let lookup = if let Some(file) = file {
            let lookup = store
                .add_lookup(openssl::x509::store::X509Lookup::file())
                .unwrap();
            lookup
                .load_cert_file(planted.dir.join(file), openssl::ssl::SslFiletype::PEM)
                .unwrap();
            "file"
        } else {
            let lookup = store
                .add_lookup(openssl::x509::store::X509Lookup::hash_dir())
                .unwrap();
            lookup
                .add_dir(
                    planted.dir.join(dir.unwrap()).to_str().unwrap(),
                    openssl::ssl::SslFiletype::PEM,
                )
                .unwrap();
            "directory"
        };
        let store = store.build();
        let mut context = openssl::x509::X509StoreContext::new().unwrap();
        let verified = context
            .init(&store, leaf, &untrusted, |context| context.verify_cert())
            .unwrap();
        assert!(
            verified,
            "the planted trust {lookup} does not anchor the fixture chain: the test proves nothing"
        );
    }
}
