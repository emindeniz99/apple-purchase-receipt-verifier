//! Q176 (2026-10-14): what the Rust core spends on the shapes Java began
//! screening on 13 and 14 October, through the core's Rust API, natively.
//!
//! Part 1 runs 21 shared cases from `fixtures/cases.json`. Part 2 builds
//! each shape again from the test PKI the Rust tests use (the shared
//! generated receipt pinned to its own root, `fixtures/generated-0.7/`),
//! from the fixture's size up to the largest the 3 MiB receipt cap or the
//! envelope's node and depth bounds allow, and measures every input the
//! same way:
//!
//! - one warm-up call, whose verdict is the row's;
//! - one call for memory: the peak of live heap above the level before the
//!   call, Rust's allocations and OpenSSL's together (OpenSSL's through
//!   `CRYPTO_set_mem_functions`), the bytes allocated in all, and the rise
//!   of the process's peak resident set during the call (`VmHWM`, reset
//!   through `/proc/self/clear_refs` after glibc's `malloc_trim` has
//!   returned the free heap; Linux and glibc only);
//! - nine timed calls (three when the warm-up took over 300 ms): median
//!   and minimum wall time.
//!
//! It prints verdicts, reasons and sizes only: nothing from a payload.
//! Run as an example of the core crate, so it gets the dev-dependencies
//! and the test seams (see README.md).

#[path = "../tests/common/mod.rs"]
mod common;

use apple_purchase_receipt_verifier::__internal::{base64_encode, openssl_version};
use apple_purchase_receipt_verifier::{Config, TrustAnchor, Verifier};
use common::ber::parse_exact;
use common::{der, der_int, der_oid, der_seq, der_set, tag, CmsBuilder, Rng};
use serde_json::Value;
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::time::{Duration, Instant};

// --- heap accounting: Rust and OpenSSL ---------------------------------

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static TOTAL: AtomicU64 = AtomicU64::new(0);

fn grew(bytes: usize) {
    let now = CURRENT.fetch_add(bytes, Relaxed) + bytes;
    PEAK.fetch_max(now, Relaxed);
    TOTAL.fetch_add(bytes as u64, Relaxed);
}

fn shrank(bytes: usize) {
    CURRENT.fetch_sub(bytes, Relaxed);
}

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        shrank(layout.size());
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            if new_size > layout.size() {
                grew(new_size - layout.size());
            } else {
                shrank(layout.size() - new_size);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// OpenSSL's allocations, routed to the same counters. Each block carries
/// its size in a 16-byte header.
const HEADER: usize = 16;
type MallocFn = unsafe extern "C" fn(usize, *const c_char, c_int) -> *mut c_void;
type ReallocFn = unsafe extern "C" fn(*mut c_void, usize, *const c_char, c_int) -> *mut c_void;
type FreeFn = unsafe extern "C" fn(*mut c_void, *const c_char, c_int);

extern "C" {
    fn CRYPTO_set_mem_functions(m: MallocFn, r: ReallocFn, f: FreeFn) -> c_int;
    /// glibc: hands freed heap pages back to the kernel, so the next call
    /// has to fault in what it uses and the peak resident set shows it.
    fn malloc_trim(pad: usize) -> c_int;
}

fn block(size: usize) -> Layout {
    Layout::from_size_align(HEADER + size, 16).unwrap()
}

unsafe extern "C" fn ossl_malloc(size: usize, _: *const c_char, _: c_int) -> *mut c_void {
    let base = unsafe { System.alloc(block(size)) };
    if base.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { base.cast::<usize>().write(size) };
    grew(size);
    unsafe { base.add(HEADER) }.cast()
}

unsafe extern "C" fn ossl_realloc(
    ptr: *mut c_void,
    size: usize,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    if ptr.is_null() {
        return unsafe { ossl_malloc(size, file, line) };
    }
    if size == 0 {
        unsafe { ossl_free(ptr, file, line) };
        return std::ptr::null_mut();
    }
    let base = unsafe { ptr.cast::<u8>().sub(HEADER) };
    let old = unsafe { base.cast::<usize>().read() };
    let moved = unsafe { System.realloc(base, block(old), HEADER + size) };
    if moved.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { moved.cast::<usize>().write(size) };
    if size > old {
        grew(size - old);
    } else {
        shrank(old - size);
    }
    unsafe { moved.add(HEADER) }.cast()
}

unsafe extern "C" fn ossl_free(ptr: *mut c_void, _: *const c_char, _: c_int) {
    if ptr.is_null() {
        return;
    }
    let base = unsafe { ptr.cast::<u8>().sub(HEADER) };
    let old = unsafe { base.cast::<usize>().read() };
    unsafe { System.dealloc(base, block(old)) };
    shrank(old);
}

fn status_kib(field: &str) -> Option<i64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with(field))?;
    line[field.len()..]
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()
}

// --- measuring one input ----------------------------------------------

struct Measured {
    verdict: String,
    median: Duration,
    min: Duration,
    runs: usize,
    peak_heap: usize,
    allocated: u64,
    rss_rise_kib: Option<i64>,
}

fn measure(call: &dyn Fn() -> String) -> Measured {
    let warm_start = Instant::now();
    let verdict = call();
    let warm = warm_start.elapsed();

    let base = CURRENT.load(Relaxed);
    PEAK.store(base, Relaxed);
    let total_before = TOTAL.load(Relaxed);
    // SAFETY: glibc's malloc_trim only releases free memory.
    unsafe { malloc_trim(0) };
    let hwm_reset = std::fs::write("/proc/self/clear_refs", "5").is_ok();
    let rss_before = status_kib("VmRSS:");
    let again = call();
    let peak_heap = PEAK.load(Relaxed).saturating_sub(base);
    let allocated = TOTAL.load(Relaxed) - total_before;
    let rss_rise_kib = match (hwm_reset, rss_before, status_kib("VmHWM:")) {
        (true, Some(before), Some(hwm)) => Some(hwm - before),
        _ => None,
    };
    assert_eq!(again, verdict, "the verdict changed between calls");

    let runs = if warm > Duration::from_millis(300) {
        3
    } else {
        9
    };
    let mut times: Vec<Duration> = (0..runs)
        .map(|_| {
            let start = Instant::now();
            let _ = call();
            start.elapsed()
        })
        .collect();
    times.sort();
    Measured {
        verdict,
        median: times[runs / 2],
        min: times[0],
        runs,
        peak_heap,
        allocated,
        rss_rise_kib,
    }
}

fn verdict_of<T>(result: Result<T, apple_purchase_receipt_verifier::Failure>) -> String {
    match result {
        Ok(_) => "ok".to_owned(),
        Err(failure) => format!("{}: {}", failure.reason().as_str(), failure.message()),
    }
}

fn header() {
    println!(
        "part\tname\tparam\tinput_b64_bytes\tverdict\tmedian_ms\tmin_ms\truns\tpeak_heap_kib\tallocated_kib\trss_rise_kib"
    );
}

fn row(part: &str, name: &str, param: &str, input_len: usize, m: &Measured) {
    println!(
        "{part}\t{name}\t{param}\t{input_len}\t{}\t{:.3}\t{:.3}\t{}\t{}\t{}\t{}",
        m.verdict,
        m.median.as_secs_f64() * 1e3,
        m.min.as_secs_f64() * 1e3,
        m.runs,
        m.peak_heap / 1024,
        m.allocated / 1024,
        m.rss_rise_kib
            .map_or_else(|| "n/a".to_owned(), |k| k.to_string()),
    );
}

fn receipt_row(verifier: &Verifier, name: &str, param: &str, der_bytes: &[u8]) {
    let b64 = base64_encode(der_bytes);
    let m = measure(&|| verdict_of(verifier.verify_receipt(&b64)));
    row("shape", name, param, b64.len(), &m);
}

// --- part 1: the shared cases ------------------------------------------

const OCTOBER_CASES: [&str; 21] = [
    "receipt/expose-unknown-attributes",
    "receipt/reject-signer-absent-beside-a-malformed-stranger",
    "receipt/verify-genuine-padded-with-oversized-strangers",
    "receipt/signer-rsa-pss-does-not-crash",
    "receipt/reject-signer-rsa-pss-tampered",
    "receipt/first-failing-signer-decides-when-the-stranger-comes-first",
    "receipt/reject-a-signer-info-signed-md2-with-rsa",
    "receipt/reject-a-signer-info-labelled-rsa-pss-with-a-huge-salt",
    "receipt/accept-genuine-beside-a-stranger-labelled-rsa-pss-with-a-huge-salt",
    "receipt/accept-genuine-beside-a-stranger-labelled-rsa-pss-with-a-negative-salt",
    "receipt/reject-a-signer-info-labelled-with-the-generic-composite-oid",
    "receipt/accept-genuine-beside-a-stranger-labelled-with-the-generic-composite-oid",
    "receipt/accept-genuine-beside-a-stranger-with-a-thousand-and-one-extensions",
    "receipt/accept-genuine-beside-a-stranger-labelled-md2-with-rsa",
    "receipt/verify-with-a-stranger-whose-key-is-unreadable",
    "receipt/verify-with-a-stranger-vouched-by-a-same-named-root-listed-first",
    "receipt/verify-with-a-stranger-vouched-by-a-same-named-root-listed-second",
    "receipt/reject-a-stranger-whose-signature-bit-string-is-unaligned",
    "receipt/printable-string-attributes-are-kept-raw",
    "signed-data/reject-a-header-number-of-1001-digits",
    "receipt/reject-signed-attributes-with-two-message-digests",
];

fn fixture(registry: &Value, id: &str) -> (Vec<u8>, String) {
    let entry = &registry[id];
    let path = common::fixtures_dir().join(entry["path"].as_str().expect("fixture path"));
    let raw = std::fs::read(&path).expect("fixture readable");
    let codec = entry["codec"].as_str().expect("codec").to_owned();
    let bytes = match codec.as_str() {
        "raw" | "text" => raw,
        "base64" => common::decode_base64(&String::from_utf8(raw).expect("utf-8")),
        "utf8" => String::from_utf8(raw)
            .expect("utf-8")
            .trim()
            .as_bytes()
            .to_vec(),
        other => panic!("unknown codec {other}"),
    };
    (bytes, codec)
}

fn shared_cases() {
    let dir = common::fixtures_dir();
    let file: Value =
        serde_json::from_slice(&std::fs::read(dir.join("cases.json")).unwrap()).unwrap();
    let registry = &file["fixtures"];
    for id in OCTOBER_CASES {
        let case = file["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["id"] == id)
            .unwrap_or_else(|| panic!("no case {id}"));
        let roots = &case["config"]["trustedRoots"];
        let config = match roots["source"].as_str().unwrap() {
            "defaults" => Config::default(),
            "fixtures" => {
                let anchors: Vec<TrustAnchor> = roots["fixtures"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|root| {
                        TrustAnchor::from_der(&fixture(registry, root.as_str().unwrap()).0).unwrap()
                    })
                    .collect();
                Config::builder().roots(anchors).build().unwrap()
            }
            other => panic!("unknown roots source {other}"),
        };
        assert!(
            case.get("clock").is_none(),
            "{id}: a pinned clock is not handled here"
        );
        let verifier = Verifier::new(config);
        let (bytes, codec) = fixture(registry, case["input"]["fixture"].as_str().unwrap());
        let expected = if let Some(one_of) = case["expected"].get("oneOf") {
            format!("oneOf {one_of}")
        } else {
            case["expected"]["reason"]
                .as_str()
                .unwrap_or_else(|| case["expected"]["status"].as_str().unwrap())
                .to_owned()
        };
        let (m, len) = match case["operation"].as_str().unwrap() {
            "verifyReceipt" => {
                let text = if codec == "text" {
                    String::from_utf8(bytes).unwrap()
                } else {
                    base64_encode(&bytes)
                };
                (
                    measure(&|| verdict_of(verifier.verify_receipt(&text))),
                    text.len(),
                )
            }
            "verifySignedData" => {
                let text = String::from_utf8(bytes).unwrap();
                (
                    measure(&|| verdict_of(verifier.verify_signed_data(&text))),
                    text.len(),
                )
            }
            other => panic!("unhandled operation {other}"),
        };
        let budget = case
            .get("maxMillis")
            .map_or_else(|| "-".to_owned(), ToString::to_string);
        row(
            "case",
            id,
            &format!("expected {expected}; maxMillis {budget}"),
            len,
            &m,
        );
    }
}

// --- part 2: the shapes, built from the test PKI ------------------------

/// The receipt cap in base64 characters, and the DER it can carry.
const CAP_B64: usize = 3_145_728;
const CAP_DER: usize = CAP_B64 / 4 * 3;

const OID_PSS: &str = "1.2.840.113549.1.1.10";
const OID_MGF1: &str = "1.2.840.113549.1.1.8";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
const OID_MD2_WITH_RSA: &str = "1.2.840.113549.1.1.2";
const OID_MD2: &str = "1.2.840.113549.2.2";
/// The generic composite label, id-alg-composite.
const OID_COMPOSITE: &str = "1.3.6.1.4.1.18227.2.1";
const OID_ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_DATA: &str = "1.2.840.113549.1.7.1";
const OID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const OID_CN: &str = "2.5.4.3";

fn sha256_alg() -> Vec<u8> {
    der_seq(&[der_oid(OID_SHA256), der(0x05, &[])])
}

fn plain_label(oid: &str) -> Vec<u8> {
    der_seq(&[der_oid(oid), der(0x05, &[])])
}

/// RSASSA-PSS, SHA-256, MGF1 with SHA-256, this saltLength TLV.
fn pss_label(salt: &[u8]) -> Vec<u8> {
    der_seq(&[
        der_oid(OID_PSS),
        der_seq(&[
            der(0xA0, &sha256_alg()),
            der(0xA1, &der_seq(&[der_oid(OID_MGF1), sha256_alg()])),
            der(0xA2, salt),
        ]),
    ])
}

/// A positive INTEGER of `octets` content octets, the largest that many
/// can hold; `None` for the fixture's 1,000,000,000.
fn salt(octets: Option<usize>) -> Vec<u8> {
    match octets {
        None => der_int(1_000_000_000),
        Some(n) => {
            let mut contents = vec![0x7F];
            contents.resize(n, 0xFF);
            der(tag::INTEGER, &contents)
        }
    }
}

/// The generic composite label holding `count` copies of `part`.
fn composite_label(part: &[u8], count: usize) -> Vec<u8> {
    der_seq(&[
        der_oid(OID_COMPOSITE),
        der(tag::SEQUENCE, &part.repeat(count)),
    ])
}

/// What the test PKI gives every shape: the shared receipt's pieces, its
/// root's subject and its signer's key.
struct Pki {
    root_name: Vec<u8>,
    signer_spki: Vec<u8>,
}

/// A certificate's TBS fields, as TLVs.
fn tbs_fields(certificate: &[u8]) -> Vec<Vec<u8>> {
    let parsed = parse_exact(certificate).unwrap();
    parsed
        .child(0)
        .unwrap()
        .children()
        .iter()
        .map(|field| field.full.to_vec())
        .collect()
}

impl Pki {
    fn new() -> Pki {
        let builder = CmsBuilder::from_shared();
        let root = common::receipt_root();
        let root_name = tbs_fields(root.der())[5].clone();
        let signer = builder
            .certificates
            .iter()
            .find(|raw| {
                let fields = tbs_fields(raw);
                parse_exact(&fields[1]).unwrap().contents == builder.signer_serial.as_slice()
            })
            .unwrap();
        let signer_spki = tbs_fields(signer)[6].clone();
        Pki {
            root_name,
            signer_spki,
        }
    }

    /// A certificate nobody signed, naming the pinned test root as its
    /// issuer (so the top-down walk compares names and runs the root's key
    /// over it), carrying the signer's key.
    fn stranger(
        &self,
        label: &[u8],
        issuer: Option<&[u8]>,
        subject: Option<&[u8]>,
        extensions: Option<&[u8]>,
        signature: &[u8],
    ) -> Vec<u8> {
        let mut tbs = vec![
            der(tag::CONTEXT_0, &der_int(2)),
            der_int(4242),
            label.to_vec(),
            issuer.map_or_else(|| self.root_name.clone(), <[u8]>::to_vec),
            der_seq(&[der(0x17, b"200101000000Z"), der(0x18, b"20991231000000Z")]),
            subject.map_or_else(|| name(der(tag::UTF8_STRING, b"Stranger")), <[u8]>::to_vec),
            self.signer_spki.clone(),
        ];
        if let Some(extensions) = extensions {
            tbs.push(der(tag::CONTEXT_3, &der(tag::SEQUENCE, extensions)));
        }
        let mut bits = vec![0x00];
        bits.extend_from_slice(signature);
        der_seq(&[der_seq(&tbs), label.to_vec(), der(tag::BIT_STRING, &bits)])
    }
}

/// A Name of one RDN holding one commonName with this value TLV.
fn name(value: Vec<u8>) -> Vec<u8> {
    der_seq(&[der_set(&[der_seq(&[der_oid(OID_CN), value])])])
}

/// The shared receipt with one more certificate in its bag.
fn with_stranger(certificate: Vec<u8>) -> Vec<u8> {
    let mut builder = CmsBuilder::from_shared();
    builder.certificates.push(certificate);
    builder.build()
}

/// The shared receipt with its one SignerInfo written by hand.
fn with_signer_info(
    issuer: Option<Vec<u8>>,
    digest_oid: &str,
    signed_attrs: Option<Vec<u8>>,
    signature_algorithm: Vec<u8>,
    signature: Option<Vec<u8>>,
    unsigned_attrs: Option<&[u8]>,
    content: Option<Vec<u8>>,
) -> Vec<u8> {
    let mut builder = CmsBuilder::from_shared();
    if let Some(content) = content {
        builder.content = Some(content);
    }
    builder.digest_oid = digest_oid.to_owned();
    let mut fields = vec![
        der_int(1),
        der_seq(&[
            issuer.unwrap_or_else(|| builder.signer_issuer.clone()),
            der(tag::INTEGER, &builder.signer_serial),
        ]),
        der_seq(&[der_oid(digest_oid)]),
    ];
    if let Some(signed) = signed_attrs.or_else(|| builder.signed_attrs.clone()) {
        fields.push(signed);
    }
    fields.push(signature_algorithm);
    fields.push(der(
        tag::OCTET_STRING,
        &signature.unwrap_or_else(|| builder.signature.clone()),
    ));
    if let Some(unsigned) = unsigned_attrs {
        fields.push(der(tag::CONTEXT_1, unsigned));
    }
    builder.include_signer_info = false;
    builder.signer_infos_before = vec![der_seq(&fields)];
    builder.build()
}

fn rsa_label() -> Vec<u8> {
    plain_label("1.2.840.113549.1.1.1")
}

/// The shared payload SET with one attribute 9999 appended whose value is
/// `octets` bytes.
fn payload_with(octets: usize) -> Vec<u8> {
    let content = CmsBuilder::from_shared().content.unwrap();
    let parsed = parse_exact(&content).unwrap();
    let mut attributes: Vec<Vec<u8>> = parsed
        .children()
        .iter()
        .map(|attribute| attribute.full.to_vec())
        .collect();
    attributes.push(der_seq(&[
        der_int(9999),
        der_int(1),
        der(
            tag::OCTET_STRING,
            &der(tag::OCTET_STRING, &vec![0x41; octets]),
        ),
    ]));
    der_set(&attributes)
}

/// BouncyCastle's `Arrays.hashCode(byte[])`, the hash of
/// `ASN1ObjectIdentifier` (bcprov 1.86): the octets from last to first,
/// each sign-extended.
fn bc_hash(data: &[u8]) -> i32 {
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let mut hc = (data.len() as i32).wrapping_add(1);
    for &octet in data.iter().rev() {
        hc = hc.wrapping_mul(257) ^ i32::from(octet as i8);
    }
    hc
}

/// 2^`stages` distinct OID contents that share one BouncyCastle hash
/// (Joux's multicollision: the hash keeps 32 bits of state, so each stage
/// is a birthday search for two 8-octet blocks that take the state to the
/// same next one). Every content is 1.3.6.1.4.1.99999 followed by one long
/// arc: the blocks, `pad` filler octets and a last octet of 1, every octet
/// before the last with its high bit set and none of them 0x80.
fn colliding_oids(stages: usize, pad: usize) -> Vec<Vec<u8>> {
    // Four octets cannot collide: 257 exceeds an octet's range, so the
    // hash of a short block never wraps 2^32 and is one-to-one. Eight do.
    const BLOCK: usize = 8;
    const PREFIX: [u8; 8] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8d, 0x1f];
    let len = PREFIX.len() + BLOCK * stages + pad + 1;
    // The hash runs from the last octet to the first: the 1, the filler,
    // then the blocks, last block first.
    let mut tail = vec![0xC1; pad];
    tail.push(0x01);
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let mut state = (len as i32).wrapping_add(1);
    for &octet in tail.iter().rev() {
        state = state.wrapping_mul(257) ^ i32::from(octet as i8);
    }
    let step = |state: i32, block: &[u8; BLOCK]| {
        block.iter().rev().fold(state, |h, &octet| {
            h.wrapping_mul(257) ^ i32::from(octet as i8)
        })
    };
    let mut rng = Rng::new(0x0176);
    let mut pairs: Vec<([u8; BLOCK], [u8; BLOCK])> = Vec::new();
    for _ in 0..stages {
        let mut seen: HashMap<i32, [u8; BLOCK]> = HashMap::new();
        loop {
            #[allow(clippy::cast_possible_truncation)]
            let candidate: [u8; BLOCK] = std::array::from_fn(|_| 0x81 + rng.below(127) as u8);
            assert!(seen.len() < 1 << 22, "no collision in 2^22 blocks");
            let next = step(state, &candidate);
            match seen.get(&next) {
                Some(other) if *other != candidate => {
                    pairs.push((*other, candidate));
                    state = next;
                    break;
                }
                _ => {
                    seen.insert(next, candidate);
                }
            }
        }
    }
    let oids: Vec<Vec<u8>> = (0..1usize << stages)
        .map(|mask| {
            let mut contents = PREFIX.to_vec();
            // Array position p holds the block of stage stages - 1 - p.
            for position in 0..stages {
                let stage = stages - 1 - position;
                let (a, b) = pairs[stage];
                contents.extend_from_slice(if mask >> stage & 1 == 1 { &b } else { &a });
            }
            contents.extend_from_slice(&tail);
            contents
        })
        .collect();
    let first = bc_hash(&oids[0]);
    assert!(oids.iter().all(|oid| bc_hash(oid) == first), "not one hash");
    let mut sorted = oids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), oids.len(), "not distinct");
    oids
}

/// The OID 1.3.6.1.4.1.99999.1.n, as the October fixtures write it.
fn filler_oid(n: usize) -> Vec<u8> {
    der_oid(&format!("1.3.6.1.4.1.99999.1.{n}"))
}

fn b64_len(der_len: usize) -> usize {
    der_len.div_ceil(3) * 4
}

/// The largest `n` in `lo..=hi` for which `fits(n)`, `fits` being true
/// up to some `n` and false after it.
fn largest(lo: usize, hi: usize, fits: impl Fn(usize) -> bool) -> usize {
    assert!(fits(lo), "even {lo} does not fit");
    if fits(hi) {
        return hi;
    }
    let (mut good, mut bad) = (lo, hi);
    while bad - good > 1 {
        let mid = good + (bad - good) / 2;
        if fits(mid) {
            good = mid;
        } else {
            bad = mid;
        }
    }
    good
}

fn within_cap(der_bytes: &[u8]) -> bool {
    b64_len(der_bytes.len()) <= CAP_B64
}

/// Within the cap and not refused by the envelope's node budget or depth.
fn within_bounds(verifier: &Verifier, der_bytes: &[u8]) -> bool {
    within_cap(der_bytes) && {
        let verdict = verdict_of(verifier.verify_receipt(&base64_encode(der_bytes)));
        !verdict.contains("ASN.1 values") && !verdict.contains("nested deeper")
    }
}

fn shapes() {
    let pki = Pki::new();
    let verifier = common::receipt_verifier();
    let signature_256 = vec![0x5A; 256];

    // 0. The floor: the valid receipt with one unsigned attribute holding
    // a cap-sized OCTET STRING, which the core accepts.
    {
        let build = |octets: usize| {
            let attribute = der_seq(&[
                der_oid("1.3.6.1.4.1.99999.2"),
                der_set(&[der(tag::OCTET_STRING, &vec![0x41; octets])]),
            ]);
            with_signer_info(
                None,
                OID_SHA256,
                None,
                rsa_label(),
                None,
                Some(&attribute),
                None,
            )
        };
        receipt_row(
            &verifier,
            "baseline-unsigned-octets",
            "0",
            &CmsBuilder::from_shared().build(),
        );
        let max = largest(0, CAP_DER, |n| within_cap(&build(n)));
        for octets in [262_144, max] {
            receipt_row(
                &verifier,
                "baseline-unsigned-octets",
                &octets.to_string(),
                &build(octets),
            );
        }
    }

    // 1. RSASSA-PSS saltLength on the SignerInfo, which names the trusted
    // signer: OpenSSL reads the parameters when it checks the signature.
    {
        let build = |octets: Option<usize>| {
            with_signer_info(
                None,
                OID_SHA256,
                None,
                pss_label(&salt(octets)),
                None,
                None,
                None,
            )
        };
        let max = largest(1, CAP_DER, |n| within_cap(&build(Some(n))));
        for octets in [
            None,
            Some(4),
            Some(8),
            Some(65_536),
            Some(524_288),
            Some(max),
        ] {
            let param =
                octets.map_or_else(|| "1e9 (fixture)".to_owned(), |n| format!("{n} octets"));
            receipt_row(&verifier, "pss-salt-signer-info", &param, &build(octets));
        }
    }

    // 2. The same label on a stranger in the bag, TBS and outer label both.
    {
        let build = |octets: usize| {
            let label = pss_label(&salt(Some(octets)));
            with_stranger(pki.stranger(&label, None, None, None, &signature_256))
        };
        let max = largest(1, CAP_DER, |n| within_cap(&build(n)));
        for octets in [4, 8, 65_536, 524_288, max] {
            receipt_row(
                &verifier,
                "pss-salt-stranger",
                &format!("{octets} octets"),
                &build(octets),
            );
        }
    }

    // 3. The generic composite label on the SignerInfo, its parameters
    // `count` sha256WithRSAEncryption AlgorithmIdentifiers.
    {
        let part = plain_label(OID_SHA256_WITH_RSA);
        let build = |count: usize| {
            with_signer_info(
                None,
                OID_SHA256,
                None,
                composite_label(&part, count),
                None,
                None,
                None,
            )
        };
        let nodes = largest(2, CAP_DER / part.len(), |n| {
            within_bounds(&verifier, &build(n))
        });
        let bytes = largest(2, CAP_DER / part.len(), |n| within_cap(&build(n)));
        for count in [2, 300, 3_000, 30_000, nodes, bytes] {
            receipt_row(
                &verifier,
                "composite-signer-info",
                &format!("{count} parts"),
                &build(count),
            );
        }
    }

    // 4. The generic composite label on a stranger: `count` ecdsa-with-SHA256
    // parts in both labels, `count` empty BIT STRINGs as its signature.
    {
        let part = der_seq(&[der_oid(OID_ECDSA_WITH_SHA256)]);
        let build = |count: usize| {
            let label = composite_label(&part, count);
            let signature = der(tag::SEQUENCE, &[0x03, 0x01, 0x00].repeat(count));
            with_stranger(pki.stranger(&label, None, None, None, &signature))
        };
        let nodes = largest(2, CAP_DER / 30, |n| within_bounds(&verifier, &build(n)));
        let bytes = largest(2, CAP_DER / 10, |n| within_cap(&build(n)));
        for count in [300, 3_000, nodes, bytes] {
            receipt_row(
                &verifier,
                "composite-stranger",
                &format!("{count} parts"),
                &build(count),
            );
        }
    }

    // 5. MD2. (a) md2WithRSAEncryption as the SignerInfo's signature label,
    // over content grown by one payload attribute; (b) MD2 as its
    // digestAlgorithm over the same content; (c) md2WithRSAEncryption on a
    // stranger whose TBS carries one large extension.
    {
        let build_a = |octets: Option<usize>| {
            with_signer_info(
                None,
                OID_SHA256,
                None,
                plain_label(OID_MD2_WITH_RSA),
                None,
                None,
                octets.map(payload_with),
            )
        };
        let max_a = largest(0, CAP_DER, |n| within_cap(&build_a(Some(n))));
        for octets in [None, Some(262_144), Some(max_a)] {
            let param =
                octets.map_or_else(|| "shared content".to_owned(), |n| format!("+{n} octets"));
            receipt_row(&verifier, "md2-label-signer-info", &param, &build_a(octets));
        }
        let build_b = |octets: Option<usize>| {
            with_signer_info(
                None,
                OID_MD2,
                None,
                rsa_label(),
                None,
                None,
                octets.map(payload_with),
            )
        };
        let max_b = largest(0, CAP_DER, |n| within_cap(&build_b(Some(n))));
        for octets in [None, Some(max_b)] {
            let param =
                octets.map_or_else(|| "shared content".to_owned(), |n| format!("+{n} octets"));
            receipt_row(
                &verifier,
                "md2-digest-signer-info",
                &param,
                &build_b(octets),
            );
        }
        let build_c = |octets: usize| {
            let extension = der_seq(&[
                der_oid("1.3.6.1.4.1.99999.3"),
                der(tag::OCTET_STRING, &vec![0x41; octets]),
            ]);
            with_stranger(pki.stranger(
                &plain_label(OID_MD2_WITH_RSA),
                None,
                None,
                Some(&extension),
                &signature_256,
            ))
        };
        let max_c = largest(0, CAP_DER, |n| within_cap(&build_c(n)));
        for octets in [0, 262_144, max_c] {
            receipt_row(
                &verifier,
                "md2-label-stranger",
                &format!("+{octets} octets"),
                &build_c(octets),
            );
        }
    }

    // OIDs that share one BouncyCastle hash: 32,768 short ones (129 octets
    // each) and 1,024 long ones, padded to fill the cap.
    let short = colliding_oids(15, 0);
    eprintln!(
        "colliding set: {} OIDs of {} content octets, one hash",
        short.len(),
        short[0].len()
    );

    // 6. Hash-colliding OIDs as unsigned attributes of the trusted
    // SignerInfo, each holding SET { NULL }.
    {
        let attribute = |oid: &[u8]| der_seq(&[der(tag::OID, oid), der_set(&[der(0x05, &[])])]);
        let build = |oids: &[Vec<u8>]| {
            let unsigned: Vec<u8> = oids.iter().flat_map(|oid| attribute(oid)).collect();
            with_signer_info(
                None,
                OID_SHA256,
                None,
                rsa_label(),
                None,
                Some(&unsigned),
                None,
            )
        };
        let nodes = largest(1, short.len(), |n| {
            within_bounds(&verifier, &build(&short[..n]))
        });
        for count in [1_001, 4_096, 16_384, nodes, short.len()] {
            receipt_row(
                &verifier,
                "colliding-oids-unsigned-attrs",
                &format!("{count} x {} octets", short[0].len()),
                &build(&short[..count]),
            );
        }
        // 1,024 colliding OIDs, as long as the cap allows: the filler grows
        // each one, and the set is rebuilt for each length tried.
        let pad = largest(0, CAP_DER / 1024, |p| {
            within_cap(&build(&colliding_oids(10, p)))
        });
        let long = colliding_oids(10, pad);
        receipt_row(
            &verifier,
            "colliding-oids-unsigned-attrs",
            &format!("1024 x {} octets", long[0].len()),
            &build(&long),
        );
    }

    // 7. A stranger with many extensions: hash-colliding OIDs up to the node
    // budget, then the cap filled with short distinct OIDs.
    {
        let extension = |oid: &[u8]| der_seq(&[der(tag::OID, oid), der(tag::OCTET_STRING, &[])]);
        let build = |oids: &[Vec<u8>]| {
            let extensions: Vec<u8> = oids.iter().flat_map(|oid| extension(oid)).collect();
            with_stranger(pki.stranger(
                &plain_label(OID_SHA256_WITH_RSA),
                None,
                None,
                Some(&extensions),
                &signature_256,
            ))
        };
        let nodes = largest(1, short.len(), |n| {
            within_bounds(&verifier, &build(&short[..n]))
        });
        for count in [1_001, 10_000, nodes] {
            receipt_row(
                &verifier,
                "extensions-stranger",
                &format!("{count} colliding"),
                &build(&short[..count]),
            );
        }
        let build_filler = |count: usize| {
            let extensions: Vec<u8> = (0..count)
                .flat_map(|n| der_seq(&[filler_oid(n), der(tag::OCTET_STRING, &[])]))
                .collect();
            with_stranger(pki.stranger(
                &plain_label(OID_SHA256_WITH_RSA),
                None,
                None,
                Some(&extensions),
                &signature_256,
            ))
        };
        let bytes = largest(1, CAP_DER / 10, |n| within_cap(&build_filler(n)));
        receipt_row(
            &verifier,
            "extensions-stranger",
            &format!("{bytes} filler"),
            &build_filler(bytes),
        );
    }

    // 8. Signed attributes on a SignerInfo that names the trusted signer:
    // contentType, the right messageDigest, and `count` more, each
    // SET { NULL } under a colliding OID; a signature nobody made.
    {
        let content = CmsBuilder::from_shared().content.unwrap();
        let digest = openssl::sha::sha256(&content);
        let build = |oids: &[Vec<u8>]| {
            let mut attributes = vec![
                der_seq(&[der_oid(OID_CONTENT_TYPE), der_set(&[der_oid(OID_DATA)])]),
                der_seq(&[
                    der_oid(OID_MESSAGE_DIGEST),
                    der_set(&[der(tag::OCTET_STRING, &digest)]),
                ]),
            ];
            attributes.extend(
                oids.iter()
                    .map(|oid| der_seq(&[der(tag::OID, oid), der_set(&[der(0x05, &[])])])),
            );
            with_signer_info(
                None,
                OID_SHA256,
                Some(der(tag::CONTEXT_0, &attributes.concat())),
                rsa_label(),
                Some(vec![0x5A; 256]),
                None,
                None,
            )
        };
        let nodes = largest(1, short.len(), |n| {
            within_bounds(&verifier, &build(&short[..n]))
        });
        for count in [0, 1_001, 10_000, nodes] {
            receipt_row(
                &verifier,
                "signed-attrs-signer-info",
                &format!("2 + {count} colliding"),
                &build(&short[..count]),
            );
        }
    }

    // 9. Nested SETs (and, for comparison, SEQUENCEs) as the commonName
    // value of an issuer name: on the SignerInfo, which then names no
    // embedded certificate, and on a stranger's issuer and subject.
    for (kind, constructed) in [("set", tag::SET), ("sequence", tag::SEQUENCE)] {
        let nested = |depth: usize, width: usize, leaf: &[u8]| {
            let mut value = leaf.to_vec();
            for _ in 0..depth {
                let mut parts = vec![leaf.to_vec(); width];
                parts.push(value);
                value = der(constructed, &parts.concat());
            }
            value
        };
        let utf8 = |octets: usize| der(tag::UTF8_STRING, &vec![0x41; octets]);
        let signer_info = |depth: usize, width: usize, leaf: &[u8]| {
            with_signer_info(
                Some(name(nested(depth, width, leaf))),
                OID_SHA256,
                None,
                rsa_label(),
                None,
                None,
                None,
            )
        };
        let stranger = |depth: usize, width: usize, leaf: &[u8]| {
            let named = name(nested(depth, width, leaf));
            with_stranger(pki.stranger(
                &plain_label(OID_SHA256_WITH_RSA),
                Some(&named),
                Some(&named),
                None,
                &signature_256,
            ))
        };
        for (place, build) in [
            (
                "signer-info-issuer",
                &signer_info as &dyn Fn(usize, usize, &[u8]) -> Vec<u8>,
            ),
            ("stranger-names", &stranger),
        ] {
            let name_row = format!("nested-{kind}-{place}");
            let leaf = utf8(1);
            let depth = largest(1, 64, |d| within_bounds(&verifier, &build(d, 1, &leaf)));
            receipt_row(
                &verifier,
                &name_row,
                &format!("depth {depth}, width 1"),
                &build(depth, 1, &leaf),
            );
            let width = largest(1, 50_000, |w| {
                within_bounds(&verifier, &build(depth, w, &leaf))
            });
            for w in [width / 10, width] {
                receipt_row(
                    &verifier,
                    &name_row,
                    &format!("depth {depth}, width {w}"),
                    &build(depth, w, &leaf),
                );
            }
            let octets = largest(1, CAP_DER, |n| within_cap(&build(depth, 1, &utf8(n))));
            receipt_row(
                &verifier,
                &name_row,
                &format!("depth {depth}, width 1, leaves of {octets} octets"),
                &build(depth, 1, &utf8(octets)),
            );
        }
    }

    // 10. Nested SETs as AlgorithmIdentifier parameters, the other place
    // Java screens for them: the SignerInfo's signatureAlgorithm, and a
    // stranger's two signature labels.
    {
        let nested = |depth: usize, width: usize, leaf: &[u8]| {
            let mut value = leaf.to_vec();
            for _ in 0..depth {
                let mut parts = vec![leaf.to_vec(); width];
                parts.push(value);
                value = der(tag::SET, &parts.concat());
            }
            value
        };
        let utf8 = |octets: usize| der(tag::UTF8_STRING, &vec![0x41; octets]);
        let label = |depth: usize, width: usize, leaf: &[u8]| {
            der_seq(&[der_oid(OID_SHA256_WITH_RSA), nested(depth, width, leaf)])
        };
        let signer_info = |depth: usize, width: usize, leaf: &[u8]| {
            with_signer_info(
                None,
                OID_SHA256,
                None,
                label(depth, width, leaf),
                None,
                None,
                None,
            )
        };
        let stranger = |depth: usize, width: usize, leaf: &[u8]| {
            with_stranger(pki.stranger(
                &label(depth, width, leaf),
                None,
                None,
                None,
                &signature_256,
            ))
        };
        for (place, build) in [
            (
                "signer-info-signature-algorithm",
                &signer_info as &dyn Fn(usize, usize, &[u8]) -> Vec<u8>,
            ),
            ("stranger-labels", &stranger),
        ] {
            let name_row = format!("nested-set-params-{place}");
            let leaf = utf8(1);
            let depth = largest(1, 64, |d| within_bounds(&verifier, &build(d, 1, &leaf)));
            receipt_row(
                &verifier,
                &name_row,
                &format!("depth {depth}, width 1"),
                &build(depth, 1, &leaf),
            );
            let width = largest(1, 50_000, |w| {
                within_bounds(&verifier, &build(depth, w, &leaf))
            });
            for w in [width / 10, width] {
                receipt_row(
                    &verifier,
                    &name_row,
                    &format!("depth {depth}, width {w}"),
                    &build(depth, w, &leaf),
                );
            }
            let octets = largest(1, CAP_DER, |n| within_cap(&build(depth, 1, &utf8(n))));
            receipt_row(
                &verifier,
                &name_row,
                &format!("depth {depth}, width 1, leaves of {octets} octets"),
                &build(depth, 1, &utf8(octets)),
            );
        }
    }
}

fn main() {
    // SAFETY: called before anything in this process has touched OpenSSL.
    let hooked = unsafe { CRYPTO_set_mem_functions(ossl_malloc, ossl_realloc, ossl_free) } == 1;
    assert!(
        hooked,
        "OpenSSL allocated before its allocator could be set"
    );
    eprintln!("{}", openssl_version());
    header();
    shared_cases();
    shapes();
}
