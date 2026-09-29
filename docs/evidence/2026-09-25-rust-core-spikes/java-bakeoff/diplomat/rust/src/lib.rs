//! Bake-off: a Diplomat bridge over the canonical core. Conversion only; the
//! core decides every verification outcome.
//!
//! Shape note: Diplomat's Kotlin backend maps `Result<T, E>` to
//! `kotlin.Result<T>`, and the Kotlin compiler gives every function returning
//! that inline class a hyphen-mangled JVM name (`verifyBase64-IoAF18A`) that
//! Java source cannot call. So no exported method returns `Result`: fallible
//! calls return an `*Outcome` opaque holding either the value or the error.

#[diplomat::bridge]
pub mod ffi {
    use diplomat_runtime::{DiplomatByte, DiplomatWrite};
    use std::fmt::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn ms(t: Option<SystemTime>) -> Option<i64> {
        t.and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .and_then(|d| i64::try_from(d.as_millis()).ok())
    }

    /// App Store environment.
    pub enum Environment {
        Production,
        Sandbox,
        Xcode,
        LocalTesting,
    }

    impl Environment {
        fn core(self) -> aprv::Environment {
            match self {
                Environment::Production => aprv::Environment::Production,
                Environment::Sandbox => aprv::Environment::Sandbox,
                Environment::Xcode => aprv::Environment::Xcode,
                Environment::LocalTesting => aprv::Environment::LocalTesting,
            }
        }
    }

    /// Why verification failed. Same tokens as every port.
    pub enum Reason {
        InvalidJwsFormat,
        InvalidCertificate,
        InvalidCertificatePurpose,
        InvalidChain,
        InvalidSignature,
        WrongBundleId,
        WrongEnvironment,
        WrongAppAppleId,
        InvalidReceiptFormat,
        DeviceHashMismatch,
        MalformedRequest,
        InternalError,
        RequestTooLarge,
    }

    impl Reason {
        fn from_core(r: aprv::Reason) -> Self {
            match r.as_str() {
                "INVALID_JWS_FORMAT" => Self::InvalidJwsFormat,
                "INVALID_CERTIFICATE" => Self::InvalidCertificate,
                "INVALID_CERTIFICATE_PURPOSE" => Self::InvalidCertificatePurpose,
                "INVALID_CHAIN" => Self::InvalidChain,
                "INVALID_SIGNATURE" => Self::InvalidSignature,
                "WRONG_BUNDLE_ID" => Self::WrongBundleId,
                "WRONG_ENVIRONMENT" => Self::WrongEnvironment,
                "WRONG_APP_APPLE_ID" => Self::WrongAppAppleId,
                "INVALID_RECEIPT_FORMAT" => Self::InvalidReceiptFormat,
                "DEVICE_HASH_MISMATCH" => Self::DeviceHashMismatch,
                "MALFORMED_REQUEST" => Self::MalformedRequest,
                "REQUEST_TOO_LARGE" => Self::RequestTooLarge,
                _ => Self::InternalError,
            }
        }
    }

    /// Verification failed: a reason token plus human-readable detail.
    #[diplomat::opaque]
    #[diplomat::attr(auto, error)]
    pub struct VerificationError(aprv::VerificationError);

    impl VerificationError {
        /// The machine-readable reason.
        pub fn reason(&self) -> Reason {
            Reason::from_core(self.0.reason())
        }
        /// Human-readable detail.
        pub fn detail(&self, w: &mut DiplomatWrite) {
            let _ = w.write_str(self.0.detail());
        }
    }

    /// The verifier was misconfigured (bad root, bad environment).
    #[diplomat::opaque]
    #[diplomat::attr(auto, error)]
    pub struct ConfigError(String);

    impl ConfigError {
        /// Human-readable detail.
        pub fn detail(&self, w: &mut DiplomatWrite) {
            let _ = w.write_str(&self.0);
        }
    }

    fn cfg(e: aprv::ConfigError) -> ConfigError {
        ConfigError(e.detail().to_owned())
    }

    /// A list of DER trust anchors (Diplomat has no list-of-byte-array input).
    #[diplomat::opaque_mut]
    pub struct TrustRoots(Vec<aprv::TrustAnchor>);

    impl TrustRoots {
        /// An empty list.
        pub fn create() -> Box<TrustRoots> {
            Box::new(TrustRoots(Vec::new()))
        }
        /// Parses and appends one DER root certificate. Returns the error, or
        /// nothing on success.
        pub fn add_der(&mut self, der: &[DiplomatByte]) -> Option<Box<ConfigError>> {
            match aprv::TrustAnchor::from_der(der) {
                Ok(a) => {
                    self.0.push(a);
                    None
                }
                Err(e) => Some(Box::new(cfg(e))),
            }
        }
    }

    fn roots_or(r: Option<&TrustRoots>, default: &[aprv::TrustAnchor]) -> Vec<aprv::TrustAnchor> {
        r.map_or_else(|| default.to_vec(), |r| r.0.clone())
    }

    /// A set of environments (Diplomat has no slice-of-enum input).
    #[diplomat::opaque_mut]
    pub struct EnvironmentSet(Vec<aprv::Environment>);

    impl EnvironmentSet {
        /// An empty set.
        pub fn create() -> Box<EnvironmentSet> {
            Box::new(EnvironmentSet(Vec::new()))
        }
        /// Adds one environment.
        pub fn add(&mut self, environment: Environment) {
            self.0.push(environment.core());
        }
    }

    /// One in-app purchase record from a verified receipt.
    #[diplomat::opaque]
    pub struct InAppPurchase(aprv::InAppPurchase);

    impl InAppPurchase {
        pub fn product_id<'a>(&'a self) -> Option<&'a str> {
            self.0.product_id.as_deref()
        }
        pub fn transaction_id<'a>(&'a self) -> Option<&'a str> {
            self.0.transaction_id.as_deref()
        }
        pub fn original_transaction_id<'a>(&'a self) -> Option<&'a str> {
            self.0.original_transaction_id.as_deref()
        }
        pub fn quantity(&self) -> Option<i64> {
            self.0.quantity
        }
        pub fn purchase_date_ms(&self) -> Option<i64> {
            ms(self.0.purchase_date)
        }
        pub fn expires_date_ms(&self) -> Option<i64> {
            ms(self.0.expires_date)
        }
    }

    /// A verified app receipt.
    #[diplomat::opaque]
    pub struct AppReceipt(aprv::AppReceipt);

    impl AppReceipt {
        pub fn receipt_type<'a>(&'a self) -> Option<&'a str> {
            self.0.receipt_type.as_deref()
        }
        pub fn bundle_id<'a>(&'a self) -> Option<&'a str> {
            self.0.bundle_id.as_deref()
        }
        pub fn app_version<'a>(&'a self) -> Option<&'a str> {
            self.0.app_version.as_deref()
        }
        pub fn original_app_version<'a>(&'a self) -> Option<&'a str> {
            self.0.original_app_version.as_deref()
        }
        pub fn opaque_value<'a>(&'a self) -> Option<&'a [DiplomatByte]> {
            self.0.opaque_value.as_deref()
        }
        pub fn sha1_hash<'a>(&'a self) -> Option<&'a [DiplomatByte]> {
            self.0.sha1_hash.as_deref()
        }
        pub fn creation_date_ms(&self) -> Option<i64> {
            ms(self.0.creation_date)
        }
        /// Number of in-app purchases.
        pub fn in_app_purchase_count(&self) -> i32 {
            i32::try_from(self.0.in_app_purchases.len()).unwrap_or(i32::MAX)
        }
        /// The in-app purchase at `index`, or nothing when out of range.
        pub fn in_app_purchase(&self, index: i32) -> Option<Box<InAppPurchase>> {
            let index = usize::try_from(index).ok()?;
            self.0.in_app_purchases.get(index).cloned().map(|p| Box::new(InAppPurchase(p)))
        }
    }

    /// Either a verified receipt or the reason it failed.
    #[diplomat::opaque]
    pub struct ReceiptOutcome(Result<AppReceipt, VerificationError>);

    impl ReceiptOutcome {
        pub fn receipt<'a>(&'a self) -> Option<&'a AppReceipt> {
            self.0.as_ref().ok()
        }
        pub fn error<'a>(&'a self) -> Option<&'a VerificationError> {
            self.0.as_ref().err()
        }
    }

    /// Verifies legacy PKCS#7 app receipts.
    #[diplomat::opaque]
    pub struct ReceiptVerifier(aprv::ReceiptVerifier);

    /// Either a receipt verifier or the configuration error.
    #[diplomat::opaque]
    pub struct ReceiptVerifierOutcome(Result<ReceiptVerifier, ConfigError>);

    impl ReceiptVerifierOutcome {
        pub fn verifier<'a>(&'a self) -> Option<&'a ReceiptVerifier> {
            self.0.as_ref().ok()
        }
        pub fn error<'a>(&'a self) -> Option<&'a ConfigError> {
            self.0.as_ref().err()
        }
    }

    impl ReceiptVerifier {
        /// `roots` absent means Apple's pinned roots.
        pub fn create(bundle_id: &str, roots: Option<&TrustRoots>) -> Box<ReceiptVerifierOutcome> {
            let r = aprv::ReceiptVerifier::builder()
                .bundle_id(bundle_id)
                .trusted_roots(roots_or(roots, aprv::apple_receipt_roots()))
                .build();
            Box::new(ReceiptVerifierOutcome(r.map(ReceiptVerifier).map_err(cfg)))
        }
        /// Verifies DER receipt bytes.
        pub fn verify(&self, der: &[DiplomatByte]) -> Box<ReceiptOutcome> {
            Box::new(ReceiptOutcome(self.0.verify(der).map(AppReceipt).map_err(VerificationError)))
        }
        /// Verifies a base64 receipt.
        pub fn verify_base64(&self, b64: &str) -> Box<ReceiptOutcome> {
            Box::new(ReceiptOutcome(self.0.verify_base64(b64).map(AppReceipt).map_err(VerificationError)))
        }
    }

    /// A verified StoreKit 2 transaction.
    #[diplomat::opaque]
    pub struct TransactionPayload(aprv::TransactionPayload);

    impl TransactionPayload {
        pub fn bundle_id<'a>(&'a self) -> Option<&'a str> {
            self.0.bundle_id.as_deref()
        }
        pub fn environment<'a>(&'a self) -> Option<&'a str> {
            self.0.environment.as_deref()
        }
        pub fn product_id<'a>(&'a self) -> Option<&'a str> {
            self.0.product_id.as_deref()
        }
        pub fn transaction_id<'a>(&'a self) -> Option<&'a str> {
            self.0.transaction_id.as_deref()
        }
        pub fn signed_date(&self) -> Option<i64> {
            self.0.signed_date
        }
        pub fn purchase_date(&self) -> Option<i64> {
            self.0.purchase_date
        }
        /// Every claim, as JSON text.
        pub fn claims_json(&self, w: &mut DiplomatWrite) {
            let _ = w.write_str(&aprv::serde_json::to_string(&self.0.claims).unwrap_or_default());
        }
    }

    /// Either a verified transaction or the reason it failed.
    #[diplomat::opaque]
    pub struct TransactionOutcome(Result<TransactionPayload, VerificationError>);

    impl TransactionOutcome {
        pub fn payload<'a>(&'a self) -> Option<&'a TransactionPayload> {
            self.0.as_ref().ok()
        }
        pub fn error<'a>(&'a self) -> Option<&'a VerificationError> {
            self.0.as_ref().err()
        }
    }

    /// Verifies StoreKit 2 JWS.
    #[diplomat::opaque]
    pub struct JwsVerifier(aprv::JwsVerifier);

    /// Either a JWS verifier or the configuration error.
    #[diplomat::opaque]
    pub struct JwsVerifierOutcome(Result<JwsVerifier, ConfigError>);

    impl JwsVerifierOutcome {
        pub fn verifier<'a>(&'a self) -> Option<&'a JwsVerifier> {
            self.0.as_ref().ok()
        }
        pub fn error<'a>(&'a self) -> Option<&'a ConfigError> {
            self.0.as_ref().err()
        }
    }

    impl JwsVerifier {
        /// `app_apple_id` absent means unchecked; `roots` absent means Apple's roots.
        pub fn create(
            bundle_id: &str,
            environments: &EnvironmentSet,
            app_apple_id: Option<i64>,
            roots: Option<&TrustRoots>,
        ) -> Box<JwsVerifierOutcome> {
            let mut b = aprv::JwsVerifier::builder()
                .bundle_id(bundle_id)
                .accepted_environments(environments.0.iter().copied())
                .trusted_roots(roots_or(roots, aprv::apple_jws_roots()));
            if let Some(id) = app_apple_id {
                match u64::try_from(id) {
                    Ok(id) => b = b.app_apple_id(id),
                    Err(_) => {
                        let e = ConfigError("appAppleId must be positive".into());
                        return Box::new(JwsVerifierOutcome(Err(e)));
                    }
                }
            }
            Box::new(JwsVerifierOutcome(b.build().map(JwsVerifier).map_err(cfg)))
        }
        pub fn verify_transaction(&self, jws: &str) -> Box<TransactionOutcome> {
            let r = self.0.verify_transaction(jws);
            Box::new(TransactionOutcome(r.map(TransactionPayload).map_err(VerificationError)))
        }
    }

    /// Local drop-in for Apple's verifyReceipt endpoint.
    #[diplomat::opaque]
    pub struct VerifyReceiptEndpoint(aprv::VerifyReceiptEndpoint);

    /// Either an endpoint or the configuration error.
    #[diplomat::opaque]
    pub struct EndpointOutcome(Result<VerifyReceiptEndpoint, ConfigError>);

    impl EndpointOutcome {
        pub fn endpoint<'a>(&'a self) -> Option<&'a VerifyReceiptEndpoint> {
            self.0.as_ref().ok()
        }
        pub fn error<'a>(&'a self) -> Option<&'a ConfigError> {
            self.0.as_ref().err()
        }
    }

    /// One request's outcome; re-renders without re-verifying.
    #[diplomat::opaque]
    pub struct VerifyReceiptResult(aprv::VerifyReceiptResult);

    impl VerifyReceiptEndpoint {
        pub fn create(environment: Environment, roots: Option<&TrustRoots>) -> Box<EndpointOutcome> {
            let r = aprv::VerifyReceiptEndpoint::builder()
                .environment(environment.core())
                .trusted_roots(roots_or(roots, aprv::apple_receipt_roots()))
                .build();
            Box::new(EndpointOutcome(r.map(VerifyReceiptEndpoint).map_err(cfg)))
        }
        /// Raw JSON body in, raw JSON body out. Never fails.
        pub fn verify_receipt_json(&self, body: &str, w: &mut DiplomatWrite) {
            let _ = w.write_str(&self.0.verify_receipt_json(body));
        }
        pub fn verify_receipt_result(&self, body: &str) -> Box<VerifyReceiptResult> {
            Box::new(VerifyReceiptResult(self.0.verify_receipt_result_from_json(body)))
        }
    }

    impl VerifyReceiptResult {
        pub fn status(&self) -> i64 {
            self.0.status()
        }
        pub fn verified(&self) -> bool {
            self.0.verified()
        }
        pub fn receipt(&self) -> Option<Box<AppReceipt>> {
            self.0.receipt().cloned().map(|r| Box::new(AppReceipt(r)))
        }
        pub fn failure_reason(&self) -> Option<Reason> {
            self.0.failure_reason().map(Reason::from_core)
        }
        pub fn to_json(&self, w: &mut DiplomatWrite) {
            let _ = w.write_str(&self.0.to_json());
        }
        /// The body as `environment`'s endpoint would send it. An environment
        /// other than Production/Sandbox yields the ConfigError instead.
        pub fn to_json_in(&self, environment: Environment) -> Box<JsonOutcome> {
            Box::new(JsonOutcome(self.0.to_json_in(environment.core()).map_err(cfg)))
        }
    }

    /// Either a JSON body or the configuration error. (`Option<()>` with a
    /// write generates a broken JNA struct; `Result` is uncallable from Java.)
    #[diplomat::opaque]
    pub struct JsonOutcome(Result<String, ConfigError>);

    impl JsonOutcome {
        /// The JSON text, or nothing on error.
        pub fn json<'a>(&'a self) -> Option<&'a str> {
            self.0.as_deref().ok()
        }
        pub fn error<'a>(&'a self) -> Option<&'a ConfigError> {
            self.0.as_ref().err()
        }
    }
}
