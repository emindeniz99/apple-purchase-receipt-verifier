//! What a [`Verifier`](crate::Verifier) is built from: the pinned roots,
//! the revocation settings and the clock.

use crate::error::ConfigError;
use crate::revocation::{BuiltIn, DistrustEntry, Revocation, Settings};
use crate::roots::{apple_roots, TrustAnchor};
use core::fmt;
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

/// The clock a [`Config`] reads: epoch milliseconds, UTC.
pub(crate) type ClockFn = dyn Fn() -> i64 + Send + Sync;

/// Immutable verifier configuration.
///
/// The clock answers "what time is it now?" and nothing else. The library
/// reads it at most once per call, and only for one of two things: the
/// certificate validity check when the receipt or JWS carries no usable
/// signing date, and `request_date` in the endpoint response. A clock must be safe to call
/// from several threads.
#[derive(Clone)]
pub struct Config {
    roots: Arc<[TrustAnchor]>,
    /// `None` only from [`Config::default`] when the built-in revocation
    /// list did not load; a verifier built from it answers
    /// `INTERNAL_ERROR` to every call.
    revocation: Option<Arc<Revocation>>,
    clock: Arc<ClockFn>,
}

impl Config {
    /// A builder whose unset parts are the [`Default`] ones.
    #[must_use]
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// The pinned roots.
    #[must_use]
    pub fn roots(&self) -> &[TrustAnchor] {
        &self.roots
    }

    /// The clock, as epoch milliseconds.
    #[must_use]
    pub fn clock(&self) -> &(dyn Fn() -> i64 + Send + Sync) {
        &*self.clock
    }

    pub(crate) fn into_parts(self) -> (Arc<[TrustAnchor]>, Option<Arc<Revocation>>, Arc<ClockFn>) {
        (self.roots, self.revocation, self.clock)
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("roots", &self.roots.len())
            .finish_non_exhaustive()
    }
}

/// Apple's three pinned roots, the built-in revocation list with no other
/// revocation setting, and the system clock.
///
/// The bundled roots load all together or not at all, each checked
/// against its published SHA-256, and so do the built-in revocation list
/// and its issuers' certificates. Should they not load, this cannot say
/// so: a [`Verifier`](crate::Verifier) built from it then answers
/// `INTERNAL_ERROR` to every call, where [`ConfigBuilder::build`] returns
/// a [`ConfigError`].
impl Default for Config {
    fn default() -> Self {
        static DEFAULT: OnceLock<Option<Arc<Revocation>>> = OnceLock::new();
        let roots: Arc<[TrustAnchor]> = apple_roots().into();
        let revocation = DEFAULT
            .get_or_init(|| {
                let settings = Settings {
                    roots: &roots,
                    lists: &[],
                    issuers: &[],
                    distrust: &[],
                };
                Revocation::build(&settings, BuiltIn::compiled()?)
                    .ok()
                    .map(Arc::new)
            })
            .clone();
        Config {
            roots,
            revocation,
            clock: Arc::new(system_millis),
        }
    }
}

/// Builds a [`Config`].
#[derive(Default)]
pub struct ConfigBuilder {
    roots: Option<Vec<TrustAnchor>>,
    revocation_lists: Vec<Vec<u8>>,
    revocation_issuers: Vec<TrustAnchor>,
    distrust: Vec<DistrustEntry>,
    built_in: Option<Result<Arc<BuiltIn>, ()>>,
    clock: Option<Arc<ClockFn>>,
}

impl ConfigBuilder {
    /// The roots a chain must reach, replacing Apple's bundled ones. Tests
    /// use their own.
    ///
    /// Each must be a root above the WWDR intermediate: an anchor that is
    /// the intermediate, or below it, never verifies a receipt or a JWS,
    /// and pinned beside its root it makes the verdict and the reason
    /// depend on the order of `roots` ([`TrustAnchor`]). Pin roots only.
    #[must_use]
    pub fn roots(mut self, roots: impl IntoIterator<Item = TrustAnchor>) -> Self {
        self.roots = Some(roots.into_iter().collect());
        self
    }

    /// Certificate revocation lists exactly as downloaded (DER), in any
    /// order, replacing any given before: Apple's lists from the URLs
    /// [`Verifier::revocation_urls`](crate::Verifier::revocation_urls)
    /// names. At most 16, each at most 1 MiB, 100,000 entries in all. Each
    /// must be signed by a configured root or a list issuer, and not be
    /// older than the newest list the built-in list records for its issuer;
    /// [`build`](ConfigBuilder::build) refuses it otherwise. A genuine list
    /// that uses something this library does not support (version 1, no
    /// `nextUpdate`, an issuing distribution point, a delta list, indirect
    /// entries, an unknown critical extension, a repeated serial) is
    /// ignored and counts as missing. Of several lists for one issuer, the
    /// one with the highest CRL Number is kept, or, when any lacks one, the
    /// latest `thisUpdate`. A list that is stale still revokes what it
    /// lists, and a missing or stale list fails no call:
    /// [`Verifier::revocation_valid_until`](crate::Verifier::revocation_valid_until)
    /// tells. To refresh, build a new verifier (docs/design/revocation.md).
    #[must_use]
    pub fn revocation_lists(mut self, lists: impl IntoIterator<Item = Vec<u8>>) -> Self {
        self.revocation_lists = lists.into_iter().collect();
        self
    }

    /// CA certificates that sign revocation lists, added to the built-in
    /// ones (Apple's WWDR G5 and G6 intermediates, and the configured
    /// roots), replacing any given before: a new Apple intermediate before a
    /// release knows it, or a test PKI. Each must be signed by a configured
    /// root, be a CA, allow `cRLSign` when it has a keyUsage, carry Apple's
    /// WWDR marker OID, and not be revoked; [`build`](ConfigBuilder::build)
    /// refuses it otherwise.
    #[must_use]
    pub fn revocation_issuers(mut self, issuers: impl IntoIterator<Item = TrustAnchor>) -> Self {
        self.revocation_issuers = issuers.into_iter().collect();
        self
    }

    /// Revocation keys to refuse, replacing any given before: each the
    /// issuer id of the certificate above the revoked one (64 hex digits:
    /// SHA-256 over that certificate's `subject` and
    /// `subjectPublicKeyInfo` as encoded) and the revoked certificate's
    /// serial in hex, either letter case, any digit count. At most 1,000.
    #[must_use]
    pub fn distrust<I, S>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = (S, S)>,
        S: Into<String>,
    {
        self.distrust = entries
            .into_iter()
            .map(|(issuer, serial)| (issuer.into(), serial.into()))
            .collect();
        self
    }

    /// Replaces the built-in revocation list with one in the format of
    /// `certs/revocations.json`, with the certificates of its issuers that
    /// are not roots. For tests only: no shipped build has it.
    #[cfg(feature = "test-seams")]
    #[doc(hidden)]
    #[must_use]
    pub fn built_in_revocations(mut self, json: &[u8], certificates: &[&[u8]]) -> Self {
        self.built_in = Some(BuiltIn::parse(json, certificates).map(Arc::new).ok_or(()));
        self
    }

    /// The clock, as a closure returning epoch milliseconds.
    #[must_use]
    pub fn clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = Some(Arc::new(clock));
        self
    }

    /// The configuration.
    ///
    /// # Errors
    /// [`ConfigError`] for an empty root set: a verifier with no roots would
    /// answer `UNTRUSTED_CHAIN` to everything, and nobody would notice until
    /// production. Also for a revocation setting that is refused, naming
    /// the first problem and its index (docs/design/revocation.md §4), and
    /// when the built-in revocation list does not load.
    pub fn build(self) -> Result<Config, ConfigError> {
        let roots: Arc<[TrustAnchor]> = match self.roots {
            Some(roots) => roots.into(),
            None => apple_roots().into(),
        };
        if roots.is_empty() {
            return Err(ConfigError::new("roots must not be empty"));
        }
        let built_in = match self.built_in {
            Some(injected) => injected.ok(),
            None => BuiltIn::compiled(),
        }
        .ok_or_else(|| ConfigError::new("the built-in revocation list did not load"))?;
        let settings = Settings {
            roots: &roots,
            lists: &self.revocation_lists,
            issuers: &self.revocation_issuers,
            distrust: &self.distrust,
        };
        let revocation = Revocation::build(&settings, built_in)?;
        Ok(Config {
            roots,
            revocation: Some(Arc::new(revocation)),
            clock: self.clock.unwrap_or_else(|| Arc::new(system_millis)),
        })
    }
}

impl fmt::Debug for ConfigBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigBuilder")
            .field("roots", &self.roots.as_ref().map(Vec::len))
            .field("revocation_lists", &self.revocation_lists.len())
            .field("revocation_issuers", &self.revocation_issuers.len())
            .field("distrust", &self.distrust.len())
            .field("built_in", &self.built_in.is_some())
            .field("clock", &self.clock.is_some())
            .finish()
    }
}

/// The system clock, as epoch milliseconds.
pub(crate) fn system_millis() -> i64 {
    crate::datetime::unix_millis_of(SystemTime::now())
}
