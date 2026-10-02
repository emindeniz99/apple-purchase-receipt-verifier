//! What a [`Verifier`](crate::Verifier) is built from: the pinned roots and
//! the clock.

use crate::error::ConfigError;
use crate::roots::{apple_roots, TrustAnchor};
use core::fmt;
use std::sync::Arc;
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
    pub fn clock(&self) -> &(dyn Fn() -> i64 + Send + Sync) {
        &*self.clock
    }

    pub(crate) fn into_parts(self) -> (Arc<[TrustAnchor]>, Arc<ClockFn>) {
        (self.roots, self.clock)
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("roots", &self.roots.len())
            .finish_non_exhaustive()
    }
}

/// Apple's three pinned roots and the system clock.
///
/// The bundled roots load all together or not at all, each checked
/// against its published SHA-256. Should they not load, this cannot say
/// so: a [`Verifier`](crate::Verifier) built from it then answers
/// `INTERNAL_ERROR` to every call, where [`ConfigBuilder::build`] returns
/// a [`ConfigError`].
impl Default for Config {
    fn default() -> Self {
        Config {
            roots: apple_roots().into(),
            clock: Arc::new(system_millis),
        }
    }
}

/// Builds a [`Config`].
#[derive(Default)]
pub struct ConfigBuilder {
    roots: Option<Vec<TrustAnchor>>,
    clock: Option<Arc<ClockFn>>,
}

impl ConfigBuilder {
    /// The roots a chain must reach, replacing Apple's bundled ones. Tests
    /// use their own.
    #[must_use]
    pub fn roots(mut self, roots: impl IntoIterator<Item = TrustAnchor>) -> Self {
        self.roots = Some(roots.into_iter().collect());
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
    /// production.
    pub fn build(self) -> Result<Config, ConfigError> {
        let roots: Arc<[TrustAnchor]> = match self.roots {
            Some(roots) => roots.into(),
            None => apple_roots().into(),
        };
        if roots.is_empty() {
            return Err(ConfigError::new("roots must not be empty"));
        }
        Ok(Config {
            roots,
            clock: self.clock.unwrap_or_else(|| Arc::new(system_millis)),
        })
    }
}

impl fmt::Debug for ConfigBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigBuilder")
            .field("roots", &self.roots.as_ref().map(Vec::len))
            .field("clock", &self.clock.is_some())
            .finish()
    }
}

/// The system clock, as epoch milliseconds.
pub(crate) fn system_millis() -> i64 {
    crate::datetime::unix_millis_of(SystemTime::now())
}
