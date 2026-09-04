//! The four App Store environments, spelled as Apple's claims spell them.

use crate::error::ConfigError;
use core::fmt;

/// An App Store environment.
///
/// The spelling is Apple's: these are the exact strings that appear in a
/// transaction's `environment` claim and an `AppTransaction`'s
/// `receiptType` claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Environment {
    /// `Production`
    Production,
    /// `Sandbox`
    Sandbox,
    /// `Xcode` — `StoreKit` Testing in Xcode; not Apple-signed.
    Xcode,
    /// `LocalTesting` — `StoreKit` Test in a simulator.
    LocalTesting,
}

impl Environment {
    /// The claim spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Environment::Production => "Production",
            Environment::Sandbox => "Sandbox",
            Environment::Xcode => "Xcode",
            Environment::LocalTesting => "LocalTesting",
        }
    }

    /// Every environment.
    #[must_use]
    pub const fn all() -> &'static [Environment] {
        &[
            Environment::Production,
            Environment::Sandbox,
            Environment::Xcode,
            Environment::LocalTesting,
        ]
    }

    /// Parses a claim spelling, returning `None` for anything else.
    #[must_use]
    pub fn from_claim(claim: &str) -> Option<Environment> {
        for environment in Environment::all() {
            if environment.as_str() == claim {
                return Some(*environment);
            }
        }
        None
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::str::FromStr for Environment {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Environment::from_claim(s)
            .ok_or_else(|| ConfigError::new(format!("unknown environment: {s}")))
    }
}
