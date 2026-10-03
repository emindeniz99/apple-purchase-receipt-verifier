//! Apple's two environments, and the mapping from the strings Apple uses
//! for them. The mapping is the core's: a verified result states its
//! environment ([`ReceiptPayload::environment`](crate::ReceiptPayload::environment),
//! [`JsonPayload::environment`](crate::JsonPayload::environment)), and no
//! binding repeats the rule (DECISIONS.md R42).

use core::fmt;

/// Which of Apple's two `verifyReceipt` URLs a call imitates, and which
/// environment a verified receipt or JWS names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Environment {
    /// `Production`
    Production,
    /// `Sandbox`
    Sandbox,
}

impl Environment {
    /// Apple's spelling, as the endpoint response writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Environment::Production => "Production",
            Environment::Sandbox => "Sandbox",
        }
    }

    /// What a receipt's `receipt_type` means: `Production` and
    /// `ProductionVPP` are [`Environment::Production`],
    /// `ProductionSandbox` and `ProductionVPPSandbox` are
    /// [`Environment::Sandbox`], anything else (`Xcode`, a missing value) is
    /// `None`. It states what Apple's value means and decides nothing; the
    /// endpoint routes 21007 and 21008 on the same rule.
    #[must_use]
    pub(crate) fn from_receipt_type(receipt_type: Option<&str>) -> Option<Environment> {
        match receipt_type? {
            "Production" | "ProductionVPP" => Some(Environment::Production),
            "ProductionSandbox" | "ProductionVPPSandbox" => Some(Environment::Sandbox),
            _ => None,
        }
    }

    /// What a JWS `environment` claim means: `Production` and `Sandbox`,
    /// anything else (`Xcode`, `LocalTesting`, a missing value) `None`.
    #[must_use]
    pub(crate) fn from_jws_environment(environment: Option<&str>) -> Option<Environment> {
        match environment? {
            "Production" => Some(Environment::Production),
            "Sandbox" => Some(Environment::Sandbox),
            _ => None,
        }
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
