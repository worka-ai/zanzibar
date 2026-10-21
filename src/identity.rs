use serde::{Deserialize, Serialize};

/// A Keldra authorization object identity, preserving its wire identity kind.
/// An exact path is not an encoded opaque ID. Tenant and bucket are explicit,
/// even when the surrounding authorization scope uses the same tenant.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum ObjectId {
    Opaque(String),
    ExactPath {
        tenant: String,
        bucket: String,
        path: String,
    },
}

impl std::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Opaque(id) => f.write_str(id),
            // Diagnostic only: this display is never used as a wire identity.
            Self::ExactPath {
                tenant,
                bucket,
                path,
            } => {
                write!(f, "exact-path({tenant:?}, {bucket:?}, {path:?})")
            }
        }
    }
}

impl From<String> for ObjectId {
    fn from(value: String) -> Self {
        Self::Opaque(value)
    }
}

impl From<&str> for ObjectId {
    fn from(value: &str) -> Self {
        Self::Opaque(value.into())
    }
}
