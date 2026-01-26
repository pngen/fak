//! Error types for FAK.

use std::fmt;

/// Unified error type for all FAK operations.
#[derive(Debug, Clone)]
pub enum FakError {
    /// Validation error with field context
    Validation { field: String, message: String },
    /// Artifact not found
    ArtifactNotFound { artifact_id: String },
    /// Artifact integrity check failed
    IntegrityFailure { artifact_id: String, expected: String, actual: String },
    /// Invariant parsing error
    ParseError { source: String, message: String },
    /// Invariant verification failed
    VerificationFailure { invariant: String, reason: String },
    /// Resource limit exceeded
    ResourceLimit { resource: String, limit: usize, actual: usize },
    /// Timeout during verification
    Timeout { operation: String, limit_secs: f64 },
    /// Serialization error
    Serialization { message: String },
    /// Unknown proof type
    UnknownProofType { value: String },
    /// Bundle verification failed
    BundleVerificationFailed { bundle_id: String, reason: String },
    /// Lock acquisition failed (thread safety)
    LockPoisoned { resource: String },
}

impl fmt::Display for FakError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation { field, message } => {
                write!(f, "validation error on '{}': {}", field, message)
            }
            Self::ArtifactNotFound { artifact_id } => {
                write!(f, "artifact '{}' not found", artifact_id)
            }
            Self::IntegrityFailure { artifact_id, expected, actual } => {
                write!(f, "integrity check failed for '{}': expected '{}', got '{}'", 
                       artifact_id, expected, actual)
            }
            Self::ParseError { source, message } => {
                write!(f, "parse error in '{}': {}", source, message)
            }
            Self::VerificationFailure { invariant, reason } => {
                write!(f, "verification failed for '{}': {}", invariant, reason)
            }
            Self::ResourceLimit { resource, limit, actual } => {
                write!(f, "{} limit exceeded: {} > {}", resource, actual, limit)
            }
            Self::Timeout { operation, limit_secs } => {
                write!(f, "{} timed out after {}s", operation, limit_secs)
            }
            Self::Serialization { message } => {
                write!(f, "serialization error: {}", message)
            }
            Self::UnknownProofType { value } => {
                write!(f, "unknown proof type: '{}'", value)
            }
            Self::BundleVerificationFailed { bundle_id, reason } => {
                write!(f, "bundle '{}' verification failed: {}", bundle_id, reason)
            }
            Self::LockPoisoned { resource } => {
                write!(f, "lock poisoned for resource: {}", resource)
            }
        }
    }
}

impl std::error::Error for FakError {}

/// Result type alias for FAK operations.
pub type FakResult<T> = Result<T, FakError>;

impl From<serde_json::Error> for FakError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization { message: e.to_string() }
    }
}

impl<T> From<std::sync::PoisonError<T>> for FakError {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        Self::LockPoisoned { resource: "mutex".to_string() }
    }
}