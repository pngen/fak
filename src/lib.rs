//! FAK - Formal Assurance Kernel
//!
//! Core modules for formal verification of governance stack components.

pub mod artifacts;
pub mod dsl;
pub mod engine;
pub mod error;
pub mod types;
pub mod verifier;

pub use artifacts::ArtifactManager;
pub use dsl::InvariantDSL;
pub use engine::ProofEngine;
pub use error::{FakError, FakResult};
pub use types::{
    compute_content_hash, CapabilityManifest, CostLedger, CounterExample, ExecutionTrace,
    InvariantSpec, PolicyIR, ProofBundle, ProofType, ProofWitness, VerificationContext,
};
pub use verifier::Verifier;
