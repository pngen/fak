//! FAK - Formal Assurance Kernel
//!
//! Core modules for formal verification of governance stack components.

pub mod error;
pub mod artifacts;
pub mod dsl;
pub mod engine;
pub mod types;
pub mod verifier;

pub use error::{FakError, FakResult};
pub use artifacts::ArtifactManager;
pub use dsl::InvariantDSL;
pub use engine::ProofEngine;
pub use types::{
    CapabilityManifest, CostLedger, CounterExample, ExecutionTrace, 
    InvariantSpec, PolicyIR, ProofBundle, ProofType, ProofWitness, 
    compute_content_hash, VerificationContext,
};
pub use verifier::Verifier;