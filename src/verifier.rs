//! Standalone verifier for FAK proof bundles.

use crate::engine::{EngineConfig, ProofEngine};
use crate::error::FakResult;
use crate::types::{compute_content_hash, ProofBundle, ProofWitness};
use serde::{Deserialize, Serialize};

/// Verification result for a single witness.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WitnessResult {
    pub proof_id: String,
    pub success: bool,
    pub invariant_count: usize,
    pub counterexample_count: usize,
    pub error: Option<String>,
}

/// Verification result for an entire bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BundleResult {
    pub bundle_id: String,
    pub success: bool,
    pub witness_results: Vec<WitnessResult>,
    pub error: Option<String>,
}

/// Standalone verifier for proof bundles.
#[derive(Debug, Clone)]
pub struct Verifier {
    engine: ProofEngine,
}

impl Verifier {
    /// Create a new verifier with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a verifier with custom engine configuration.
    pub fn with_config(config: EngineConfig) -> Self {
        Self {
            engine: ProofEngine::with_config(config),
        }
    }

    /// Verify a proof bundle, returning structured results.
    pub fn verify_bundle(&self, bundle: &ProofBundle) -> BundleResult {
        // Validate bundle structure
        if let Err(e) = bundle.validate() {
            return BundleResult {
                bundle_id: bundle.id.clone(),
                success: false,
                witness_results: Vec::new(),
                error: Some(e.to_string()),
            };
        }

        // Verify bundle ID integrity
        let expected_id = self.compute_bundle_id(bundle);
        if expected_id != bundle.id {
            return BundleResult {
                bundle_id: bundle.id.clone(),
                success: false,
                witness_results: Vec::new(),
                error: Some(format!(
                    "Bundle ID mismatch: expected '{}', got '{}'",
                    expected_id, bundle.id
                )),
            };
        }

        // Verify each witness
        let mut witness_results = Vec::new();
        let mut overall_success = true;

        for witness in &bundle.witnesses {
            let result = self.verify_witness(witness);
            if !result.success {
                overall_success = false;
            }
            witness_results.push(result);
        }

        BundleResult {
            bundle_id: bundle.id.clone(),
            success: overall_success,
            witness_results,
            error: None,
        }
    }

    fn verify_witness(&self, witness: &ProofWitness) -> WitnessResult {
        if let Err(e) = witness.validate() {
            return WitnessResult {
                proof_id: witness.proof_id.clone(),
                success: false,
                invariant_count: witness.invariants.len(),
                counterexample_count: 0,
                error: Some(e.to_string()),
            };
        }

        match self.engine.verify_invariants(
            &witness.execution_trace,
            &witness.capability_manifest,
            &witness.cost_ledger,
            &witness.policy_ir,
            &witness.invariants,
        ) {
            Ok(reverified) => {
                if reverified.proof_id != witness.proof_id {
                    return WitnessResult {
                        proof_id: witness.proof_id.clone(),
                        success: false,
                        invariant_count: witness.invariants.len(),
                        counterexample_count: reverified.counterexamples.len(),
                        error: Some(format!(
                            "Proof ID mismatch: expected '{}', got '{}'",
                            witness.proof_id, reverified.proof_id
                        )),
                    };
                }

                WitnessResult {
                    proof_id: witness.proof_id.clone(),
                    success: reverified.counterexamples.is_empty(),
                    invariant_count: witness.invariants.len(),
                    counterexample_count: reverified.counterexamples.len(),
                    error: None,
                }
            }
            Err(e) => WitnessResult {
                proof_id: witness.proof_id.clone(),
                success: false,
                invariant_count: witness.invariants.len(),
                counterexample_count: 0,
                error: Some(e.to_string()),
            },
        }
    }

    fn compute_bundle_id(&self, bundle: &ProofBundle) -> String {
        let content = serde_json::json!({
            "witnesses": bundle.witnesses.iter().map(|w| w.proof_id.clone()).collect::<Vec<_>>(),
            "metadata": bundle.metadata.clone(),
        });
        compute_content_hash(&content)
    }

    /// Verify bundle and return JSON result (legacy API compatibility).
    pub fn verify_bundle_json(&self, bundle: &ProofBundle) -> serde_json::Value {
        let result = self.verify_bundle(bundle);
        serde_json::to_value(&result).unwrap_or_else(|_| {
            serde_json::json!({
                "bundle_id": bundle.id,
                "success": false,
                "error": "Failed to serialize verification result"
            })
        })
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self {
            engine: ProofEngine::new(),
        }
    }
}