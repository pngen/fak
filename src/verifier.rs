//! Standalone verifier for FAK proof bundles.

use crate::engine::{EngineConfig, ProofEngine, PROOF_ALGORITHM_VERSION};
use crate::error::FakError;
use crate::types::{compute_content_hash, CounterExample, ProofBundle, ProofWitness};
use serde::{Deserialize, Serialize};

const PROOF_ALGORITHM: &str = "fak-invariant-replay";
const PROOF_VERSION: &str = PROOF_ALGORITHM_VERSION;

/// Verification result for a single witness.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WitnessResult {
    pub proof_id: String,
    pub success: bool,
    pub invariant_count: usize,
    pub counterexample_count: usize,
    #[serde(default)]
    pub counterexamples: Vec<CounterExample>,
    pub error: Option<String>,
    #[serde(default)]
    pub proof_algorithm: String,
    #[serde(default)]
    pub proof_version: String,
    #[serde(default)]
    pub engine_max_invariants: usize,
    #[serde(default)]
    pub engine_timeout_secs: f64,
}

/// Verification result for an entire bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BundleResult {
    pub bundle_id: String,
    pub success: bool,
    pub witness_results: Vec<WitnessResult>,
    pub error: Option<String>,
    #[serde(default)]
    pub proof_algorithm: String,
    #[serde(default)]
    pub proof_version: String,
    #[serde(default)]
    pub engine_max_invariants: usize,
    #[serde(default)]
    pub engine_timeout_secs: f64,
}

/// Standalone verifier for proof bundles.
#[derive(Debug, Clone)]
pub struct Verifier {
    engine: ProofEngine,
    config: EngineConfig,
}

impl Verifier {
    /// Create a new verifier with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a verifier with custom engine configuration.
    pub fn with_config(config: EngineConfig) -> Self {
        let engine = ProofEngine::with_config(config.clone());
        Self { engine, config }
    }

    fn bundle_result(
        &self,
        bundle_id: String,
        success: bool,
        witness_results: Vec<WitnessResult>,
        error: Option<String>,
    ) -> BundleResult {
        BundleResult {
            bundle_id,
            success,
            witness_results,
            error,
            proof_algorithm: PROOF_ALGORITHM.to_string(),
            proof_version: PROOF_VERSION.to_string(),
            engine_max_invariants: self.config.max_invariants,
            engine_timeout_secs: self.config.timeout_secs,
        }
    }

    fn witness_result(
        &self,
        proof_id: String,
        success: bool,
        invariant_count: usize,
        counterexamples: Vec<CounterExample>,
        error: Option<String>,
    ) -> WitnessResult {
        WitnessResult {
            proof_id,
            success,
            invariant_count,
            counterexample_count: counterexamples.len(),
            counterexamples,
            error,
            proof_algorithm: PROOF_ALGORITHM.to_string(),
            proof_version: PROOF_VERSION.to_string(),
            engine_max_invariants: self.config.max_invariants,
            engine_timeout_secs: self.config.timeout_secs,
        }
    }

    /// Verify a proof bundle, returning structured results.
    pub fn verify_bundle(&self, bundle: &ProofBundle) -> BundleResult {
        // Validate bundle structure
        if let Err(e) = bundle.validate() {
            return self.bundle_result(bundle.id.clone(), false, Vec::new(), Some(e.to_string()));
        }

        if bundle.witnesses.is_empty() {
            let error = FakError::Validation {
                field: "witnesses".to_string(),
                message: "ProofBundle must contain at least one witness".to_string(),
            };
            return self.bundle_result(
                bundle.id.clone(),
                false,
                Vec::new(),
                Some(error.to_string()),
            );
        }

        // Verify bundle ID integrity
        let expected_id = self.compute_bundle_id(bundle);
        if expected_id != bundle.id {
            return self.bundle_result(
                bundle.id.clone(),
                false,
                Vec::new(),
                Some(format!(
                    "Bundle ID mismatch: expected '{}', got '{}'",
                    expected_id, bundle.id
                )),
            );
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

        self.bundle_result(bundle.id.clone(), overall_success, witness_results, None)
    }

    fn verify_witness(&self, witness: &ProofWitness) -> WitnessResult {
        if let Err(e) = witness.validate() {
            return self.witness_result(
                witness.proof_id.clone(),
                false,
                witness.invariants.len(),
                Vec::new(),
                Some(e.to_string()),
            );
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
                    return self.witness_result(
                        witness.proof_id.clone(),
                        false,
                        witness.invariants.len(),
                        reverified.counterexamples,
                        Some(format!(
                            "Proof ID mismatch: expected '{}', got '{}'",
                            witness.proof_id, reverified.proof_id
                        )),
                    );
                }

                if reverified.counterexamples != witness.counterexamples {
                    return self.witness_result(
                        witness.proof_id.clone(),
                        false,
                        witness.invariants.len(),
                        reverified.counterexamples,
                        Some(
                            "Stored counterexamples do not match replayed counterexamples"
                                .to_string(),
                        ),
                    );
                }

                let success = reverified.counterexamples.is_empty();
                self.witness_result(
                    witness.proof_id.clone(),
                    success,
                    witness.invariants.len(),
                    reverified.counterexamples,
                    None,
                )
            }
            Err(e) => self.witness_result(
                witness.proof_id.clone(),
                false,
                witness.invariants.len(),
                Vec::new(),
                Some(e.to_string()),
            ),
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
        Self::with_config(EngineConfig::default())
    }
}
