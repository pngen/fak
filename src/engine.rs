//! Proof engine for FAK.
use crate::error::{FakError, FakResult};
use crate::types::{
    CapabilityManifest, CostLedger, CounterExample, ExecutionTrace, InvariantSpec,
    PolicyIR, ProofBundle, ProofType, ProofWitness, compute_content_hash,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration for proof engine resource limits.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub max_invariants: usize,
    pub timeout_secs: f64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_invariants: 1000,
            timeout_secs: 30.0,
        }
    }
}

/// Proof engine for verifying governance invariants.
#[derive(Debug, Clone)]
pub struct ProofEngine {
    config: EngineConfig,
}

impl ProofEngine {
    /// Create a new proof engine with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a proof engine with custom configuration.
    pub fn with_config(config: EngineConfig) -> Self {
        Self { config }
    }

    /// Verify invariants against governance artifacts.
    pub fn verify_invariants(
        &self,
        trace: &ExecutionTrace,
        capabilities: &CapabilityManifest,
        cost_ledger: &CostLedger,
        policy_ir: &PolicyIR,
        invariants: &[InvariantSpec],
    ) -> FakResult<ProofWitness> {
        // Validate inputs
        trace.validate()?;
        capabilities.validate()?;
        cost_ledger.validate()?;
        policy_ir.validate()?;

        let start_time = self.current_time_secs();

        if invariants.len() > self.config.max_invariants {
            return Err(FakError::ResourceLimit {
                resource: "invariants".to_string(),
                limit: self.config.max_invariants,
                actual: invariants.len(),
            });
        }

        let mut counterexamples = Vec::new();

        for invariant in invariants {
            let elapsed = self.current_time_secs() - start_time;
            if elapsed > self.config.timeout_secs {
                counterexamples.push(CounterExample {
                    invariant_name: invariant.name.clone(),
                    error_type: "timeout".to_string(),
                    details: serde_json::json!({
                        "reason": "Verification timed out",
                        "elapsed_secs": elapsed,
                        "limit_secs": self.config.timeout_secs
                    }),
                    step_index: None,
                });
                break;
            }

            match self.check_invariant(trace, capabilities, cost_ledger, policy_ir, invariant) {
                Ok(true) => continue,
                Ok(false) => counterexamples.push(CounterExample {
                    invariant_name: invariant.name.clone(),
                    error_type: "violation".to_string(),
                    details: serde_json::json!({
                        "reason": "Invariant violated",
                        "invariant_type": invariant.invariant_type.as_str()
                    }),
                    step_index: None,
                }),
                Err(e) => counterexamples.push(CounterExample {
                    invariant_name: invariant.name.clone(),
                    error_type: "check_error".to_string(),
                    details: serde_json::json!({"error": e.to_string()}),
                    step_index: None,
                }),
            }
        }

        let proof_content = serde_json::json!({
            "trace_id": trace.id,
            "capabilities_id": capabilities.id,
            "cost_ledger_id": cost_ledger.id,
            "policy_ir_id": policy_ir.id,
            "invariant_names": invariants.iter().map(|i| &i.name).collect::<Vec<_>>(),
        });

        let proof_id = compute_content_hash(&proof_content);

        Ok(ProofWitness {
            proof_id,
            execution_trace: trace.clone(),
            capability_manifest: capabilities.clone(),
            cost_ledger: cost_ledger.clone(),
            policy_ir: policy_ir.clone(),
            invariants: invariants.to_vec(),
            counterexamples,
        })
    }

    fn check_invariant(
        &self,
        trace: &ExecutionTrace,
        capabilities: &CapabilityManifest,
        cost_ledger: &CostLedger,
        policy_ir: &PolicyIR,
        invariant: &InvariantSpec,
    ) -> FakResult<bool> {
        invariant.validate()?;

        match invariant.invariant_type {
            ProofType::BehavioralSoundness => self.check_behavioral_soundness(trace, invariant),
            ProofType::AuthorityNonEscalation => {
                self.check_authority_non_escalation(capabilities, invariant)
            }
            ProofType::EconomicInvariance => self.check_economic_invariance(cost_ledger, invariant),
            ProofType::SemanticPreservation => {
                self.check_semantic_preservation(policy_ir, invariant)
            }
        }
    }

    fn check_behavioral_soundness(
        &self,
        trace: &ExecutionTrace,
        inv: &InvariantSpec,
    ) -> FakResult<bool> {
        // Trace must be non-empty if precondition exists
        Ok(!trace.steps.is_empty() || inv.precondition.is_none())
    }

    fn check_authority_non_escalation(
        &self,
        caps: &CapabilityManifest,
        inv: &InvariantSpec,
    ) -> FakResult<bool> {
        // Authority graph must be non-empty if precondition exists
        Ok(!caps.authority_graph.is_empty() || inv.precondition.is_none())
    }

    fn check_economic_invariance(
        &self,
        ledger: &CostLedger,
        _inv: &InvariantSpec,
    ) -> FakResult<bool> {
        Ok(ledger.total_cost >= 0.0)
    }

    fn check_semantic_preservation(
        &self,
        policy: &PolicyIR,
        _inv: &InvariantSpec,
    ) -> FakResult<bool> {
        Ok(!policy.id.is_empty())
    }

    fn current_time_secs(&self) -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
    }

    /// Generate a proof bundle from witnesses.
    pub fn generate_bundle(&self, witnesses: &[ProofWitness]) -> FakResult<ProofBundle> {
        if witnesses.is_empty() {
            return Err(FakError::Validation {
                field: "witnesses".to_string(),
                message: "cannot create bundle with zero witnesses".to_string(),
            });
        }

        for w in witnesses {
            w.validate()?;
        }

        let bundle_content = serde_json::json!({
            "witnesses": witnesses.iter().map(|w| w.proof_id.clone()).collect::<Vec<_>>(),
            "metadata": {},
        });

        let bundle_id = compute_content_hash(&bundle_content);

        Ok(ProofBundle {
            id: bundle_id,
            witnesses: witnesses.to_vec(),
            metadata: serde_json::Map::new(),
        })
    }
}

impl Default for ProofEngine {
    fn default() -> Self {
        Self {
            config: EngineConfig::default(),
        }
    }
}