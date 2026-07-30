//! Artifact management for FAK.

use crate::engine::ProofEngine;
use crate::error::{FakError, FakResult};
use crate::types::{
    compute_content_hash, CapabilityManifest, CostLedger, ExecutionTrace, InvariantSpec, PolicyIR,
    ProofBundle,
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Thread-safe artifact manager with content-addressable storage.
#[derive(Debug)]
pub struct ArtifactManager {
    artifacts: Arc<RwLock<HashMap<String, serde_json::Value>>>,
}

impl ArtifactManager {
    /// Create a new artifact manager.
    pub fn new() -> Self {
        Self {
            artifacts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Store an artifact and return its content-addressable ID.
    pub fn store_artifact(&self, artifact: &serde_json::Value) -> FakResult<String> {
        let artifact_id = compute_content_hash(artifact);
        let mut artifacts = self.artifacts.write().map_err(|_| FakError::LockPoisoned {
            resource: "artifacts".to_string(),
        })?;
        artifacts.insert(artifact_id.clone(), artifact.clone());
        Ok(artifact_id)
    }

    /// Retrieve an artifact by its ID.
    pub fn retrieve_artifact(&self, artifact_id: &str) -> FakResult<serde_json::Value> {
        let artifacts = self.artifacts.read().map_err(|_| FakError::LockPoisoned {
            resource: "artifacts".to_string(),
        })?;
        match artifacts.get(artifact_id) {
            Some(value) => Ok(value.clone()),
            None => Err(FakError::ArtifactNotFound {
                artifact_id: artifact_id.to_string(),
            }),
        }
    }

    /// Check if an artifact exists.
    pub fn contains(&self, artifact_id: &str) -> FakResult<bool> {
        let artifacts = self.artifacts.read().map_err(|_| FakError::LockPoisoned {
            resource: "artifacts".to_string(),
        })?;
        Ok(artifacts.contains_key(artifact_id))
    }

    /// Validate artifact integrity by recomputing hash.
    pub fn validate_artifact_integrity(
        &self,
        artifact_id: &str,
        artifact: &serde_json::Value,
    ) -> bool {
        let computed_id = compute_content_hash(artifact);
        computed_id == artifact_id
    }

    /// Create a proof bundle from governance artifacts.
    pub fn create_bundle(
        &self,
        _trace: &ExecutionTrace,
        _capabilities: &CapabilityManifest,
        _cost_ledger: &CostLedger,
        _policy_ir: &PolicyIR,
    ) -> FakResult<ProofBundle> {
        Err(FakError::Validation {
            field: "invariants".to_string(),
            message: "at least one invariant is required; use create_bundle_with_invariants"
                .to_string(),
        })
    }

    /// Create a proof bundle from governance artifacts and explicit invariants.
    ///
    /// Verification and bundle construction complete before artifacts are stored,
    /// so a failed proof cannot leave partially persisted inputs behind.
    pub fn create_bundle_with_invariants(
        &self,
        trace: &ExecutionTrace,
        capabilities: &CapabilityManifest,
        cost_ledger: &CostLedger,
        policy_ir: &PolicyIR,
        invariants: &[InvariantSpec],
    ) -> FakResult<ProofBundle> {
        if invariants.is_empty() {
            return Err(FakError::Validation {
                field: "invariants".to_string(),
                message: "at least one invariant is required".to_string(),
            });
        }

        // Verify and construct the complete bundle before mutating storage.
        let engine = ProofEngine::new();
        let witness =
            engine.verify_invariants(trace, capabilities, cost_ledger, policy_ir, invariants)?;
        let bundle = engine.generate_bundle(&[witness])?;

        // Serialize artifacts
        let trace_json = serde_json::to_value(trace)?;
        let cap_json = serde_json::to_value(capabilities)?;
        let cost_json = serde_json::to_value(cost_ledger)?;
        let policy_json = serde_json::to_value(policy_ir)?;

        // Compute and verify every content address before mutating storage.
        let trace_id = compute_content_hash(&trace_json);
        let cap_id = compute_content_hash(&cap_json);
        let cost_id = compute_content_hash(&cost_json);
        let policy_id = compute_content_hash(&policy_json);

        self.verify_integrity(&trace_id, &trace_json, "trace")?;
        self.verify_integrity(&cap_id, &cap_json, "capability_manifest")?;
        self.verify_integrity(&cost_id, &cost_json, "cost_ledger")?;
        self.verify_integrity(&policy_id, &policy_json, "policy_ir")?;

        // Store the verified artifacts atomically under a single write lock.
        let mut artifacts = self.artifacts.write().map_err(|_| FakError::LockPoisoned {
            resource: "artifacts".to_string(),
        })?;
        artifacts.insert(trace_id, trace_json);
        artifacts.insert(cap_id, cap_json);
        artifacts.insert(cost_id, cost_json);
        artifacts.insert(policy_id, policy_json);

        Ok(bundle)
    }

    fn verify_integrity(
        &self,
        artifact_id: &str,
        artifact: &serde_json::Value,
        _name: &str,
    ) -> FakResult<()> {
        if !self.validate_artifact_integrity(artifact_id, artifact) {
            return Err(FakError::IntegrityFailure {
                artifact_id: artifact_id.to_string(),
                expected: artifact_id.to_string(),
                actual: compute_content_hash(artifact),
            });
        }
        Ok(())
    }

    /// Clear all stored artifacts.
    pub fn clear(&self) -> FakResult<()> {
        let mut artifacts = self.artifacts.write().map_err(|_| FakError::LockPoisoned {
            resource: "artifacts".to_string(),
        })?;
        artifacts.clear();
        Ok(())
    }
}

impl Default for ArtifactManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ArtifactManager {
    fn clone(&self) -> Self {
        let artifacts = self.artifacts.read().expect("lock not poisoned");
        Self {
            artifacts: Arc::new(RwLock::new(artifacts.clone())),
        }
    }
}
