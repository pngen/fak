//! Core data types for FAK.

use crate::error::{FakError, FakResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Execution trace capturing a sequence of governance operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionTrace {
    pub id: String,
    pub steps: Vec<serde_json::Value>,
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

impl ExecutionTrace {
    /// Maximum allowed trace steps to prevent resource exhaustion.
    pub const MAX_STEPS: usize = 100_000;

    pub fn new(
        id: String,
        steps: Vec<serde_json::Value>,
        metadata: serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        Self { id, steps, metadata }
    }

    pub fn validate(&self) -> FakResult<()> {
        if self.id.is_empty() {
            return Err(FakError::Validation {
                field: "id".to_string(),
                message: "ExecutionTrace must have a non-empty ID".to_string(),
            });
        }
        if self.steps.len() > Self::MAX_STEPS {
            return Err(FakError::ResourceLimit {
                resource: "trace_steps".to_string(),
                limit: Self::MAX_STEPS,
                actual: self.steps.len(),
            });
        }
        Ok(())
    }
}

impl Default for ExecutionTrace {
    fn default() -> Self {
        Self {
            id: String::new(),
            steps: Vec::new(),
            metadata: serde_json::Map::new(),
        }
    }
}

/// Capability manifest defining agent permissions and authority relationships.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityManifest {
    pub id: String,
    pub agent_id: String,
    pub capabilities: Vec<String>,
    pub authority_graph: HashMap<String, Vec<String>>,
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

impl CapabilityManifest {
    pub fn new(
        id: String,
        agent_id: String,
        capabilities: Vec<String>,
        authority_graph: HashMap<String, Vec<String>>,
        metadata: serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        Self {
            id,
            agent_id,
            capabilities,
            authority_graph,
            metadata,
        }
    }

    pub fn validate(&self) -> FakResult<()> {
        if self.id.is_empty() {
            return Err(FakError::Validation {
                field: "id".to_string(),
                message: "CapabilityManifest must have a non-empty ID".to_string(),
            });
        }
        if self.agent_id.is_empty() {
            return Err(FakError::Validation {
                field: "agent_id".to_string(),
                message: "CapabilityManifest must have a non-empty agent_id".to_string(),
            });
        }
        Ok(())
    }
}

impl Default for CapabilityManifest {
    fn default() -> Self {
        Self {
            id: String::new(),
            agent_id: String::new(),
            capabilities: Vec::new(),
            authority_graph: HashMap::new(),
            metadata: serde_json::Map::new(),
        }
    }
}

/// Cost ledger tracking economic attribution for inference operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CostLedger {
    pub id: String,
    pub entries: Vec<serde_json::Value>,
    pub total_cost: f64,
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

impl CostLedger {
    pub fn new(
        id: String,
        entries: Vec<serde_json::Value>,
        total_cost: f64,
        metadata: serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        Self {
            id,
            entries,
            total_cost,
            metadata,
        }
    }

    pub fn validate(&self) -> FakResult<()> {
        if self.id.is_empty() {
            return Err(FakError::Validation {
                field: "id".to_string(),
                message: "CostLedger must have a non-empty ID".to_string(),
            });
        }
        if self.total_cost < 0.0 {
            return Err(FakError::Validation {
                field: "total_cost".to_string(),
                message: "CostLedger total_cost cannot be negative".to_string(),
            });
        }
        if self.total_cost.is_nan() || self.total_cost.is_infinite() {
            return Err(FakError::Validation {
                field: "total_cost".to_string(),
                message: "CostLedger total_cost must be finite".to_string(),
            });
        }
        Ok(())
    }
}

impl Default for CostLedger {
    fn default() -> Self {
        Self {
            id: String::new(),
            entries: Vec::new(),
            total_cost: 0.0,
            metadata: serde_json::Map::new(),
        }
    }
}

/// Policy intermediate representation for compiled governance rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyIR {
    pub id: String,
    pub ast: serde_json::Map<String, serde_json::Value>,
    pub compiled_enforcement: Vec<u8>,
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

impl PolicyIR {
    pub fn new(
        id: String,
        ast: serde_json::Map<String, serde_json::Value>,
        compiled_enforcement: Vec<u8>,
        metadata: serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        Self {
            id,
            ast,
            compiled_enforcement,
            metadata,
        }
    }

    pub fn validate(&self) -> FakResult<()> {
        if self.id.is_empty() {
            return Err(FakError::Validation {
                field: "id".to_string(),
                message: "PolicyIR must have a non-empty ID".to_string(),
            });
        }
        Ok(())
    }
}

impl Default for PolicyIR {
    fn default() -> Self {
        Self {
            id: String::new(),
            ast: serde_json::Map::new(),
            compiled_enforcement: Vec::new(),
            metadata: serde_json::Map::new(),
        }
    }
}

/// Specification for an invariant to be verified.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InvariantSpec {
    pub name: String,
    pub description: String,
    pub precondition: Option<String>,
    pub postcondition: Option<String>,
    pub temporal_properties: Vec<String>,
    pub invariant_type: ProofType,
}

impl InvariantSpec {
    pub fn new(
        name: String,
        description: String,
        precondition: Option<String>,
        postcondition: Option<String>,
        temporal_properties: Vec<String>,
        invariant_type: ProofType,
    ) -> Self {
        Self {
            name,
            description,
            precondition,
            postcondition,
            temporal_properties,
            invariant_type,
        }
    }

    pub fn validate(&self) -> FakResult<()> {
        if self.name.is_empty() {
            return Err(FakError::Validation {
                field: "name".to_string(),
                message: "InvariantSpec must have a non-empty name".to_string(),
            });
        }
        Ok(())
    }
}

impl Default for InvariantSpec {
    fn default() -> Self {
        Self {
            name: String::new(),
            description: String::new(),
            precondition: None,
            postcondition: None,
            temporal_properties: Vec::new(),
            invariant_type: ProofType::BehavioralSoundness,
        }
    }
}

/// Counter-example generated when an invariant is violated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CounterExample {
    pub invariant_name: String,
    pub error_type: String,
    pub details: serde_json::Value,
    pub step_index: Option<usize>,
}

/// Witness containing proof artifacts and verification results.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProofWitness {
    pub proof_id: String,
    pub execution_trace: ExecutionTrace,
    pub capability_manifest: CapabilityManifest,
    pub cost_ledger: CostLedger,
    pub policy_ir: PolicyIR,
    pub invariants: Vec<InvariantSpec>,
    pub counterexamples: Vec<CounterExample>,
}

impl ProofWitness {
    pub fn new(
        proof_id: String,
        execution_trace: ExecutionTrace,
        capability_manifest: CapabilityManifest,
        cost_ledger: CostLedger,
        policy_ir: PolicyIR,
        invariants: Vec<InvariantSpec>,
        counterexamples: Vec<CounterExample>,
    ) -> Self {
        Self {
            proof_id,
            execution_trace,
            capability_manifest,
            cost_ledger,
            policy_ir,
            invariants,
            counterexamples,
        }
    }

    pub fn validate(&self) -> FakResult<()> {
        if self.proof_id.is_empty() {
            return Err(FakError::Validation {
                field: "proof_id".to_string(),
                message: "ProofWitness must have a non-empty proof ID".to_string(),
            });
        }
        self.execution_trace.validate()?;
        self.capability_manifest.validate()?;
        self.cost_ledger.validate()?;
        self.policy_ir.validate()?;
        Ok(())
    }
}

impl Default for ProofWitness {
    fn default() -> Self {
        Self {
            proof_id: String::new(),
            execution_trace: ExecutionTrace::default(),
            capability_manifest: CapabilityManifest::default(),
            cost_ledger: CostLedger::default(),
            policy_ir: PolicyIR::default(),
            invariants: Vec::new(),
            counterexamples: Vec::new(),
        }
    }
}

/// Bundle containing multiple proof witnesses for batch verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProofBundle {
    pub id: String,
    pub witnesses: Vec<ProofWitness>,
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

impl ProofBundle {
    /// Maximum allowed witnesses per bundle to prevent resource exhaustion.
    pub const MAX_WITNESSES: usize = 100;

    pub fn new(
        id: String,
        witnesses: Vec<ProofWitness>,
        metadata: serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        Self { id, witnesses, metadata }
    }

    pub fn validate(&self) -> FakResult<()> {
        if self.id.is_empty() {
            return Err(FakError::Validation {
                field: "id".to_string(),
                message: "ProofBundle must have a non-empty ID".to_string(),
            });
        }
        if self.witnesses.len() > Self::MAX_WITNESSES {
            return Err(FakError::ResourceLimit {
                resource: "bundle_witnesses".to_string(),
                limit: Self::MAX_WITNESSES,
                actual: self.witnesses.len(),
            });
        }
        for witness in &self.witnesses {
            witness.validate()?;
        }
        Ok(())
    }
}

impl Default for ProofBundle {
    fn default() -> Self {
        Self {
            id: String::new(),
            witnesses: Vec::new(),
            metadata: serde_json::Map::new(),
        }
    }
}

/// Type of formal proof being verified.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProofType {
    BehavioralSoundness,
    AuthorityNonEscalation,
    EconomicInvariance,
    SemanticPreservation,
}

impl ProofType {
    /// Parse a proof type from string, returning an error for unknown values.
    pub fn from_str(s: &str) -> FakResult<Self> {
        match s.trim().to_lowercase().as_str() {
            "behavioral_soundness" | "behavioralsoundness" => Ok(Self::BehavioralSoundness),
            "authority_non_escalation" | "authoritynonescalation" => Ok(Self::AuthorityNonEscalation),
            "economic_invariance" | "economicinvariance" => Ok(Self::EconomicInvariance),
            "semantic_preservation" | "semanticpreservation" => Ok(Self::SemanticPreservation),
            _ => Err(FakError::UnknownProofType { value: s.to_string() }),
        }
    }

    /// Convert proof type to canonical string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BehavioralSoundness => "behavioral_soundness",
            Self::AuthorityNonEscalation => "authority_non_escalation",
            Self::EconomicInvariance => "economic_invariance",
            Self::SemanticPreservation => "semantic_preservation",
        }
    }
}

impl Default for ProofType {
    fn default() -> Self {
        Self::BehavioralSoundness
    }
}

impl From<ProofType> for String {
    fn from(pt: ProofType) -> Self {
        pt.as_str().to_string()
    }
}

impl std::fmt::Display for ProofType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ProofType {
    type Err = FakError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str(s)
    }
}

/// Context for verification operations, bundling all required inputs.
#[derive(Debug, Clone)]
pub struct VerificationContext<'a> {
    pub trace: &'a ExecutionTrace,
    pub capabilities: &'a CapabilityManifest,
    pub cost_ledger: &'a CostLedger,
    pub policy_ir: &'a PolicyIR,
}

impl<'a> VerificationContext<'a> {
    pub fn new(
        trace: &'a ExecutionTrace,
        capabilities: &'a CapabilityManifest,
        cost_ledger: &'a CostLedger,
        policy_ir: &'a PolicyIR,
    ) -> Self {
        Self { trace, capabilities, cost_ledger, policy_ir }
    }
}

/// Compute a deterministic content-addressable hash for an artifact.
pub fn compute_content_hash(obj: &serde_json::Value) -> String {
    // Use compact serialization with sorted keys for determinism
    let serialized = canonical_json(obj);
    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Produce canonical JSON with deterministic key ordering.
fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            let pairs: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap_or_default(), canonical_json(&map[k])))
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        _ => serde_json::to_string(value).unwrap_or_else(|_| "null".to_string()),
    }
}