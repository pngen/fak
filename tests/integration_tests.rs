//! Integration tests for FAK deployment validation.

use fak::{
    ArtifactManager, FakError, InvariantDSL, ProofEngine, Verifier,
    CapabilityManifest, CostLedger, ExecutionTrace, InvariantSpec, 
    PolicyIR, ProofType, compute_content_hash,
};
use std::collections::HashMap;

// ============================================================================
// Test Fixtures
// ============================================================================

fn sample_trace() -> ExecutionTrace {
    ExecutionTrace::new(
        "trace-001".to_string(),
        vec![serde_json::json!({"step": 1, "action": "init"})],
        serde_json::Map::new(),
    )
}

fn sample_capabilities() -> CapabilityManifest {
    let mut graph = HashMap::new();
    graph.insert("admin".to_string(), vec!["read".to_string(), "write".to_string()]);
    CapabilityManifest::new(
        "cap-001".to_string(),
        "agent-001".to_string(),
        vec!["read".to_string()],
        graph,
        serde_json::Map::new(),
    )
}

fn sample_cost_ledger() -> CostLedger {
    CostLedger::new(
        "cost-001".to_string(),
        vec![serde_json::json!({"op": "inference", "cost": 0.001})],
        0.001,
        serde_json::Map::new(),
    )
}

fn sample_policy_ir() -> PolicyIR {
    let mut ast = serde_json::Map::new();
    ast.insert("rules".to_string(), serde_json::json!([]));
    PolicyIR::new(
        "policy-001".to_string(),
        ast,
        vec![0x00, 0x01],
        serde_json::Map::new(),
    )
}

// ============================================================================
// ArtifactManager Tests
// ============================================================================

#[test]
fn test_artifact_manager_store_retrieve() {
    let mgr = ArtifactManager::new();
    let artifact = serde_json::json!({"test": "data", "nested": {"value": 42}});

    let id = mgr.store_artifact(&artifact).expect("store should succeed");
    assert!(!id.is_empty());

    let retrieved = mgr.retrieve_artifact(&id).expect("retrieve should succeed");
    assert_eq!(artifact, retrieved);
}

#[test]
fn test_artifact_manager_integrity_validation() {
    let mgr = ArtifactManager::new();
    let artifact = serde_json::json!({"key": "value"});
    let id = mgr.store_artifact(&artifact).expect("store");

    assert!(mgr.validate_artifact_integrity(&id, &artifact));
    assert!(!mgr.validate_artifact_integrity("wrong-id", &artifact));
}

#[test]
fn test_artifact_not_found() {
    let mgr = ArtifactManager::new();
    let result = mgr.retrieve_artifact("nonexistent-id");
    assert!(matches!(result, Err(FakError::ArtifactNotFound { .. })));
}

#[test]
fn test_artifact_manager_contains() {
    let mgr = ArtifactManager::new();
    let artifact = serde_json::json!({"x": 1});
    let id = mgr.store_artifact(&artifact).expect("store");

    assert!(mgr.contains(&id).expect("contains check"));
    assert!(!mgr.contains("missing").expect("contains check"));
}

#[test]
fn test_artifact_manager_clear() {
    let mgr = ArtifactManager::new();
    let artifact = serde_json::json!({"x": 1});
    let id = mgr.store_artifact(&artifact).expect("store");

    assert!(mgr.contains(&id).expect("exists before clear"));
    mgr.clear().expect("clear");
    assert!(!mgr.contains(&id).expect("gone after clear"));
}

#[test]
fn test_artifact_manager_clone() {
    let mgr = ArtifactManager::new();
    let artifact = serde_json::json!({"x": 1});
    let id = mgr.store_artifact(&artifact).expect("store");

    let cloned = mgr.clone();
    assert!(cloned.contains(&id).expect("cloned contains artifact"));
}

// ============================================================================
// ProofEngine Tests
// ============================================================================

#[test]
fn test_proof_engine_verify_empty_invariants() {
    let engine = ProofEngine::new();
    let trace = sample_trace();
    let caps = sample_capabilities();
    let cost = sample_cost_ledger();
    let policy = sample_policy_ir();

    let witness = engine
        .verify_invariants(&trace, &caps, &cost, &policy, &[])
        .expect("verification should succeed");

    assert!(!witness.proof_id.is_empty());
    assert!(witness.counterexamples.is_empty());
}

#[test]
fn test_proof_engine_with_invariants() {
    let engine = ProofEngine::new();
    let trace = sample_trace();
    let caps = sample_capabilities();
    let cost = sample_cost_ledger();
    let policy = sample_policy_ir();

    let invariants = vec![
        InvariantSpec::new(
            "cost_non_negative".to_string(),
            "Cost must be non-negative".to_string(),
            None,
            Some("total_cost >= 0".to_string()),
            vec![],
            ProofType::EconomicInvariance,
        ),
        InvariantSpec::new(
            "policy_valid".to_string(),
            "Policy must have ID".to_string(),
            None,
            None,
            vec![],
            ProofType::SemanticPreservation,
        ),
    ];

    let witness = engine
        .verify_invariants(&trace, &caps, &cost, &policy, &invariants)
        .expect("verification should succeed");

    assert!(witness.counterexamples.is_empty());
    assert_eq!(witness.invariants.len(), 2);
}

#[test]
fn test_proof_engine_resource_limit() {
    let engine = ProofEngine::new();
    let trace = sample_trace();
    let caps = sample_capabilities();
    let cost = sample_cost_ledger();
    let policy = sample_policy_ir();

    let too_many: Vec<InvariantSpec> = (0..1001)
        .map(|i| InvariantSpec::new(
            format!("inv_{}", i),
            String::new(),
            None,
            None,
            vec![],
            ProofType::BehavioralSoundness,
        ))
        .collect();

    let result = engine.verify_invariants(&trace, &caps, &cost, &policy, &too_many);
    assert!(matches!(
        result,
        Err(FakError::ResourceLimit { resource, .. }) if resource == "invariants"
    ));
}

#[test]
fn test_proof_engine_generate_bundle() {
    let engine = ProofEngine::new();
    let trace = sample_trace();
    let caps = sample_capabilities();
    let cost = sample_cost_ledger();
    let policy = sample_policy_ir();

    let witness = engine
        .verify_invariants(&trace, &caps, &cost, &policy, &[])
        .expect("verify");

    let bundle = engine.generate_bundle(&[witness]).expect("bundle");
    assert!(!bundle.id.is_empty());
    assert_eq!(bundle.witnesses.len(), 1);
}

#[test]
fn test_proof_engine_empty_witnesses_rejected() {
    let engine = ProofEngine::new();
    let result = engine.generate_bundle(&[]);
    assert!(matches!(
        result,
        Err(FakError::Validation { field, .. }) if field == "witnesses"
    ));
}

// ============================================================================
// Verifier Tests
// ============================================================================

#[test]
fn test_verifier_valid_bundle() {
    let mgr = ArtifactManager::new();
    let trace = sample_trace();
    let caps = sample_capabilities();
    let cost = sample_cost_ledger();
    let policy = sample_policy_ir();

    let bundle = mgr
        .create_bundle(&trace, &caps, &cost, &policy)
        .expect("bundle creation");

    let verifier = Verifier::new();
    let result = verifier.verify_bundle(&bundle);

    assert!(result.success, "Verification failed: {:?}", result.error);
    assert_eq!(result.witness_results.len(), 1);
    assert!(result.witness_results[0].success);
}

#[test]
fn test_verifier_json_output() {
    let mgr = ArtifactManager::new();
    let trace = sample_trace();
    let caps = sample_capabilities();
    let cost = sample_cost_ledger();
    let policy = sample_policy_ir();

    let bundle = mgr.create_bundle(&trace, &caps, &cost, &policy).expect("bundle");
    let verifier = Verifier::new();
    let json = verifier.verify_bundle_json(&bundle);

    assert!(json.get("success").and_then(|v| v.as_bool()).unwrap_or(false));
    assert!(json.get("bundle_id").is_some());
}

// ============================================================================
// DSL Tests
// ============================================================================

#[test]
fn test_dsl_parse_invariant() {
    let spec = r#"
        invariant cost_bound
        precondition: budget > 0
        postcondition: spent <= budget
        temporal_properties: [always cost_valid]
    "#;

    let parsed = InvariantDSL::parse_invariant(spec).expect("parsing should succeed");

    assert_eq!(parsed.name, "cost_bound");
    assert_eq!(parsed.precondition, Some("budget > 0".to_string()));
    assert_eq!(parsed.postcondition, Some("spent <= budget".to_string()));
    assert_eq!(parsed.temporal_properties, vec!["always cost_valid"]);
}

#[test]
fn test_dsl_parse_with_comments() {
    let spec = r#"
        # This is a comment
        invariant test_inv  # inline comment
        precondition: x > 0
    "#;

    let parsed = InvariantDSL::parse_invariant(spec).expect("parse");
    assert_eq!(parsed.name, "test_inv");
    assert_eq!(parsed.precondition, Some("x > 0".to_string()));
}

#[test]
fn test_dsl_missing_name() {
    let spec = "precondition: x > 0";
    let result = InvariantDSL::parse_invariant(spec);
    assert!(matches!(result, Err(FakError::ParseError { .. })));
}

#[test]
fn test_dsl_parse_temporal_property() {
    let prop = InvariantDSL::parse_temporal_property("always x > 0").expect("parse");
    assert_eq!(prop.operator, "always");
    assert_eq!(prop.expression, "x > 0");

    let prop = InvariantDSL::parse_temporal_property("eventually done").expect("parse");
    assert_eq!(prop.operator, "eventually");
}

#[test]
fn test_dsl_temporal_empty_expression() {
    let result = InvariantDSL::parse_temporal_property("always");
    assert!(matches!(result, Err(FakError::ParseError { .. })));
}

#[test]
fn test_dsl_unknown_temporal_operator() {
    let result = InvariantDSL::parse_temporal_property("sometimes x");
    assert!(matches!(result, Err(FakError::ParseError { .. })));
}

// ============================================================================
// Type Validation Tests
// ============================================================================

#[test]
fn test_execution_trace_validation() {
    let empty_id = ExecutionTrace::new(String::new(), vec![], serde_json::Map::new());
    assert!(matches!(
        empty_id.validate(),
        Err(FakError::Validation { field, .. }) if field == "id"
    ));

    let valid = sample_trace();
    assert!(valid.validate().is_ok());
}

#[test]
fn test_capability_manifest_validation() {
    let empty_id = CapabilityManifest::new(
        String::new(),
        "agent".to_string(),
        vec![],
        HashMap::new(),
        serde_json::Map::new(),
    );
    assert!(matches!(
        empty_id.validate(),
        Err(FakError::Validation { field, .. }) if field == "id"
    ));

    let empty_agent = CapabilityManifest::new(
        "id".to_string(),
        String::new(),
        vec![],
        HashMap::new(),
        serde_json::Map::new(),
    );
    assert!(matches!(
        empty_agent.validate(),
        Err(FakError::Validation { field, .. }) if field == "agent_id"
    ));
}

#[test]
fn test_cost_ledger_validation() {
    let negative = CostLedger::new("id".to_string(), vec![], -1.0, serde_json::Map::new());
    assert!(matches!(
        negative.validate(),
        Err(FakError::Validation { field, .. }) if field == "total_cost"
    ));

    let nan = CostLedger::new("id".to_string(), vec![], f64::NAN, serde_json::Map::new());
    assert!(matches!(
        nan.validate(),
        Err(FakError::Validation { field, .. }) if field == "total_cost"
    ));

    let inf = CostLedger::new("id".to_string(), vec![], f64::INFINITY, serde_json::Map::new());
    assert!(matches!(
        inf.validate(),
        Err(FakError::Validation { field, .. }) if field == "total_cost"
    ));
}

#[test]
fn test_policy_ir_validation() {
    let empty = PolicyIR::new(String::new(), serde_json::Map::new(), vec![], serde_json::Map::new());
    assert!(matches!(
        empty.validate(),
        Err(FakError::Validation { field, .. }) if field == "id"
    ));
}

#[test]
fn test_invariant_spec_validation() {
    let empty = InvariantSpec::new(
        String::new(),
        String::new(),
        None,
        None,
        vec![],
        ProofType::BehavioralSoundness,
    );
    assert!(matches!(
        empty.validate(),
        Err(FakError::Validation { field, .. }) if field == "name"
    ));
}

// ============================================================================
// ProofType Tests
// ============================================================================

#[test]
fn test_proof_type_from_str() {
    assert!(matches!(ProofType::from_str("behavioral_soundness"), Ok(ProofType::BehavioralSoundness)));
    assert!(matches!(ProofType::from_str("authority_non_escalation"), Ok(ProofType::AuthorityNonEscalation)));
    assert!(matches!(ProofType::from_str("economic_invariance"), Ok(ProofType::EconomicInvariance)));
    assert!(matches!(ProofType::from_str("semantic_preservation"), Ok(ProofType::SemanticPreservation)));
    
    // Case insensitive
    assert!(matches!(ProofType::from_str("BEHAVIORAL_SOUNDNESS"), Ok(ProofType::BehavioralSoundness)));
    
    // Unknown
    assert!(matches!(ProofType::from_str("unknown"), Err(FakError::UnknownProofType { .. })));
}

#[test]
fn test_proof_type_as_str() {
    assert_eq!(ProofType::BehavioralSoundness.as_str(), "behavioral_soundness");
    assert_eq!(ProofType::AuthorityNonEscalation.as_str(), "authority_non_escalation");
    assert_eq!(ProofType::EconomicInvariance.as_str(), "economic_invariance");
    assert_eq!(ProofType::SemanticPreservation.as_str(), "semantic_preservation");
}

#[test]
fn test_proof_type_display() {
    assert_eq!(format!("{}", ProofType::BehavioralSoundness), "behavioral_soundness");
}

// ============================================================================
// Content Hash Tests
// ============================================================================

#[test]
fn test_deterministic_hashing() {
    let obj = serde_json::json!({"b": 2, "a": 1, "c": {"z": 26, "y": 25}});
    let hash1 = compute_content_hash(&obj);
    let hash2 = compute_content_hash(&obj);
    assert_eq!(hash1, hash2, "Hashes must be deterministic");
}

#[test]
fn test_hash_key_order_independence() {
    let obj1 = serde_json::json!({"b": 2, "a": 1});
    let obj2 = serde_json::json!({"a": 1, "b": 2});
    assert_eq!(
        compute_content_hash(&obj1),
        compute_content_hash(&obj2),
        "Key order should not affect hash"
    );
}

#[test]
fn test_hash_nested_key_order() {
    let obj1 = serde_json::json!({"outer": {"b": 2, "a": 1}});
    let obj2 = serde_json::json!({"outer": {"a": 1, "b": 2}});
    assert_eq!(
        compute_content_hash(&obj1),
        compute_content_hash(&obj2),
        "Nested key order should not affect hash"
    );
}

#[test]
fn test_hash_different_values() {
    let obj1 = serde_json::json!({"a": 1});
    let obj2 = serde_json::json!({"a": 2});
    assert_ne!(
        compute_content_hash(&obj1),
        compute_content_hash(&obj2),
        "Different values must produce different hashes"
    );
}

// ============================================================================
// Default Trait Tests
// ============================================================================

#[test]
fn test_defaults() {
    let _trace = ExecutionTrace::default();
    let _caps = CapabilityManifest::default();
    let _cost = CostLedger::default();
    let _policy = PolicyIR::default();
    let _inv = InvariantSpec::default();
    let _witness = fak::ProofWitness::default();
    let _bundle = fak::ProofBundle::default();
    let _mgr = ArtifactManager::default();
    let _engine = ProofEngine::default();
    let _verifier = Verifier::default();
}

// ============================================================================
// End-to-End Test
// ============================================================================

#[test]
fn test_full_workflow() {
    // 1. Create artifacts
    let trace = sample_trace();
    let caps = sample_capabilities();
    let cost = sample_cost_ledger();
    let policy = sample_policy_ir();

    // 2. Define invariants
    let invariants = vec![
        InvariantSpec::new(
            "economic_check".to_string(),
            "Costs must be non-negative".to_string(),
            None,
            Some("total_cost >= 0".to_string()),
            vec![],
            ProofType::EconomicInvariance,
        ),
    ];

    // 3. Create proof
    let engine = ProofEngine::new();
    let witness = engine
        .verify_invariants(&trace, &caps, &cost, &policy, &invariants)
        .expect("verification");

    assert!(witness.counterexamples.is_empty());

    // 4. Bundle proof
    let bundle = engine.generate_bundle(&[witness]).expect("bundle");

    // 5. Verify bundle
    let verifier = Verifier::new();
    let result = verifier.verify_bundle(&bundle);

    assert!(result.success);
    assert_eq!(result.witness_results.len(), 1);
    assert!(result.witness_results[0].success);
    assert_eq!(result.witness_results[0].invariant_count, 1);
    assert_eq!(result.witness_results[0].counterexample_count, 0);
}