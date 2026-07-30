//! Proof engine for FAK.
use crate::error::{FakError, FakResult};
use crate::types::{
    compute_content_hash, CapabilityManifest, CostLedger, CounterExample, ExecutionTrace,
    InvariantSpec, PolicyIR, ProofBundle, ProofType, ProofWitness,
};
use serde::Serialize;
use std::time::Instant;

/// Version of the proof algorithm and expression semantics committed into proof IDs.
pub const PROOF_ALGORITHM_VERSION: &str = "fak-proof-v2";

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

    /// Return the immutable engine configuration used for verification.
    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Return the proof algorithm version committed into generated proof IDs.
    pub fn algorithm_version(&self) -> &'static str {
        PROOF_ALGORITHM_VERSION
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
        self.validate_config()?;

        // Validate inputs
        trace.validate()?;
        capabilities.validate()?;
        cost_ledger.validate()?;
        policy_ir.validate()?;

        if invariants.is_empty() {
            return Err(FakError::Validation {
                field: "invariants".to_string(),
                message: "at least one invariant is required".to_string(),
            });
        }

        if invariants.len() > self.config.max_invariants {
            return Err(FakError::ResourceLimit {
                resource: "invariants".to_string(),
                limit: self.config.max_invariants,
                actual: invariants.len(),
            });
        }

        // Invalid specifications are input errors, not proof counterexamples.
        // Validate them before evaluation so this method never returns a
        // witness that fails ProofWitness::validate().
        for invariant in invariants {
            invariant.validate()?;
        }

        let start_time = Instant::now();
        let mut counterexamples = Vec::new();

        for invariant in invariants {
            self.check_timeout(start_time)?;

            match self.check_invariant(trace, capabilities, cost_ledger, policy_ir, invariant) {
                Ok(true) => {}
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

            self.check_timeout(start_time)?;
        }

        let proof_content = serde_json::json!({
            "algorithm_version": PROOF_ALGORITHM_VERSION,
            "engine_config": {
                "max_invariants": self.config.max_invariants,
                "timeout_secs": self.config.timeout_secs,
            },
            "trace_hash": content_hash_for(trace)?,
            "capabilities_hash": content_hash_for(capabilities)?,
            "cost_ledger_hash": content_hash_for(cost_ledger)?,
            "policy_ir_hash": content_hash_for(policy_ir)?,
            "invariant_hashes": invariants
                .iter()
                .map(content_hash_for)
                .collect::<FakResult<Vec<_>>>()?,
            "counterexamples": &counterexamples,
            "outcome": if counterexamples.is_empty() { "pass" } else { "fail" },
        });

        let proof_id = compute_content_hash(&proof_content);
        self.check_timeout(start_time)?;

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

    fn validate_config(&self) -> FakResult<()> {
        if self.config.max_invariants == 0 {
            return Err(FakError::Validation {
                field: "max_invariants".to_string(),
                message: "max_invariants must be greater than zero".to_string(),
            });
        }
        if !self.config.timeout_secs.is_finite() || self.config.timeout_secs <= 0.0 {
            return Err(FakError::Validation {
                field: "timeout_secs".to_string(),
                message: "timeout_secs must be finite and greater than zero".to_string(),
            });
        }
        Ok(())
    }

    fn check_timeout(&self, start_time: Instant) -> FakResult<()> {
        let elapsed = start_time.elapsed().as_secs_f64();
        if elapsed > self.config.timeout_secs {
            return Err(FakError::Timeout {
                operation: "invariant verification".to_string(),
                limit_secs: self.config.timeout_secs,
            });
        }
        Ok(())
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

        let context = match invariant.invariant_type {
            ProofType::BehavioralSoundness => EvaluationContext::Behavioral(trace),
            ProofType::AuthorityNonEscalation => EvaluationContext::Authority(capabilities),
            ProofType::EconomicInvariance => EvaluationContext::Economic(cost_ledger),
            ProofType::SemanticPreservation => EvaluationContext::Semantic(policy_ir),
        };

        if let Some(precondition) = invariant.precondition.as_deref() {
            if !evaluate_expression(precondition, &context, invariant)? {
                return Ok(true);
            }
        }

        if let Some(postcondition) = invariant.postcondition.as_deref() {
            if !evaluate_expression(postcondition, &context, invariant)? {
                return Ok(false);
            }
        }

        for temporal_property in &invariant.temporal_properties {
            if !evaluate_temporal_property(temporal_property, &context, invariant)? {
                return Ok(false);
            }
        }

        Ok(true)
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

#[derive(Debug, Clone, Copy)]
enum EvaluationValue {
    Boolean(bool),
    Number(f64),
}

enum EvaluationContext<'a> {
    Behavioral(&'a ExecutionTrace),
    Authority(&'a CapabilityManifest),
    Economic(&'a CostLedger),
    Semantic(&'a PolicyIR),
}

fn evaluate_temporal_property(
    temporal_property: &str,
    context: &EvaluationContext<'_>,
    invariant: &InvariantSpec,
) -> FakResult<bool> {
    let trimmed = temporal_property.trim();
    let mut parts = trimmed.splitn(2, |character: char| character.is_whitespace());
    let operator = parts.next().unwrap_or_default();
    let expression = parts.next().unwrap_or_default().trim();

    if operator != "always" || expression.is_empty() {
        return Err(verification_failure(
            invariant,
            format!(
                "unsupported temporal property '{}'; expected 'always <expression>'",
                temporal_property
            ),
        ));
    }

    evaluate_expression(expression, context, invariant)
}

fn evaluate_expression(
    expression: &str,
    context: &EvaluationContext<'_>,
    invariant: &InvariantSpec,
) -> FakResult<bool> {
    let expression = expression.trim();
    if expression.is_empty() {
        return Err(verification_failure(
            invariant,
            "expression cannot be empty",
        ));
    }

    match split_comparison(expression) {
        Ok(Some((left, operator, right))) => {
            let left = resolve_numeric_operand(left, context, invariant)?;
            let right = resolve_numeric_operand(right, context, invariant)?;
            Ok(match operator {
                "<=" => left <= right,
                ">=" => left >= right,
                "==" => left == right,
                "!=" => left != right,
                "<" => left < right,
                ">" => left > right,
                _ => unreachable!("comparison parser returned a known operator"),
            })
        }
        Ok(None) => match resolve_value(expression, context, invariant)? {
            EvaluationValue::Boolean(value) => Ok(value),
            EvaluationValue::Number(_) => Err(verification_failure(
                invariant,
                format!(
                    "numeric expression '{}' requires an explicit comparison",
                    expression
                ),
            )),
        },
        Err(reason) => Err(verification_failure(invariant, reason)),
    }
}

fn split_comparison(expression: &str) -> Result<Option<(&str, &str, &str)>, String> {
    let mut matches = Vec::new();
    let mut characters = expression.char_indices().peekable();

    while let Some((index, character)) = characters.next() {
        let (operator, length) = match character {
            '<' if expression[index..].starts_with("<=") => ("<=", 2),
            '>' if expression[index..].starts_with(">=") => (">=", 2),
            '=' if expression[index..].starts_with("==") => ("==", 2),
            '!' if expression[index..].starts_with("!=") => ("!=", 2),
            '<' => ("<", 1),
            '>' => (">", 1),
            _ => continue,
        };

        matches.push((index, operator, length));
        if length == 2 {
            characters.next();
        }
    }

    match matches.as_slice() {
        [] => Ok(None),
        [(operator_index, operator, operator_length)] => {
            let left = expression[..*operator_index].trim();
            let right = expression[*operator_index + *operator_length..].trim();
            if left.is_empty() || right.is_empty() {
                return Err(format!("malformed comparison '{}'", expression));
            }
            Ok(Some((left, *operator, right)))
        }
        _ => Err(format!(
            "chained or ambiguous comparisons are unsupported: '{}'",
            expression
        )),
    }
}

fn resolve_numeric_operand(
    operand: &str,
    context: &EvaluationContext<'_>,
    invariant: &InvariantSpec,
) -> FakResult<f64> {
    match resolve_value(operand, context, invariant)? {
        EvaluationValue::Number(value) => Ok(value),
        EvaluationValue::Boolean(_) => Err(verification_failure(
            invariant,
            format!("boolean operand '{}' cannot be used numerically", operand),
        )),
    }
}

fn resolve_value(
    operand: &str,
    context: &EvaluationContext<'_>,
    invariant: &InvariantSpec,
) -> FakResult<EvaluationValue> {
    let operand = operand.trim();
    match operand {
        "true" => return Ok(EvaluationValue::Boolean(true)),
        "false" => return Ok(EvaluationValue::Boolean(false)),
        _ => {}
    }

    if let Ok(value) = operand.parse::<f64>() {
        if value.is_finite() {
            return Ok(EvaluationValue::Number(value));
        }
        return Err(verification_failure(
            invariant,
            format!("numeric literal '{}' must be finite", operand),
        ));
    }

    let value = match context {
        EvaluationContext::Behavioral(trace) => match operand {
            "step_count" => EvaluationValue::Number(trace.steps.len() as f64),
            "trace_nonempty" => EvaluationValue::Boolean(!trace.steps.is_empty()),
            _ => return Err(unsupported_variable(invariant, operand)),
        },
        EvaluationContext::Authority(capabilities) => match operand {
            "capability_count" => EvaluationValue::Number(capabilities.capabilities.len() as f64),
            "authority_graph_nonempty" => {
                EvaluationValue::Boolean(!capabilities.authority_graph.is_empty())
            }
            _ => return Err(unsupported_variable(invariant, operand)),
        },
        EvaluationContext::Economic(cost_ledger) => match operand {
            "total_cost" => EvaluationValue::Number(cost_ledger.total_cost),
            "entry_count" => EvaluationValue::Number(cost_ledger.entries.len() as f64),
            "entries_total" => EvaluationValue::Number(cost_entries_total(cost_ledger, invariant)?),
            _ => return Err(unsupported_variable(invariant, operand)),
        },
        EvaluationContext::Semantic(policy_ir) => match operand {
            "policy_id_nonempty" => EvaluationValue::Boolean(!policy_ir.id.is_empty()),
            "ast_nonempty" => EvaluationValue::Boolean(!policy_ir.ast.is_empty()),
            "compiled_enforcement_nonempty" => {
                EvaluationValue::Boolean(!policy_ir.compiled_enforcement.is_empty())
            }
            _ => return Err(unsupported_variable(invariant, operand)),
        },
    };

    Ok(value)
}

fn cost_entries_total(ledger: &CostLedger, invariant: &InvariantSpec) -> FakResult<f64> {
    let mut total = 0.0;
    for (index, entry) in ledger.entries.iter().enumerate() {
        let value = entry
            .as_object()
            .and_then(|object| object.get("total_cost").or_else(|| object.get("cost")))
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| {
                verification_failure(
                    invariant,
                    format!(
                        "cost entry {} must contain a numeric 'total_cost' or 'cost' field",
                        index
                    ),
                )
            })?;
        if !value.is_finite() {
            return Err(verification_failure(
                invariant,
                format!("cost entry {} must contain a finite cost", index),
            ));
        }
        total += value;
        if !total.is_finite() {
            return Err(verification_failure(
                invariant,
                "sum of cost entries must be finite",
            ));
        }
    }
    Ok(total)
}

fn unsupported_variable(invariant: &InvariantSpec, variable: &str) -> FakError {
    verification_failure(
        invariant,
        format!(
            "unsupported variable '{}' for {} invariant",
            variable,
            invariant.invariant_type.as_str()
        ),
    )
}

fn verification_failure(invariant: &InvariantSpec, reason: impl Into<String>) -> FakError {
    FakError::VerificationFailure {
        invariant: invariant.name.clone(),
        reason: reason.into(),
    }
}

fn content_hash_for<T: Serialize>(value: &T) -> FakResult<String> {
    let json = serde_json::to_value(value)?;
    Ok(compute_content_hash(&json))
}

impl Default for ProofEngine {
    fn default() -> Self {
        Self {
            config: EngineConfig::default(),
        }
    }
}
