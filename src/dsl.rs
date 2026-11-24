//! Invariant specification DSL for FAK.

use crate::error::{FakError, FakResult};
use crate::types::{InvariantSpec, ProofType};
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Temporal property specification for invariants.
#[derive(Debug, Clone, PartialEq)]
pub struct TemporalProperty {
    pub operator: String,
    pub expression: String,
}

/// DSL parser for invariant specifications.
#[derive(Debug, Clone, Default)]
pub struct InvariantDSL;

static INVARIANT_RE: OnceLock<Regex> = OnceLock::new();
static TYPE_RE: OnceLock<Regex> = OnceLock::new();

fn get_invariant_re() -> &'static Regex {
    INVARIANT_RE.get_or_init(|| Regex::new(r"invariant\s+(\w+)").expect("valid regex"))
}

fn get_type_re() -> &'static Regex {
    // Declarations start a line. Text inside another field's value (for example
    // a description that mentions `type: ...`) is not a declaration.
    TYPE_RE.get_or_init(|| Regex::new(r"(?m)^type:\s*(\w+)").expect("valid regex"))
}

impl InvariantDSL {
    /// Parse an invariant specification from DSL text.
    pub fn parse_invariant(spec_str: &str) -> FakResult<InvariantSpec> {
        let spec_str_clean = Self::strip_comments(spec_str);
        Self::reject_duplicate_declarations(&spec_str_clean)?;
        let name = Self::extract_name(&spec_str_clean)?;
        let fields = Self::extract_fields(&spec_str_clean);
        let temporal_properties = Self::parse_temporal_properties_list(
            fields.get("temporal_properties").map(|s| s.as_str()),
        )?;
        let invariant_type = Self::extract_type(&spec_str_clean)?;

        Ok(InvariantSpec {
            name,
            description: fields.get("description").cloned().unwrap_or_default(),
            precondition: fields.get("precondition").cloned(),
            postcondition: fields.get("postcondition").cloned(),
            temporal_properties,
            invariant_type,
        })
    }

    fn strip_comments(spec_str: &str) -> String {
        spec_str
            .lines()
            .filter_map(|line| {
                let trimmed = if let Some(pos) = line.find('#') {
                    line[..pos].trim()
                } else {
                    line.trim()
                };
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A field may be declared once. Reading only the first of two
    /// declarations would prove the invariant without the other one.
    fn reject_duplicate_declarations(spec_str: &str) -> FakResult<()> {
        for field_name in [
            "description",
            "precondition",
            "postcondition",
            "temporal_properties",
            "type",
        ] {
            let declaration = format!("{}:", field_name);
            if spec_str
                .lines()
                .filter(|line| line.starts_with(&declaration))
                .count()
                > 1
            {
                return Err(FakError::ParseError {
                    source: field_name.to_string(),
                    message: "field is declared more than once".to_string(),
                });
            }
        }
        Ok(())
    }

    fn extract_name(spec_str: &str) -> FakResult<String> {
        get_invariant_re()
            .captures(spec_str)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| FakError::ParseError {
                source: "invariant_spec".to_string(),
                message: "missing invariant name declaration".to_string(),
            })
    }

    fn extract_type(spec_str: &str) -> FakResult<ProofType> {
        match get_type_re().captures(spec_str).and_then(|c| c.get(1)) {
            Some(m) => ProofType::from_str(m.as_str()),
            None => Ok(ProofType::BehavioralSoundness),
        }
    }

    fn extract_fields(spec_str: &str) -> HashMap<String, String> {
        let mut fields = HashMap::new();
        for field_name in &[
            "description",
            "precondition",
            "postcondition",
            "temporal_properties",
        ] {
            if let Some(value) = Self::extract_field_value(spec_str, field_name) {
                fields.insert(field_name.to_string(), value);
            }
        }
        fields
    }

    fn extract_field_value(spec_str: &str, field_name: &str) -> Option<String> {
        let pattern = format!(r"(?m)^{}:\s*(.+)", field_name);
        Regex::new(&pattern)
            .ok()?
            .captures(spec_str)?
            .get(1)
            .map(|m| m.as_str().trim().to_string())
    }

    fn parse_temporal_properties_list(props_str: Option<&str>) -> FakResult<Vec<String>> {
        match props_str {
            None => Ok(Vec::new()),
            Some(s) if s.starts_with('[') && s.ends_with(']') => Ok(s[1..s.len() - 1]
                .split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect()),
            // A declared list that is not bracketed must not be read as "no
            // temporal properties": the invariant would be proven without them.
            Some(s) => Err(FakError::ParseError {
                source: "temporal_properties".to_string(),
                message: format!(
                    "expected a bracketed list such as [always <expression>], got: {}",
                    s
                ),
            }),
        }
    }

    /// Parse a temporal property expression into operator and expression.
    pub fn parse_temporal_property(prop_str: &str) -> FakResult<TemporalProperty> {
        let trimmed = prop_str.trim();
        let operators = ["always", "eventually", "until", "next"];
        for op in &operators {
            if let Some(rest) = trimmed.strip_prefix(op) {
                let expr = rest.trim();
                if expr.is_empty() {
                    return Err(FakError::ParseError {
                        source: "temporal_property".to_string(),
                        message: format!("operator '{}' requires an expression", op),
                    });
                }
                return Ok(TemporalProperty {
                    operator: op.to_string(),
                    expression: expr.to_string(),
                });
            }
        }
        Err(FakError::ParseError {
            source: "temporal_property".to_string(),
            message: format!("unknown temporal operator in: {}", trimmed),
        })
    }
}
