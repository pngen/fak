# Formal Assurance Kernel (FAK)

## One-sentence value proposition

FAK is a minimal, release-grade proof substrate that formally verifies the correctness of autonomous governance stack components through deterministic, replayable, machine-verifiable proofs.

## Overview

FAK serves as a kernel-level verification system beneath the Deterministic Intelligence Orchestrator (DIO), Zero-Trust Autonomous Agent Sandbox (ZT-AAS), Inference Cost Attribution Engine (ICAE), and Policy-to-Outcome Compiler (POC). It consumes immutable artifacts from these systems and attaches formal proofs to them, ensuring behavioral soundness, authority non-escalation, economic invariance, and semantic preservation.

## Architecture diagram
<pre>
┌─────────────────┐    ┌──────────────────┐
│   DIO           │    │   ZT-AAS         │
│  (Execution)    │    │  (Capabilities)  │
└─────────┬───────┘    └────────┬─────────┘
          │                     │
          ▼                     ▼
┌─────────────────────────────────────────┐
│     FAK - Formal Assurance Kernel       │
│                                         │
│  ┌─────────────┐ ┌─────────────┐        │
│  │ Invariant   │ │ Proof       │        │
│  │ DSL         │ │ Engine      │        │
│  └─────────────┘ └─────────────┘        │
│           ▲          ▲                  │
│           │          │                  │
│  ┌────────────────────────────────┐     │
│  │ Artifact Manager               │     │
│  │ (Content-addressable storage)  │     │
│  └────────────────────────────────┘     │
└─────────────────────────────────────────┘
                    ▲
                    │
┌──────────────────────────────────────┐
│         Verifier                     │
│  (Standalone verification tool)      │
└──────────────────────────────────────┘
</pre>

## Quick Start

Add to `Cargo.toml`:
```toml
[dependencies]
fak = "1.0"
```

Basic usage:
```rust
use fak::{
    ArtifactManager, ProofEngine, Verifier,
    ExecutionTrace, CapabilityManifest, CostLedger, PolicyIR,
    InvariantSpec, ProofType,
};
use std::collections::HashMap;

// Create governance artifacts
let trace = ExecutionTrace::new("trace-1".into(), vec![], Default::default());
let caps = CapabilityManifest::new("cap-1".into(), "agent-1".into(), vec![], HashMap::new(), Default::default());
let cost = CostLedger::new("cost-1".into(), vec![], 0.0, Default::default());
let policy = PolicyIR::new("policy-1".into(), Default::default(), vec![], Default::default());

// Define invariants
let invariants = vec![
    InvariantSpec::new(
        "cost_check".into(),
        "Verify non-negative costs".into(),
        None, None, vec![],
        ProofType::EconomicInvariance,
    ),
];

// Generate proof
let engine = ProofEngine::new();
let witness = engine.verify_invariants(&trace, &caps, &cost, &policy, &invariants)?;
let bundle = engine.generate_bundle(&[witness])?;

// Verify bundle
let verifier = Verifier::new();
let result = verifier.verify_bundle(&bundle);
assert!(result.success);
```

## Core Components

1. **Invariant Specification DSL** - Minimal language for declaring invariants, preconditions, postconditions, and temporal properties.
2. **Proof Engine** - Combines trace replay with invariant checking using SMT-style reasoning where required.
3. **Artifact Manager** - Ensures immutability, content-addressability, and versioning of all inputs.
4. **Verifier Tooling** - Standalone tool that accepts proof bundles and re-checks invariants without runtime dependencies.

## Usage

FAK integrates non-invasively into existing systems by consuming artifacts emitted from DIO, ZT-AAS, ICAE, and POC. It produces deterministic, replayable proofs that can be independently verified offline.

## Building & Testing

```bash
# Build
cargo build --release

# Run tests
cargo test

# Run with verbose output
cargo test -- --nocapture
```

## Design Principles

- **Deterministic**: All proofs are reproducible with identical inputs.
- **Replayable**: Proofs can be re-executed without external dependencies.
- **Machine-verifiable**: Proofs compile to verifiable intermediate representations.
- **Content-addressable**: Artifacts are immutable and uniquely identified.
- **Minimal DSL**: Invariant language avoids general-purpose computation.
- **Explicit failures**: Clear counterexamples on invariant violations.

## Requirements

FAK must be deployment-grade v1.0.0 with semantic closure, providing:
- Formal verification of behavioral soundness
- Authority non-escalation proofs
- Economic invariance validation
- Semantic preservation guarantees
- Deterministic, replayable, machine-verifiable outputs
- Standalone verifier tooling
- Content-addressable artifact management

## Limitations (v1.0.0)

### Temporal Logic Implementation
The temporal logic evaluator is currently a stub. Actual implementation requires integration with SMT solvers or symbolic execution engines.

### Resource Limits
FAK implements basic resource limits to prevent denial-of-service:
- Maximum 100,000 trace steps per ExecutionTrace
- Maximum 1,000 invariants per ProofEngine verification
- Maximum 100 witnesses per ProofBundle
- 30-second timeout for invariant verification

### Bundle Verification
FAK performs integrity checks on bundles to ensure content-addressability and prevent tampering.

### Serialization
All dataclasses are properly serialized with support for:
- Enum fields (ProofType)
- Bytes fields (PolicyIR compiled_enforcement)
- Nested structures