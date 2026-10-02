//! Readback evidence for queryable native mutations. ACKs never satisfy this contract.
use super::{Context, Error, Operation, Request, Verb};
use crate::syncml::Command;
use serde::Serialize;
use std::collections::BTreeMap;

/// Native evidence expected after a mutation, separate from its receipt.
#[derive(Clone, PartialEq, Eq)]
pub enum Expected {
    /// Exact compiled native scalar or XML value.
    Value(String),
    /// The native object exists; no unrequested value is inferred.
    Present,
    /// A native 404 for this exact object after its Delete.
    Absent,
}
impl std::fmt::Debug for Expected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeExpected([REDACTED])")
    }
}
/// A bounded native query and the object evidence it is intended to observe.
pub struct Verification {
    /// Read-only native operations; Atomic does not permit Get and is not reused here.
    pub request: Request,
    /// Canonical object URI to expected native evidence.
    pub expected: BTreeMap<String, Expected>,
}
/// A native effect contract. It never treats transport acceptance as verification.
pub enum EffectPlan {
    /// A query proves returned facts rather than a mutation effect.
    ReadOnly,
    /// Every requested mutation has an independently queryable effect.
    Readback(Verification),
    /// No generic detector can prove this operation's effect.
    Unverifiable(&'static str),
}
impl EffectPlan {
    /// Borrow the independently compiled readback when the contract supplies one.
    pub fn readback(&self) -> Option<&Verification> {
        if let Self::Readback(v) = self {
            Some(v)
        } else {
            None
        }
    }
    /// Consume the compiled readback for dispatch.
    pub fn into_readback(self) -> Option<Verification> {
        if let Self::Readback(v) = self {
            Some(v)
        } else {
            None
        }
    }
    /// Evaluate exact, already-correlated facts. Ingestion owns identity and eligibility checks.
    pub fn assess(&self, facts: &[EffectFact]) -> EffectAssessment {
        let Self::Readback(verification) = self else {
            return match self {
                Self::Unverifiable(reason) => EffectAssessment {
                    state: EffectState::Unverifiable,
                    reason: Some(reason),
                },
                _ => EffectAssessment::waiting("query_facts_have_no_mutation_effect"),
            };
        };
        if facts
            .iter()
            .any(|f| f.uri.is_empty() && (!f.receipt_accepted || f.status != Some(200)))
        {
            return EffectAssessment::waiting("incomplete_group_evidence");
        }
        if facts
            .iter()
            .any(|f| !f.uri.is_empty() && !verification.expected.contains_key(&f.uri))
        {
            return EffectAssessment::waiting("unexpected_object_evidence");
        }
        for (uri, expected) in &verification.expected {
            let matching = facts.iter().filter(|f| &f.uri == uri).collect::<Vec<_>>();
            if matching.len() != 1 {
                return EffectAssessment::waiting("incomplete_or_ambiguous_evidence");
            }
            let fact = matching[0];
            if !fact.receipt_accepted
                || (fact.value.is_some() && !fact.result_accepted)
                || fact.status.is_none()
            {
                return EffectAssessment::waiting("ineligible_or_incomplete_evidence");
            }
            if !expected.matches(fact.status, fact.value.as_deref()) {
                return EffectAssessment {
                    state: EffectState::Diverged,
                    reason: Some("native_value_mismatch"),
                };
            }
        }
        EffectAssessment {
            state: EffectState::Verified,
            reason: None,
        }
    }
}
/// Native results after correlation, decryption and generation/permission admission.
pub struct EffectFact {
    /// Canonical native object identity.
    pub uri: String,
    /// The matching Get status.
    pub status: Option<i32>,
    /// Exact native result value.
    pub value: Option<String>,
    /// Whether the status passed current ingestion eligibility.
    pub receipt_accepted: bool,
    /// Whether the result passed current ingestion eligibility.
    pub result_accepted: bool,
}
/// Effect evidence is separate from execution progress and compliance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectState {
    /// All native conditions match accepted readback evidence.
    Verified,
    /// Accepted readback differs from the native goal.
    Diverged,
    /// Evidence is missing, partial or ineligible.
    Waiting,
    /// The operation has no trustworthy generic detector.
    Unverifiable,
}
/// Pure decision consumed by both execution and query projection.
#[derive(Serialize)]
pub struct EffectAssessment {
    /// Evidence conclusion, never a command state machine.
    pub state: EffectState,
    /// Closed diagnostic without input or credential values.
    pub reason: Option<&'static str>,
}
impl EffectAssessment {
    /// Missing evidence must not manufacture success.
    pub fn waiting(reason: &'static str) -> Self {
        Self {
            state: EffectState::Waiting,
            reason: Some(reason),
        }
    }
}
impl Request {
    /// Build readback only if every mutation has a valid native Get on the same target.
    /// Exec has no universal effect query; its platform lifecycle must supply one explicitly.
    pub fn effect_plan(&self, context: Context) -> Result<EffectPlan, Error> {
        self.command_count()?;
        let mut pending = vec![self];
        let mut operations = BTreeMap::new();
        let mut expected = BTreeMap::new();
        while let Some(request) = pending.pop() {
            match request {
                Self::Atomic { operations } | Self::Sequence { operations } => {
                    pending.extend(operations.iter().rev())
                }
                Self::Node {
                    node,
                    instance,
                    operation,
                    value,
                } => {
                    if *operation == Verb::Get {
                        continue;
                    }
                    if *operation == Verb::Exec {
                        return Ok(EffectPlan::Unverifiable(
                            "operation_requires_family_effect_evidence",
                        ));
                    }
                    let op =
                        Operation::compile(node, instance, *operation, value.clone(), context)?;
                    if Operation::compile(node, instance, Verb::Get, None, context).is_err() {
                        return Ok(EffectPlan::Unverifiable("native_object_is_not_queryable"));
                    }
                    let goal = if *operation == Verb::Delete {
                        if node.contains("/Policy/Config/") || op.semantics().lifetime != "Dynamic"
                        {
                            return Ok(EffectPlan::Unverifiable(
                                "delete_restores_default_without_frozen_detector",
                            ));
                        }
                        Expected::Absent
                    } else {
                        match op.command(1) {
                            Command::Add { items, .. } | Command::Replace { items, .. } => items
                                .into_iter()
                                .next()
                                .and_then(|i| i.data)
                                .map(|v| Expected::Value(v.0))
                                .unwrap_or(Expected::Present),
                            _ => return Err(Error::Value),
                        }
                    };
                    // Repeated writes to one object in a Sequence describe its last desired value.
                    expected.insert(op.uri().into(), goal);
                    operations.insert(
                        op.uri().to_owned(),
                        Self::Node {
                            node: node.clone(),
                            instance: instance.clone(),
                            operation: Verb::Get,
                            value: None,
                        },
                    );
                }
            }
        }
        if operations.is_empty() {
            return Ok(EffectPlan::ReadOnly);
        }
        let mut operations = operations.into_values().collect::<Vec<_>>();
        let request = if operations.len() == 1 {
            operations.remove(0)
        } else {
            Self::Sequence { operations }
        };
        Ok(EffectPlan::Readback(Verification { request, expected }))
    }
}
impl Expected {
    /// Interpret a correlated Get only; missing results and protocol failures remain unverified.
    pub fn matches(&self, status: Option<i32>, value: Option<&str>) -> bool {
        match self {
            Self::Absent => status == Some(404) && value.is_none(),
            Self::Present => status == Some(200) && value.is_some(),
            Self::Value(expected) => status == Some(200) && value == Some(expected.as_str()),
        }
    }
}
