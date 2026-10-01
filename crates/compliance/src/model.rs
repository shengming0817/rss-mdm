//! Compliance-owned metadata and evidence. The predicate AST remains owned by the host's engine.
use crate::{Decision, Status, assess};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;
/// Closed validation categories. Messages never contain policy or device values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Invalid {
    #[error("invalid compliance definition")]
    Definition,
    #[error("invalid frozen compliance input")]
    Input,
    #[error("invalid compliance assessment")]
    Assessment,
    #[error("invalid compliance evidence")]
    Evidence,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    All,
    Windows,
    Macos,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    All,
    Groups { ids: Vec<Uuid> },
}
/// One version owns metadata and one foreign-owner predicate, never a second evaluator.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Definition<C> {
    pub name: String,
    pub severity: Severity,
    pub enabled: bool,
    pub platform: Platform,
    pub target: Target,
    pub criteria: C,
}
impl<C> Definition<C> {
    pub fn groups(&self) -> Vec<Uuid> {
        match &self.target {
            Target::All => vec![],
            Target::Groups { ids } => ids.clone(),
        }
    }
    pub fn validate(&self) -> Result<(), Invalid> {
        if !text(&self.name, 128) {
            return Err(Invalid::Definition);
        }
        if let Target::Groups { ids } = &self.target
            && (ids.is_empty()
                || ids.len() > 16
                || ids.iter().any(Uuid::is_nil)
                || ids.iter().collect::<BTreeSet<_>>().len() != ids.len())
        {
            return Err(Invalid::Definition);
        }
        Ok(())
    }
}
fn text(v: &str, max: usize) -> bool {
    !v.trim().is_empty() && v.chars().count() <= max && !v.chars().any(char::is_control)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupInput {
    pub id: Uuid,
    pub revision: i64,
    pub member_set: Option<Uuid>,
    pub member_version: i64,
    pub asset_watermark: Option<i64>,
    pub ready: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Input<C> {
    pub rule: Uuid,
    pub revision: i64,
    pub definition: Definition<C>,
    pub watermark: i64,
    pub evaluated_at: i64,
    pub groups: Vec<GroupInput>,
}
impl<C> Input<C> {
    pub fn validate(&self) -> Result<(), Invalid> {
        self.definition.validate()?;
        if self.rule.is_nil() || self.revision < 1 || self.watermark < 0 || self.evaluated_at < 0 {
            return Err(Invalid::Input);
        }
        let expected: BTreeSet<_> = self.definition.groups().into_iter().collect();
        if self.groups.len() != expected.len()
            || self.groups.iter().map(|g| g.id).collect::<BTreeSet<_>>() != expected
        {
            return Err(Invalid::Input);
        }
        if self.groups.iter().any(|g| {
            g.revision < 1
                || g.member_version < 0
                || g.asset_watermark
                    .is_some_and(|v| v < 0 || v > self.watermark)
        }) {
            return Err(Invalid::Input);
        }
        Ok(())
    }
}
/// Reference only; never carries a collected or manual field value.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FactReference {
    pub source: String,
    pub dataset: Option<String>,
    pub registration: Option<String>,
    pub registration_generation: Option<u64>,
    pub epoch: Option<String>,
    pub snapshot_id: String,
    pub observed_at: i64,
    pub received_at: i64,
    pub actor: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceReference {
    pub source: String,
    pub registration: String,
    pub generation: String,
    pub epoch: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldEvidence {
    pub field: String,
    pub sources: Vec<FactReference>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Match,
    NoMatch,
    Null,
    Missing,
    Deleted,
    Unsupported,
    Conflict,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Explanation {
    pub path: Vec<usize>,
    pub outcome: Outcome,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupEvidence {
    pub id: Uuid,
    pub member_set: Option<Uuid>,
    pub decision: Decision,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Applicability {
    pub platform: Platform,
    pub platform_decision: Decision,
    pub sources: Vec<SourceReference>,
    pub groups: Vec<GroupEvidence>,
}
impl Applicability {
    pub fn group_decision(&self) -> Decision {
        if self.groups.is_empty() {
            return Decision::Match;
        }
        self.groups
            .iter()
            .fold(Decision::NoMatch, |old, g| union(old, g.decision))
    }
    pub fn decision(&self) -> Decision {
        intersection(self.platform_decision, self.group_decision())
    }
}
pub fn union(a: Decision, b: Decision) -> Decision {
    match (a, b) {
        (Decision::Match, _) | (_, Decision::Match) => Decision::Match,
        (Decision::Unknown, _) | (_, Decision::Unknown) => Decision::Unknown,
        _ => Decision::NoMatch,
    }
}
pub fn intersection(a: Decision, b: Decision) -> Decision {
    match (a, b) {
        (Decision::NoMatch, _) | (_, Decision::NoMatch) => Decision::NoMatch,
        (Decision::Unknown, _) | (_, Decision::Unknown) => Decision::Unknown,
        _ => Decision::Match,
    }
}
pub fn platform_decision(platform: Platform, sources: &[SourceReference]) -> Decision {
    if platform == Platform::All {
        return Decision::Match;
    }
    let windows = sources.iter().any(|s| s.source == "mdm.windows");
    let macos = sources.iter().any(|s| s.source == "mdm.apple");
    match (windows, macos) {
        (true, false) if platform == Platform::Windows => Decision::Match,
        (false, true) if platform == Platform::Macos => Decision::Match,
        (true, false) | (false, true) => Decision::NoMatch,
        _ => Decision::Unknown,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    PlatformNotApplicable,
    GroupNotApplicable,
    PlatformUnknown,
    GroupUnknown,
    RuleSatisfied,
    RuleFailed,
    FactsUnknown,
}
fn conclusion(a: &Applicability, condition: Decision) -> (Status, Reason) {
    let status = assess(a.decision(), condition);
    let reason = match status {
        Status::NotApplicable if a.platform_decision == Decision::NoMatch => {
            Reason::PlatformNotApplicable
        }
        Status::NotApplicable => Reason::GroupNotApplicable,
        Status::Unknown if a.platform_decision == Decision::Unknown => Reason::PlatformUnknown,
        Status::Unknown if a.group_decision() == Decision::Unknown => Reason::GroupUnknown,
        Status::Unknown => Reason::FactsUnknown,
        Status::Compliant => Reason::RuleSatisfied,
        Status::NonCompliant => Reason::RuleFailed,
    };
    (status, reason)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Assessment {
    pub rule_id: Uuid,
    pub rule_version: i64,
    pub dictionary_version: String,
    pub fact_watermark: i64,
    pub evaluated_at: i64,
    pub groups: Vec<GroupInput>,
    pub status: Status,
    pub reason: Reason,
    pub condition: Decision,
    pub applicability: Applicability,
    pub explanations: Vec<Explanation>,
    pub evidence: Vec<FieldEvidence>,
}
impl Assessment {
    pub fn evaluate<C>(
        input: &Input<C>,
        dictionary: &str,
        condition: Decision,
        applicability: Applicability,
        explanations: Vec<Explanation>,
        evidence: Vec<FieldEvidence>,
    ) -> Result<Self, Invalid> {
        input.validate()?;
        let (status, reason) = conclusion(&applicability, condition);
        let result = Self {
            rule_id: input.rule,
            rule_version: input.revision,
            dictionary_version: dictionary.into(),
            fact_watermark: input.watermark,
            evaluated_at: input.evaluated_at,
            groups: input.groups.clone(),
            status,
            reason,
            condition,
            applicability,
            explanations,
            evidence,
        };
        result.validate()?;
        Ok(result)
    }
    pub fn validate(&self) -> Result<(), Invalid> {
        if self.rule_id.is_nil()
            || self.rule_version < 1
            || self.fact_watermark < 0
            || self.evaluated_at < 0
            || !text(&self.dictionary_version, 128)
        {
            return Err(Invalid::Assessment);
        }
        if self.groups.len() > 16
            || self.groups.iter().any(|g| !g.ready)
            || self.groups.len() != self.applicability.groups.len()
        {
            return Err(Invalid::Assessment);
        }
        for (g, p) in self.groups.iter().zip(&self.applicability.groups) {
            if g.id != p.id || g.member_set != p.member_set {
                return Err(Invalid::Assessment);
            }
        }
        // Platform provenance includes every active registration/source, unlike a
        // resolved field's two-source value limit. The host bounds its source page.
        if self.explanations.len() > 1024 || self.evidence.len() > 256 {
            return Err(Invalid::Assessment);
        }
        if self.applicability.platform_decision
            != platform_decision(self.applicability.platform, &self.applicability.sources)
            || conclusion(&self.applicability, self.condition) != (self.status, self.reason)
        {
            return Err(Invalid::Assessment);
        }
        if self.evidence.iter().any(|e| {
            !text(&e.field, 256)
                || e.sources.len() > 2
                || e.sources
                    .iter()
                    .any(|s| !text(&s.source, 128) || !text(&s.snapshot_id, 1024))
        }) {
            return Err(Invalid::Evidence);
        }
        Ok(())
    }
}
