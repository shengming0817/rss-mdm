//! Commutative evidence projection. Apple StatusReport provides no production sequence.
use super::{DeclarationKind, DeclarationSet, Error, StatusReport, Target, Validity};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
/// Immutable authenticated ingress evidence with the subscription set at receipt.
#[derive(Clone, Serialize, Deserialize)]
pub struct ReportEvidence {
    pub report: Vec<u8>,
    pub context: crate::applicability::Context,
    pub subscriptions: BTreeSet<String>,
    pub declarations_token: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusProjection {
    pub items: BTreeMap<String, Value>,
    pub unknown_items: BTreeSet<String>,
    pub declarations: Vec<Value>,
    pub errors: Vec<Value>,
    pub completeness: String,
    pub effect: String,
    pub synchronized: bool,
    pub compliance: String,
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct ArrayClaims {
    objects: BTreeMap<String, BTreeSet<String>>,
    full: Option<BTreeSet<String>>,
    absent: bool,
}
impl ArrayClaims {
    fn observe(&mut self, value: &Value, full: bool) -> Result<(), Error> {
        let Some(items) = value.as_array() else {
            self.absent = true;
            return Ok(());
        };
        let mut seen = BTreeSet::new();
        for item in items {
            let id = item["identifier"].as_str().ok_or(Error::Field)?.to_owned();
            seen.insert(id.clone());
            let value = if item["_removed"] == true {
                "null".into()
            } else {
                serde_json::to_string(item).map_err(|_| Error::Encoding)?
            };
            claim(self.objects.entry(id).or_default(), value);
        }
        if full {
            self.full = Some(self.full.take().map_or(seen.clone(), |old| {
                old.intersection(&seen).cloned().collect()
            }));
        }
        Ok(())
    }
    fn finish(self) -> Result<(Value, bool), Error> {
        let mut items = Vec::new();
        let mut unknown = self.absent;
        for (id, mut values) in self.objects {
            if self.absent
                || self
                    .full
                    .as_ref()
                    .is_some_and(|snapshot| !snapshot.contains(&id))
            {
                values.insert("null".into());
            }
            if values.len() != 1 {
                unknown = true;
                continue;
            }
            let value = values.first().ok_or(Error::Encoding)?;
            if value != "null" {
                items.push(serde_json::from_str(value).map_err(|_| Error::Encoding)?);
            }
        }
        Ok((Value::Array(items), unknown))
    }
}
/// Bounded accumulated claims for one immutable native publication. No report history is needed.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionState {
    claims: BTreeMap<String, BTreeSet<String>>,
    arrays: BTreeMap<String, ArrayClaims>,
    native: BTreeMap<String, BTreeSet<String>>,
    errors: BTreeSet<String>,
    full: bool,
    exhausted: bool,
}
/// Maximum persisted claim bytes; exceeding it preserves raw evidence but makes projection Unknown.
pub const PROJECTION_BYTES: usize = 512 * 1024;
/// Exact-token, commutative native evidence fold; persistence and receive order remain outside.
pub struct Projection<'a> {
    set: &'a DeclarationSet,
    expected_versions: BTreeMap<String, String>,
    wanted: BTreeSet<String>,
    claims: BTreeMap<String, BTreeSet<String>>,
    arrays: BTreeMap<String, ArrayClaims>,
    native: BTreeMap<String, BTreeSet<String>>,
    errors: BTreeSet<String>,
    full: bool,
    exhausted: bool,
}
impl<'a> Projection<'a> {
    /// Freeze expected versions and subscribed native names.
    pub fn new(set: &'a DeclarationSet, target: &Target<'_>) -> Result<Self, Error> {
        let manifest = set.manifest();
        let mut expected_versions = BTreeMap::new();
        let mut wanted = BTreeSet::new();
        for kind in [
            DeclarationKind::Activation,
            DeclarationKind::Configuration,
            DeclarationKind::Asset,
            DeclarationKind::Management,
        ] {
            let family = match kind {
                DeclarationKind::Activation => "Activations",
                DeclarationKind::Configuration => "Configurations",
                DeclarationKind::Asset => "Assets",
                DeclarationKind::Management => "Management",
            };
            for item in manifest["Declarations"][family]
                .as_array()
                .ok_or(Error::Encoding)?
            {
                let id = item["Identifier"].as_str().ok_or(Error::Encoding)?;
                let server_token = item["ServerToken"].as_str().ok_or(Error::Encoding)?;
                expected_versions.insert(id.to_string(), server_token.to_string());
                if let Some(document) = set.declaration(kind, id)
                    && document["Type"] == "com.apple.configuration.management.status-subscriptions"
                {
                    for item in document["Payload"]["StatusItems"]
                        .as_array()
                        .ok_or(Error::Field)?
                    {
                        wanted.insert(item["Name"].as_str().ok_or(Error::Field)?.to_string());
                    }
                }
            }
        }
        let claims: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut arrays: BTreeMap<String, ArrayClaims> = BTreeMap::new();
        for name in &wanted {
            let definition = super::super::generated::DEFINITIONS
                .iter()
                .find(|d| d.kind == super::super::Kind::Status && d.identity == name)
                .ok_or(Error::InvalidSchema)?;
            if super::status::incremental_item(definition, target)?.is_some() {
                arrays.insert(name.clone(), ArrayClaims::default());
            }
        }
        let native: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let errors = BTreeSet::new();
        let full = false;
        Ok(Self {
            set,
            expected_versions,
            wanted,
            claims,
            arrays,
            native,
            errors,
            full,
            exhausted: false,
        })
    }
    /// Restore only claims bound by the caller to this exact immutable publication.
    pub fn restore(
        set: &'a DeclarationSet,
        target: &Target<'_>,
        state: ProjectionState,
    ) -> Result<Self, Error> {
        let mut projection = Self::new(set, target)?;
        projection.claims = state.claims;
        projection.arrays.extend(state.arrays);
        projection.native = state.native;
        projection.errors = state.errors;
        projection.full = state.full;
        projection.exhausted = state.exhausted;
        Ok(projection)
    }
    pub fn checkpoint(&self) -> ProjectionState {
        ProjectionState {
            claims: self.claims.clone(),
            arrays: self.arrays.clone(),
            native: self.native.clone(),
            errors: self.errors.clone(),
            full: self.full,
            exhausted: self.exhausted,
        }
    }
    /// Add one immutable report. No insertion or receive order determines recency.
    pub fn observe(&mut self, evidence: &ReportEvidence) -> Result<(), Error> {
        if self.exhausted {
            return Ok(());
        }
        let Self {
            set,
            expected_versions,
            wanted,
            claims,
            arrays,
            native,
            errors,
            full,
            ..
        } = self;
        let report = StatusReport::decode(
            &evidence.report,
            &Target {
                context: &evidence.context,
                access_rights: &[],
            },
        )?;
        let declaration_status = report.declarations()?;
        let reported_versions = declaration_status
            .iter()
            .map(|d| (d.identifier.as_str(), d.server_token.as_str()))
            .collect::<BTreeMap<_, _>>();
        // Only an exact collection version can establish subscribed values.
        let current = !expected_versions.is_empty()
            && expected_versions.iter().all(|(id, token)| {
                reported_versions.get(id.as_str()).copied() == Some(token.as_str())
            });
        *full |= current && report.full_report();
        for name in evidence.subscriptions.intersection(wanted) {
            if let Some(value) = report.items().get(name) {
                if let Some(array) = arrays.get_mut(name) {
                    array.observe(
                        if current { value } else { &Value::Null },
                        current && report.full_report(),
                    )?;
                    continue;
                }
                claim(
                    claims.entry(name.clone()).or_default(),
                    if current {
                        serde_json::to_string(value).map_err(|_| Error::Encoding)?
                    } else {
                        "null".into()
                    },
                );
            } else if report.full_report() {
                if let Some(array) = arrays.get_mut(name) {
                    array.observe(&Value::Null, true)?;
                    continue;
                }
                claim(claims.entry(name.clone()).or_default(), "null".into());
            }
        }
        for error in report.errors() {
            if let Some(name) = error.get("StatusItem").and_then(Value::as_str)
                && wanted.contains(name)
                && evidence.subscriptions.contains(name)
            {
                errors.insert(serde_json::to_string(error).map_err(|_| Error::Encoding)?);
                if let Some(array) = arrays.get_mut(name) {
                    array.observe(&Value::Null, false)?;
                } else {
                    claim(claims.entry(name.into()).or_default(), "null".into());
                }
            }
        }
        {
            // Apple reports management.declarations automatically, without a subscription.
            for status in declaration_status {
                let Some(expected) = set.declaration(status.kind, &status.identifier) else {
                    continue;
                };
                if expected["ServerToken"].as_str() != Some(&status.server_token) {
                    continue;
                }
                let value = json!({"active":status.active,"valid":match status.validity{Validity::Valid=>"valid",Validity::Invalid=>"invalid",Validity::Unknown=>"unknown"},"reasons":status.reasons});
                claim(
                    native.entry(status.identifier).or_default(),
                    serde_json::to_string(&value).map_err(|_| Error::Encoding)?,
                );
            }
        }
        if serde_json::to_vec(&self.checkpoint())
            .map_err(|_| Error::Encoding)?
            .len()
            > PROJECTION_BYTES
        {
            self.claims.clear();
            self.arrays.clear();
            self.native.clear();
            self.errors.clear();
            self.full = false;
            self.exhausted = true;
        }
        Ok(())
    }
    /// Read the consensus without promoting it to setting effects or compliance.
    pub fn finish(self) -> Result<StatusProjection, Error> {
        let Self {
            set,
            claims,
            arrays,
            native,
            errors,
            full,
            ..
        } = self;
        let mut items = BTreeMap::new();
        let mut unknown_items = BTreeSet::new();
        if self.exhausted {
            unknown_items.extend(self.wanted);
            unknown_items.insert("management.declarations".into());
        }
        for (name, values) in claims {
            if values.len() == 1
                && let Some(value) = values.first()
                && value != "null"
            {
                items.insert(
                    name,
                    serde_json::from_str(value).map_err(|_| Error::Encoding)?,
                );
            } else {
                unknown_items.insert(name);
            }
        }
        for (name, array) in arrays {
            if array.full.is_none() && array.objects.is_empty() && !array.absent {
                continue;
            }
            let (value, unknown) = array.finish()?;
            if unknown {
                unknown_items.insert(name.clone());
            }
            items.insert(name, value);
        }
        let mut declarations = Vec::new();
        let manifest = set.manifest();
        for (family, kind) in [
            ("Configurations", DeclarationKind::Configuration),
            ("Assets", DeclarationKind::Asset),
            ("Activations", DeclarationKind::Activation),
            ("Management", DeclarationKind::Management),
        ] {
            for expected in manifest["Declarations"][family]
                .as_array()
                .ok_or(Error::Encoding)?
            {
                let id = expected["Identifier"].as_str().ok_or(Error::Encoding)?;
                let token = expected["ServerToken"].as_str().ok_or(Error::Encoding)?;
                let values = native.get(id);
                let state = if let Some(values) = values
                    && values.len() == 1
                {
                    serde_json::from_str(values.first().ok_or(Error::Encoding)?)
                        .map_err(|_| Error::Encoding)?
                } else {
                    json!({"active":null,"valid":"unknown","reasons":[],"evidence":if self.exhausted{"work_budget_exceeded"}else if values.is_some(){"unordered_conflict"}else{"unobserved"}})
                };
                declarations
                    .push(json!({"identifier":id,"serverToken":token,"kind":kind,"native":state}));
            }
        }
        let synchronized = !declarations.is_empty()
            && declarations.iter().all(|d| d["native"]["valid"] == "valid")
            && !unknown_items.contains("management.declarations");
        Ok(StatusProjection {
            synchronized,
            items,
            unknown_items,
            declarations,
            errors: errors
                .into_iter()
                .map(|v| serde_json::from_str(&v).map_err(|_| Error::Encoding))
                .collect::<Result<_, _>>()?,
            completeness: if full {
                "full_report_observed"
            } else {
                "unknown"
            }
            .into(),
            effect: "unverified".into(),
            compliance: "unknown".into(),
        })
    }
}
/// Interpret a bounded caller-owned collection; streaming callers use Projection directly.
pub fn project(
    set: &DeclarationSet,
    evidence: &[ReportEvidence],
    target: &Target<'_>,
) -> Result<StatusProjection, Error> {
    let mut projection = Projection::new(set, target)?;
    for report in evidence {
        projection.observe(report)?;
    }
    projection.finish()
}

fn claim(values: &mut BTreeSet<String>, value: String) {
    values.insert(value);
    if values.len() > 2 {
        values.pop_last();
    }
}
