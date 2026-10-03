//! Readback evidence for queryable native mutations. ACKs never satisfy this contract.
use super::{Context, Error, Operation, Request, Verb};
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
    /// Full result must match the immutable desired document and native operation.
    Declared {
        /// Immutable desired identity, version and resources.
        document: super::declared::Document,
        /// Expected native Set, Get or Delete lifecycle.
        operation: String,
    },
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
        verification.assess(facts)
    }
}
impl Verification {
    fn assess(&self, facts: &[EffectFact]) -> EffectAssessment {
        if facts
            .iter()
            .any(|f| f.uri.is_empty() && (!f.receipt_accepted || f.status != Some(200)))
        {
            return EffectAssessment::waiting("incomplete_group_evidence");
        }
        if facts
            .iter()
            .any(|f| !f.uri.is_empty() && !self.expected.contains_key(&f.uri))
        {
            return EffectAssessment::waiting("unexpected_object_evidence");
        }
        for (uri, expected) in &self.expected {
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
            let matches = if let Expected::Declared {
                document,
                operation,
            } = expected
            {
                let result = fact
                    .value
                    .as_deref()
                    .filter(|_| fact.status == Some(200))
                    .and_then(|xml| super::declared::ResultDocument::parse(xml).ok());
                if result
                    .as_ref()
                    .is_some_and(|result| result.in_progress(document, operation))
                {
                    return EffectAssessment::waiting("declared_operation_in_progress");
                }
                result.is_some_and(|result| result.converged(document, operation))
            } else {
                expected.matches(fact.status, fact.value.as_deref())
            };
            if !matches {
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
        Ok(self.resolve()?.prepare(context)?.effect)
    }
}
impl Expected {
    /// Interpret a correlated Get only; missing results and protocol failures remain unverified.
    pub fn matches(&self, status: Option<i32>, value: Option<&str>) -> bool {
        match self {
            Self::Declared {
                document,
                operation,
            } => {
                status == Some(200)
                    && value
                        .and_then(|xml| super::declared::ResultDocument::parse(xml).ok())
                        .is_some_and(|result| result.converged(document, operation))
            }
            Self::Absent => status == Some(404) && value.is_none(),
            Self::Present => status == Some(200) && value.is_some(),
            Self::Value(expected) => status == Some(200) && value == Some(expected.as_str()),
        }
    }
}

impl Request {
    /// DMAcc dynamic names are not provider IDs. Prove their ServerID before reading
    /// credentials or changing account state, using the same operation's Prepare attempt.
    pub fn enrollment_binding(
        &self,
        provider: &str,
        context: Context,
    ) -> Result<Option<Verification>, Error> {
        self.command_count()?;
        let mut pending = vec![self];
        let mut accounts = BTreeMap::new();
        while let Some(request) = pending.pop() {
            match request {
                Self::Atomic { operations } | Self::Sequence { operations } => {
                    pending.extend(operations)
                }
                Self::Node { node, instance, .. } if node.starts_with("./SyncML/DMAcc/*") => {
                    let account = instance.first().ok_or(Error::Identity)?;
                    let path = "./SyncML/DMAcc/*/ServerID";
                    let op = Operation::compile(
                        path,
                        std::slice::from_ref(account),
                        Verb::Get,
                        None,
                        context,
                    )?;
                    accounts.insert(
                        op.uri().to_owned(),
                        Self::Node {
                            node: path.into(),
                            instance: vec![account.clone()],
                            operation: Verb::Get,
                            value: None,
                        },
                    );
                }
                _ => {}
            }
        }
        if accounts.is_empty() {
            return Ok(None);
        }
        let expected = accounts
            .keys()
            .map(|uri| (uri.clone(), Expected::Value(provider.into())))
            .collect();
        let mut operations = accounts.into_values().collect::<Vec<_>>();
        let request = if operations.len() == 1 {
            operations.remove(0)
        } else {
            Self::Sequence { operations }
        };
        Ok(Some(Verification { request, expected }))
    }
}

impl Request {
    /// Desired connection addresses, in the native list syntax. Discovery upgrades
    /// have a different enrollment lifecycle and are deliberately not conflated here.
    pub fn management_addresses(&self) -> Result<Vec<String>, Error> {
        self.command_count()?;
        let mut pending = vec![self];
        let mut addresses = BTreeMap::new();
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
                    ..
                } if matches!(operation, Verb::Add | Verb::Replace)
                    && ((node.contains("/DMClient/Provider/*/")
                        && (node.ends_with("/ManagementServerAddressList")
                            || node.ends_with("/ManagementServiceAddress")))
                        || node == "./SyncML/DMAcc/*/AppAddr/*/Addr") =>
                {
                    let Some(super::Value::Text(value)) = value else {
                        return Err(Error::Value);
                    };
                    let mut remaining = value.trim();
                    let mut values = Vec::new();
                    if remaining.starts_with('<') {
                        while !remaining.is_empty() {
                            let body = remaining.strip_prefix('<').ok_or(Error::Value)?;
                            let (url, rest) = body.split_once('>').ok_or(Error::Value)?;
                            values.push(url.to_owned());
                            remaining = rest.trim();
                            if values.len() > 16 {
                                return Err(Error::Limit);
                            }
                        }
                    } else {
                        values.push(remaining.to_owned());
                    }
                    if values.iter().any(|u| {
                        u.len() > 4096
                            || !u.starts_with("https://")
                            || u.bytes()
                                .any(|b| b.is_ascii_whitespace() || b == b'<' || b == b'>')
                    }) {
                        return Err(Error::Value);
                    }
                    // Every dynamic address object is independently authorized. Repeated writes
                    // to one object make the intended reconnect endpoint ambiguous.
                    if addresses.insert((node, instance), values).is_some() {
                        return Err(Error::Value);
                    }
                }
                _ => {}
            }
        }
        Ok(addresses.into_values().flatten().collect())
    }
}

/// Result versions keyed by exact readback URI; tuple encoding retains existing attempt storage.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct DeclaredVersions(BTreeMap<String, (String, u32)>);
impl Verification {
    /// Matching summaries only request a read; their progress never proves an effect.
    pub fn declared_versions(
        &self,
        summaries: &[super::declared::Summary],
    ) -> Option<DeclaredVersions> {
        let mut declared = false;
        let mut versions = BTreeMap::new();
        for (uri, expected) in &self.expected {
            if let Expected::Declared { document, .. } = expected {
                declared = true;
                if let Some(summary) = summaries.iter().find(|s| {
                    s.id == document.identity.id
                        && s.scope == document.identity.scope
                        && s.checksum == document.identity.checksum
                }) {
                    versions.insert(
                        uri.clone(),
                        (summary.result_checksum.clone(), summary.state),
                    );
                }
            }
        }
        declared.then_some(DeclaredVersions(versions))
    }
    /// A live query remains correlatable; a new session may retry abandoned work.
    pub fn declared_query_needed(
        &self,
        facts: &[EffectFact],
        queried: Option<&DeclaredVersions>,
        current: &DeclaredVersions,
        same_session: bool,
    ) -> bool {
        if self.assess(facts).state == EffectState::Verified {
            return false;
        }
        if !observation_complete(facts) || current.0.is_empty() {
            return !same_session;
        }
        current.0.iter().any(|(uri, version)| {
            if queried.and_then(|q| q.0.get(uri)) == Some(version) {
                return false;
            }
            let consumed = facts.iter().find(|f| &f.uri == uri).and_then(|fact| {
                if !fact.receipt_accepted || !fact.result_accepted || fact.status != Some(200) {
                    return None;
                }
                let Expected::Declared {
                    document,
                    operation,
                } = self.expected.get(uri)?
                else {
                    return None;
                };
                let result = super::declared::ResultDocument::parse(fact.value.as_deref()?).ok()?;
                (result.identity == document.identity && &result.operation == operation)
                    .then_some((result.result_checksum, result.state))
            });
            consumed.as_ref() != Some(version)
        })
    }
}
fn observation_complete(facts: &[EffectFact]) -> bool {
    use super::receipt::{CommandKind, ItemEvidence, ReceiptRole};
    !facts.is_empty()
        && facts.iter().all(|f| {
            ItemEvidence {
                phase: ReceiptRole::Observe,
                kind: if f.uri.is_empty() {
                    CommandKind::Atomic
                } else {
                    CommandKind::Get
                },
                status: f.status,
                receipt_accepted: f.receipt_accepted,
                has_value: f.value.is_some(),
                result_accepted: f.result_accepted,
            }
            .complete()
        })
}
