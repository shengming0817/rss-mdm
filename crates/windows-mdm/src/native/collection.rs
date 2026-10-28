//! Bounded read plans. The channel owns transactions, authorization and wire history.
//! ref: Microsoft Learn win32appinventory-csp, enterprisemodernappmanagement-csp,
//! devicestatus-csp and update-csp (fixed source evidence in schema/collection).
use super::{Context, Error, Request, Scope, Verb};
use crate::CodecLimits;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Closed traversal recipes; each one describes an independently complete namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Inventory {
    /// Win32InstalledProgram records.
    Win32,
    /// Store packages.
    Store,
    /// Non-Store packages.
    NonStore,
    /// System packages.
    System,
    /// DeviceStatus network identifiers.
    Network,
    /// Installed update identities.
    InstalledUpdates,
    /// Applicable uninstalled update identities.
    InstallableUpdates,
    /// Failed update identities and native failure codes.
    FailedUpdates,
    /// Updates awaiting reboot.
    PendingRebootUpdates,
}
impl Inventory {
    fn settings_child(self, depth: usize, child: &str) -> bool {
        // Full enrollment exposes fixed settings across Device/User and signing
        // origins. Build the closed set from Microsoft's existing CSP schema.
        static SETTINGS: std::sync::LazyLock<BTreeSet<&'static str>> =
            std::sync::LazyLock::new(|| {
                super::generated::NODES
                    .iter()
                    .filter_map(
                        |node| match node.path.split('/').collect::<Vec<_>>().as_slice() {
                            [
                                ".",
                                "Device" | "User",
                                "Vendor",
                                "MSFT",
                                "EnterpriseModernAppManagement",
                                "AppManagement",
                                "AppStore" | "nonStore" | "System",
                                "*",
                                name,
                            ] if *name != "*" => Some(*name),
                            _ => None,
                        },
                    )
                    .collect()
            });
        depth == 1
            && matches!(self, Self::Store | Self::NonStore | Self::System)
            && SETTINGS.contains(child)
    }
    /// Exact device namespace root.
    pub fn root(self) -> &'static str {
        match self {
            Self::Win32 => "./Device/Vendor/MSFT/Win32AppInventory/Win32InstalledProgram",
            Self::Store => {
                "./Device/Vendor/MSFT/EnterpriseModernAppManagement/AppManagement/AppStore"
            }
            Self::NonStore => {
                "./Device/Vendor/MSFT/EnterpriseModernAppManagement/AppManagement/nonStore"
            }
            Self::System => {
                "./Device/Vendor/MSFT/EnterpriseModernAppManagement/AppManagement/System"
            }
            Self::Network => "./Vendor/MSFT/DeviceStatus/NetworkIdentifiers",
            Self::InstalledUpdates => "./Vendor/MSFT/Update/InstalledUpdates",
            Self::InstallableUpdates => "./Vendor/MSFT/Update/InstallableUpdates",
            Self::FailedUpdates => "./Vendor/MSFT/Update/FailedUpdates",
            Self::PendingRebootUpdates => "./Vendor/MSFT/Update/PendingRebootUpdates",
        }
    }
    fn depth(self) -> usize {
        if matches!(self, Self::Store | Self::NonStore | Self::System) {
            2
        } else {
            1
        }
    }
    /// Only fields provided by this CSP; absent metadata is never invented.
    pub fn columns(self) -> &'static [&'static str] {
        match self {
            Self::Win32 => &["Name", "Publisher", "Version", "RegKey", "Source"],
            Self::Store | Self::NonStore | Self::System => &[
                "Name",
                "Publisher",
                "Version",
                "Architecture",
                "IsBundle",
                "IsFramework",
                "IsProvisioned",
                "PackageStatus",
                "Users",
            ],
            Self::Network => &["IPAddressV4", "IPAddressV6", "IsConnected", "Type"],
            Self::InstalledUpdates => &["RevisionNumber"],
            Self::InstallableUpdates => &["RevisionNumber", "Type"],
            Self::FailedUpdates => &["RevisionNumber", "HResult", "State"],
            Self::PendingRebootUpdates => &["RevisionNumber", "InstalledTime"],
        }
    }
}
/// One field's native input; field identities remain opaque to the protocol owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Read {
    /// One exact scalar CSP leaf.
    Scalar {
        /// Exact CSP leaf URI.
        uri: String,
    },
    /// One closed dynamic namespace.
    Inventory {
        /// Fixed traversal namespace.
        inventory: Inventory,
    },
    /// Current provider's enrollment identifier.
    EnrollmentId,
    /// Current provider's enrollment type.
    EnrollmentType,
}
/// Immutable, validated read plan. No network command or write verb can be supplied.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "BTreeMap<String, Read>", into = "BTreeMap<String, Read>")]
pub struct Plan(BTreeMap<String, Read>);
impl From<Plan> for BTreeMap<String, Read> {
    fn from(p: Plan) -> Self {
        p.0
    }
}
impl TryFrom<BTreeMap<String, Read>> for Plan {
    type Error = Error;
    fn try_from(reads: BTreeMap<String, Read>) -> Result<Self, Error> {
        if reads.is_empty()
            || reads.len() > 64
            || reads.keys().any(|k| k.len() > 128 || k.is_empty())
        {
            return Err(Error::Limit);
        }
        let plan = Self(reads);
        for read in plan.0.values() {
            if let Read::Scalar { uri } = read {
                let Request::Node { node, .. } = request(uri)? else {
                    return Err(Error::Value);
                };
                let schema = super::generated::NODES
                    .iter()
                    .find(|n| n.path == node)
                    .ok_or(Error::UnknownObject)?;
                if uri.contains("/DMClient/") || schema.format == super::Format::Node {
                    return Err(Error::Value);
                }
            }
        }
        plan.requests()?;
        Ok(plan)
    }
}
fn request(uri: &str) -> Result<Request, Error> {
    Request::from_uri(uri, Verb::Get, None, Scope::Device)
}
impl Plan {
    /// All possible native authorization targets, including dynamic leaf patterns.
    pub fn requests(&self) -> Result<Vec<Request>, Error> {
        let mut out = Vec::new();
        for read in self.0.values() {
            match read {
                Read::Scalar { uri } => out.push(request(uri)?),
                Read::EnrollmentId | Read::EnrollmentType => {
                    out.push(request(&enrollment_uri(read, "inventory-provider"))?)
                }
                Read::Inventory { inventory } => {
                    let mut uri = inventory.root().to_owned();
                    out.push(request(&uri)?);
                    for _ in 0..inventory.depth() {
                        uri.push_str("/inventory-instance");
                        out.push(request(&uri)?);
                    }
                    for column in inventory.columns() {
                        out.push(request(&format!("{uri}/{column}"))?);
                    }
                }
            }
        }
        Ok(out)
    }
    /// Check the entire plan against authenticated platform evidence.
    pub fn applicable(&self, context: Context) -> Result<(), Error> {
        for q in self.requests()? {
            q.compile(context, 1)?;
        }
        Ok(())
    }
    /// Initialize collection progress without emitting protocol commands.
    pub fn start(&self, provider: &str) -> Result<State, Error> {
        if provider.is_empty() || provider.len() > 128 {
            return Err(Error::Identity);
        }
        let steps = self
            .0
            .iter()
            .map(|(field, read)| {
                Step::new(
                    field,
                    match read {
                        Read::Scalar { uri } => uri.clone(),
                        Read::EnrollmentId | Read::EnrollmentType => enrollment_uri(read, provider),
                        Read::Inventory { inventory } => inventory.root().into(),
                    },
                    match read {
                        Read::Scalar { .. } | Read::EnrollmentId | Read::EnrollmentType => {
                            Purpose::Scalar
                        }
                        Read::Inventory { .. } => Purpose::Enumerate { depth: 0 },
                    },
                )
            })
            .collect();
        Ok(State {
            steps,
            failed: BTreeMap::new(),
            verified: BTreeSet::new(),
            delivered: BTreeSet::new(),
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Purpose {
    Scalar,
    Enumerate { depth: usize },
    Leaf { item: String, column: String },
    Verify { expected: BTreeSet<String> },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    field: String,
    uri: String,
    purpose: Purpose,
    sent: Option<(u32, u32)>,
    status: Option<u16>,
    value: Option<String>,
    advanced: bool,
}
impl Step {
    fn new(field: &str, uri: String, purpose: Purpose) -> Self {
        Self {
            field: field.into(),
            uri,
            purpose,
            sent: None,
            status: None,
            value: None,
            advanced: false,
        }
    }
    fn complete(&self) -> bool {
        self.status
            .is_some_and(|s| s >= 400 || matches!(s, 200 | 214) && self.value.is_some())
    }
}
/// Persist only collection progress. Wire correlation/MoreData belongs to the session transcript.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    steps: Vec<Step>,
    failed: BTreeMap<String, u16>,
    verified: BTreeSet<String>,
    delivered: BTreeSet<String>,
}
/// Terminal native field outcome, before product type conversion.
pub enum Outcome {
    /// Complete native value awaiting product type conversion.
    Value(serde_json::Value),
    /// Native failure or unsupported status, never a deletion.
    Status(u16),
}
impl State {
    /// Restart unfinished fields under a fresh session without mixing partial inventories.
    /// Completed field outputs remain delivered and cannot be published a second time.
    pub fn resume(&self, plan: &Plan, provider: &str) -> Result<Self, Error> {
        let mut next = plan.start(provider)?;
        next.steps
            .retain(|step| !self.delivered.contains(&step.field));
        next.steps.extend(
            self.steps
                .iter()
                .filter(|step| self.delivered.contains(&step.field))
                .cloned(),
        );
        next.delivered = self.delivered.clone();
        next.verified = self
            .verified
            .intersection(&self.delivered)
            .cloned()
            .collect();
        next.failed = self
            .failed
            .iter()
            .filter(|(field, _)| self.delivered.contains(*field))
            .map(|(field, status)| (field.clone(), *status))
            .collect();
        Ok(next)
    }

    /// Whether a wire command was actually emitted by this collection.
    pub fn owns(&self, message: u32, command: u32) -> bool {
        self.steps
            .iter()
            .any(|s| s.sent == Some((message, command)))
    }
    /// Whether a cached server message contains reads owned by this plan.
    pub fn sent_in(&self, message: u32) -> bool {
        self.steps
            .iter()
            .any(|s| s.sent.is_some_and(|(m, _)| m == message))
    }
    /// Whether any nonfailed field still requires a response.
    pub fn pending(&self) -> bool {
        self.steps
            .iter()
            .any(|s| !s.complete() && !self.failed.contains_key(&s.field))
    }
    /// Number of queued steps not yet emitted.
    pub fn unsent(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| s.sent.is_none() && !self.failed.contains_key(&s.field))
            .count()
    }
    /// Bind one actual command only after the enclosing response fits its negotiated wire budget.
    pub fn next(&self) -> Result<Option<(usize, Request)>, Error> {
        self.steps
            .iter()
            .enumerate()
            .find(|(_, s)| s.sent.is_none() && !self.failed.contains_key(&s.field))
            .map(|(i, s)| Ok((i, request(&s.uri)?)))
            .transpose()
    }
    /// Bind an emitted command to its collection step.
    pub fn sent(&mut self, step: usize, message: u32, command: u32) -> Result<(), Error> {
        let s = self.steps.get_mut(step).ok_or(Error::Identity)?;
        if s.sent.is_some() {
            return Err(Error::Identity);
        }
        s.sent = Some((message, command));
        Ok(())
    }
    /// Record a correlated status, rejecting conflicting retransmissions.
    pub fn status(&mut self, message: u32, command: u32, status: u16) -> Result<(), Error> {
        let s = self
            .steps
            .iter_mut()
            .find(|s| s.sent == Some((message, command)))
            .ok_or(Error::Identity)?;
        if s.status.is_some_and(|old| old != status)
            || s.value.is_some() && !matches!(status, 200 | 214)
        {
            return Err(Error::Value);
        }
        s.status = Some(status);
        Ok(())
    }
    /// Record a correlated complete value with exact native URI identity.
    pub fn value(
        &mut self,
        message: u32,
        command: u32,
        uri: &str,
        value: String,
    ) -> Result<(), Error> {
        let s = self
            .steps
            .iter_mut()
            .find(|s| s.sent == Some((message, command)))
            .ok_or(Error::Identity)?;
        let expected = request(&s.uri)?.objects()?.pop().ok_or(Error::Identity)?;
        if expected.key() != uri
            || s.value.as_ref().is_some_and(|old| *old != value)
            || s.status.is_some_and(|code| !matches!(code, 200 | 214))
        {
            return Err(Error::Value);
        }
        s.value = Some(value);
        Ok(())
    }
    /// Expand only authenticated completed reads. A failed child invalidates the whole field.
    pub fn advance(&mut self, plan: &Plan, output_bytes: usize) -> Result<(), Error> {
        let mut added = Vec::new();
        let step_count = self.steps.len();
        for step in &mut self.steps {
            if self.failed.contains_key(&step.field) || step.advanced || !step.complete() {
                continue;
            }
            step.advanced = true;
            if !matches!(step.status, Some(200 | 214)) {
                self.failed
                    .insert(step.field.clone(), step.status.unwrap_or(500));
                continue;
            }
            let raw = step.value.as_deref().ok_or(Error::Value)?;
            match &step.purpose {
                Purpose::Enumerate { depth } => {
                    let children = match children(raw) {
                        Ok(v) => v,
                        Err(_) => {
                            self.failed.insert(step.field.clone(), 500);
                            continue;
                        }
                    };
                    let Some(Read::Inventory { inventory }) = plan.0.get(&step.field) else {
                        return Err(Error::Identity);
                    };
                    for child in &children {
                        let uri = format!("{}/{}", step.uri, child);
                        // Interior nodes also enumerate fixed settings. Only schema-declared
                        // dynamic identities belong to the inventory namespace.
                        let Ok(Request::Node { node, .. }) = request(&uri) else {
                            self.failed.insert(step.field.clone(), 500);
                            break;
                        };
                        if !node.ends_with("/*") || inventory.settings_child(*depth, child) {
                            continue;
                        }
                        if added.len() + step_count + inventory.columns().len()
                            > CodecLimits::default().session_commands
                        {
                            self.failed.insert(step.field.clone(), 500);
                            break;
                        }
                        if depth + 1 < inventory.depth() {
                            added.push(Step::new(
                                &step.field,
                                uri,
                                Purpose::Enumerate { depth: depth + 1 },
                            ));
                        } else {
                            for column in inventory.columns() {
                                added.push(Step::new(
                                    &step.field,
                                    format!("{uri}/{column}"),
                                    Purpose::Leaf {
                                        item: uri.clone(),
                                        column: (*column).into(),
                                    },
                                ));
                            }
                        }
                    }
                }
                Purpose::Verify { expected } if children(raw).as_ref() != Ok(expected) => {
                    self.failed.insert(step.field.clone(), 500);
                }
                _ => (),
            }
        }
        self.steps.extend(added);
        self.verify_completed(plan)?;
        let limits = CodecLimits::default();
        if self.steps.len() > limits.session_commands
            || self
                .steps
                .iter()
                .filter_map(|s| s.value.as_ref())
                .map(String::len)
                .sum::<usize>()
                > output_bytes
            || serde_json::to_vec(self).map_err(|_| Error::Value)?.len() > limits.object_bytes
        {
            // Freeze failure rather than rolling back and repeatedly accepting oversized input.
            for field in plan.0.keys() {
                self.failed.insert(field.clone(), 500);
            }
            self.steps.retain(|s| s.sent.is_some());
            for s in &mut self.steps {
                s.value = None;
            }
        }
        Ok(())
    }
    fn verify_completed(&mut self, plan: &Plan) -> Result<(), Error> {
        for (field, read) in &plan.0 {
            if !matches!(read, Read::Inventory { .. })
                || self.failed.contains_key(field)
                || self.verified.contains(field)
            {
                continue;
            }
            if self
                .steps
                .iter()
                .filter(|s| &s.field == field)
                .all(Step::complete)
            {
                let checks = self
                    .steps
                    .iter()
                    .filter(|s| &s.field == field && matches!(s.purpose, Purpose::Enumerate { .. }))
                    .map(|s| {
                        Ok(Step::new(
                            field,
                            s.uri.clone(),
                            Purpose::Verify {
                                expected: children(s.value.as_deref().ok_or(Error::Value)?)?,
                            },
                        ))
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                self.steps.extend(checks);
                self.verified.insert(field.clone());
            }
        }
        Ok(())
    }
    /// Available terminal outputs; successful lists require the final verification pass.
    pub fn outcomes(&mut self, plan: &Plan) -> Result<BTreeMap<String, Outcome>, Error> {
        let mut out = BTreeMap::new();
        for (field, read) in &plan.0 {
            if self.delivered.contains(field) {
                continue;
            }
            if let Some(status) = self.failed.get(field) {
                out.insert(field.clone(), Outcome::Status(*status));
                continue;
            }
            let steps: Vec<_> = self.steps.iter().filter(|s| &s.field == field).collect();
            if !steps.iter().all(|s| s.complete()) {
                continue;
            }
            let value = match read {
                Read::Scalar { .. } | Read::EnrollmentId | Read::EnrollmentType => {
                    serde_json::Value::String(steps[0].value.clone().ok_or(Error::Value)?)
                }
                Read::Inventory { inventory } => {
                    if !self.verified.contains(field) {
                        continue;
                    }
                    let mut rows: BTreeMap<String, serde_json::Map<String, serde_json::Value>> =
                        BTreeMap::new();
                    for s in steps {
                        if let Purpose::Leaf { item, column } = &s.purpose {
                            rows.entry(item.clone()).or_default().insert(
                                column.clone(),
                                s.value.clone().ok_or(Error::Value)?.into(),
                            );
                        }
                    }
                    serde_json::Value::Array(
                        rows.into_iter()
                            .map(|(id, mut row)| {
                                // The CSP declares an integer; Windows also returns 2.
                                // Preserve the raw leaf, deriving only documented 0/1.
                                match row.get("IsProvisioned").and_then(|v| v.as_str()) {
                                    Some("0") => {
                                        row.insert("IsProvisionedBoolean".into(), false.into());
                                    }
                                    Some("1") => {
                                        row.insert("IsProvisionedBoolean".into(), true.into());
                                    }
                                    _ => (),
                                }
                                row.insert("id".into(), id.into());
                                row.insert("origin".into(), inventory.root().into());
                                row.insert("collection_scope".into(), "device".into());
                                row.insert("installation_scope".into(), "unknown".into());
                                serde_json::Value::Object(row)
                            })
                            .collect(),
                    )
                }
            };
            out.insert(field.clone(), Outcome::Value(value));
        }
        self.delivered.extend(out.keys().cloned());
        Ok(out)
    }
}
fn children(raw: &str) -> Result<BTreeSet<String>, Error> {
    if raw.is_empty() {
        return Ok(BTreeSet::new());
    }
    let mut out = BTreeSet::new();
    for child in raw.split('/') {
        let decoded = percent_encoding::percent_decode_str(child)
            .decode_utf8()
            .map_err(|_| Error::Identity)?;
        if decoded.is_empty()
            || matches!(decoded.as_ref(), "." | "..")
            || decoded.len() > 256
            || decoded
                .chars()
                .any(|c| c.is_control() || matches!(c, '/' | '\\' | '?' | '#' | '%'))
        {
            return Err(Error::Identity);
        }
        let canonical =
            percent_encoding::utf8_percent_encode(&decoded, percent_encoding::NON_ALPHANUMERIC)
                .to_string();
        if !out.insert(canonical) || out.len() > CodecLimits::default().session_commands {
            return Err(Error::Limit);
        }
    }
    Ok(out)
}

fn enrollment_uri(read: &Read, provider: &str) -> String {
    let provider =
        percent_encoding::utf8_percent_encode(provider, percent_encoding::NON_ALPHANUMERIC);
    format!(
        "./Device/Vendor/MSFT/DMClient/Provider/{provider}/{}",
        if matches!(read, Read::EnrollmentId) {
            "EntDMID"
        } else {
            "EnrollmentType"
        }
    )
}

#[cfg(test)]
mod receipt_tests {
    use super::*;

    fn pending_read() -> State {
        let mut step = Step::new("version", "./DevDetail/SwV".into(), Purpose::Scalar);
        step.sent = Some((2, 1024));
        State {
            steps: vec![step],
            failed: BTreeMap::new(),
            verified: BTreeSet::new(),
            delivered: BTreeSet::new(),
        }
    }

    #[test]
    fn resume_preserves_delivered_fields_but_restarts_unfinished_inventory() {
        let plan = Plan::try_from(BTreeMap::from([
            (
                "version".into(),
                Read::Scalar {
                    uri: "./DevDetail/SwV".into(),
                },
            ),
            (
                "software".into(),
                Read::Inventory {
                    inventory: Inventory::Win32,
                },
            ),
        ]))
        .unwrap();
        let mut state = plan.start("provider").unwrap();
        let version = state
            .steps
            .iter_mut()
            .find(|s| s.field == "version")
            .unwrap();
        version.sent = Some((2, 1024));
        version.status = Some(214);
        version.value = Some("10.0".into());
        version.advanced = true;
        state.delivered.insert("version".into());
        let software = state
            .steps
            .iter_mut()
            .find(|s| s.field == "software")
            .unwrap();
        software.sent = Some((2, 1025));
        software.status = Some(200);
        software.value = Some("old-child".into());
        let resumed = state.resume(&plan, "provider").unwrap();
        assert!(resumed.delivered.contains("version"));
        assert_eq!(resumed.unsent(), 1);
        let software = resumed
            .steps
            .iter()
            .find(|s| s.field == "software")
            .unwrap();
        assert!(software.sent.is_none() && software.status.is_none() && software.value.is_none());
        assert!(state.owns(2, 1025), "old binding remains intact for replay");
    }

    #[test]
    fn stopped_get_requires_a_complete_correlated_value() {
        let mut state = pending_read();
        state.status(2, 1024, 214).unwrap();
        assert!(state.pending());
        assert!(
            state
                .value(2, 1025, "./DevDetail/SwV", "10.0".into())
                .is_err()
        );
        state
            .value(2, 1024, "./DevDetail/SwV", "10.0".into())
            .unwrap();
        assert!(!state.pending());
        assert!(
            state
                .value(2, 1024, "./DevDetail/SwV", "11.0".into())
                .is_err()
        );
        assert!(state.status(2, 1024, 200).is_err());
    }

    #[test]
    fn stopped_get_accepts_value_before_status_without_relaxing_failures() {
        let mut state = pending_read();
        state
            .value(2, 1024, "./DevDetail/SwV", "10.0".into())
            .unwrap();
        assert!(state.pending());
        assert!(state.status(2, 1024, 500).is_err());
        state.status(2, 1024, 214).unwrap();
        assert!(!state.pending());
    }
}
