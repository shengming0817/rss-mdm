#![allow(
    dead_code,
    reason = "each capability consumes a subset of the shared case coordinates"
)]
//! Required coordinates supplied by the T2 runner before migration and execution.
//! Ordinary objects share a tenant; each full-tenant observation owns its planned domain.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io, path::Path, sync::OnceLock};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseContext {
    case_id: String,
    invocation_id: String,
    namespace: String,
    tenant: String,
    peer: String,
    admin_login: String,
    other_login: String,
    identity_tenants: Vec<String>,
    fixtures: Vec<String>,
    admins: BTreeMap<String, String>,
}

#[derive(Clone, Copy)]
pub enum Phase {
    Preparing,
    Ready,
}

impl CaseContext {
    pub fn read(path: &Path, phase: Phase) -> io::Result<Self> {
        Self::decode(&std::fs::read(path)?, phase)
    }
    pub fn decode(bytes: &[u8], phase: Phase) -> io::Result<Self> {
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate(phase).map_err(|field| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid case context: {field}"),
            )
        })?;
        Ok(value)
    }
    fn validate(&self, phase: Phase) -> Result<(), &'static str> {
        for (field, value) in [
            ("caseId", &self.case_id),
            ("invocationId", &self.invocation_id),
            ("adminLogin", &self.admin_login),
            ("otherLogin", &self.other_login),
        ] {
            if value.is_empty() {
                return Err(field);
            }
        }
        if self.namespace.len() != 32 || !self.namespace.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("namespace");
        }
        for (field, value) in [("tenant", &self.tenant), ("peer", &self.peer)] {
            if uuid::Uuid::parse_str(value).is_err() {
                return Err(field);
            }
        }
        if self.tenant == self.peer {
            return Err("peer");
        }
        if self.identity_tenants != [self.tenant.clone()]
            && self.identity_tenants != [self.tenant.clone(), self.peer.clone()]
        {
            return Err("identityTenants");
        }
        if self.fixtures.iter().any(String::is_empty)
            || self
                .fixtures
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.fixtures.len()
            || self.has_fixture("shared_worker") && self.has_fixture("local_worker")
        {
            return Err("fixtures");
        }
        if self.admins.iter().any(|(tenant, id)| {
            !self.identity_tenants.contains(tenant) || uuid::Uuid::parse_str(id).is_err()
        }) || matches!(phase, Phase::Ready)
            && self.has_fixture("identity")
            && self.admins.len() != self.identity_tenants.len()
        {
            return Err("admins");
        }
        Ok(())
    }
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    pub fn peer(&self) -> &str {
        &self.peer
    }
    pub fn invocation_id(&self) -> &str {
        &self.invocation_id
    }
    pub fn identity_tenants(&self) -> &[String] {
        &self.identity_tenants
    }
    pub fn admin_for(&self, tenant: &str) -> &str {
        self.admins
            .get(tenant)
            .expect("tenant not prepared in validated case context")
    }
    pub fn account_login(&self, kind: &str) -> &str {
        match kind {
            "admin" => &self.admin_login,
            "other" => &self.other_login,
            _ => panic!("unknown fixture account kind"),
        }
    }
    pub fn record_admin(&mut self, tenant: &str, principal: String) -> io::Result<()> {
        if !self.identity_tenants.iter().any(|value| value == tenant)
            || uuid::Uuid::parse_str(&principal).is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid prepared admin",
            ));
        }
        self.admins.insert(tenant.into(), principal);
        Ok(())
    }
    // An optional qualification gate is reached from inside both actual Rust cases.
    // It cannot turn mere fixture preparation or nextest startup overlap into proof.
    #[allow(
        clippy::disallowed_methods,
        reason = "bounded wall clock only for the cross-process T2 qualification gate"
    )]
    fn rendezvous(&self) -> io::Result<()> {
        let Some(directory) = std::env::var_os("MDM_CASE_RENDEZVOUS") else {
            return Ok(());
        };
        let directory = Path::new(&directory);
        let participants: Vec<String> =
            serde_json::from_slice(&std::fs::read(directory.join("participants.json"))?)?;
        if participants.len() != 2
            || participants[0] == participants[1]
            || !participants
                .iter()
                .all(|id| id.len() == 20 && id.bytes().all(|b| b.is_ascii_hexdigit()))
            || !participants.contains(&self.invocation_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid rendezvous participants",
            ));
        }
        std::fs::write(directory.join(&self.invocation_id), [])?;
        let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !participants.iter().all(|id| directory.join(id).is_file()) {
            if std::time::Instant::now() >= end {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "peer did not enter the Rust case",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Ok(())
    }
    fn has_fixture(&self, name: &str) -> bool {
        self.fixtures.iter().any(|value| value == name)
    }
}

pub fn context() -> &'static CaseContext {
    static VALUE: OnceLock<CaseContext> = OnceLock::new();
    VALUE.get_or_init(|| {
        let path =
            std::env::var("MDM_CASE_CONTEXT").expect("make t2 must provide MDM_CASE_CONTEXT");
        let value = CaseContext::read(Path::new(&path), Phase::Ready)
            .expect("validate case context before execution");
        value.rendezvous().expect("reuse qualification rendezvous");
        value
    })
}
pub fn tenant() -> &'static str {
    context().tenant()
}
pub fn peer() -> &'static str {
    context().peer()
}
pub fn admin() -> &'static str {
    context().admin_for(tenant())
}
pub fn login(value: &str) -> &str {
    match value {
        "admin" | "other" => context().account_login(value),
        _ => value,
    }
}

pub fn name(label: &str) -> &'static str {
    // Each test process executes one invocation; the finite fixture labels live with it.
    static NAMES: OnceLock<std::sync::Mutex<std::collections::HashMap<String, &'static str>>> =
        OnceLock::new();
    let mut names = NAMES.get_or_init(Default::default).lock().unwrap();
    names
        .entry(label.into())
        .or_insert_with(|| Box::leak(format!("{}-{label}", context().namespace).into_boxed_str()))
}

pub fn id(label: &str) -> u128 {
    use std::hash::{Hash, Hasher};
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    label.hash(&mut hash);
    let namespace = u128::from_str_radix(&context().namespace, 16).unwrap();
    namespace ^ u128::from(hash.finish())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WorkerOwner {
    Run,
    Case,
    None,
}

pub fn worker_owner() -> WorkerOwner {
    match (
        context().has_fixture("shared_worker"),
        context().has_fixture("local_worker"),
    ) {
        (true, false) => WorkerOwner::Run,
        (false, true) => WorkerOwner::Case,
        (false, false) => WorkerOwner::None,
        (true, true) => panic!("case has conflicting worker owners"),
    }
}

pub fn owns_worker() -> bool {
    match worker_owner() {
        WorkerOwner::Run => false,
        WorkerOwner::Case => true,
        WorkerOwner::None => panic!("worker ownership is missing from case policy"),
    }
}

#[cfg(test)]
mod validation {
    use super::*;
    fn planned() -> serde_json::Value {
        serde_json::json!({"caseId":"case", "invocationId":"invoke", "namespace":"00000000000000000000000000000001",
            "tenant":"11111111-1111-4111-8111-111111111111", "peer":"22222222-2222-4222-8222-222222222222",
            "adminLogin":"admin-1", "otherLogin":"other-1", "identityTenants":["11111111-1111-4111-8111-111111111111"],
            "fixtures":["identity"], "admins":{}})
    }
    #[test]
    fn rejects_malformed_and_incomplete_contract_before_consumption() {
        for field in [
            "caseId",
            "invocationId",
            "namespace",
            "tenant",
            "peer",
            "adminLogin",
            "otherLogin",
            "identityTenants",
            "fixtures",
            "admins",
        ] {
            for replacement in [
                None,
                Some(serde_json::json!(42)),
                Some(serde_json::json!("")),
            ] {
                let mut value = planned();
                if let Some(replacement) = replacement {
                    value[field] = replacement;
                } else {
                    value.as_object_mut().unwrap().remove(field);
                }
                assert!(
                    CaseContext::decode(&serde_json::to_vec(&value).unwrap(), Phase::Preparing)
                        .is_err(),
                    "{field}"
                );
            }
        }
        let bytes = serde_json::to_vec(&planned()).unwrap();
        assert!(CaseContext::decode(&bytes, Phase::Preparing).is_ok());
        assert!(CaseContext::decode(&bytes, Phase::Ready).is_err());
        let mut value = CaseContext::decode(&bytes, Phase::Preparing).unwrap();
        let tenant = value.tenant().to_owned();
        value
            .record_admin(&tenant, "44444444-4444-4444-8444-444444444444".into())
            .unwrap();
        assert!(CaseContext::decode(&serde_json::to_vec(&value).unwrap(), Phase::Ready).is_ok());
        value
            .fixtures
            .extend(["local_worker".into(), "shared_worker".into()]);
        assert!(CaseContext::decode(&serde_json::to_vec(&value).unwrap(), Phase::Ready).is_err());
    }
}
