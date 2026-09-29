#![allow(
    dead_code,
    reason = "each capability consumes a subset of the shared case coordinates"
)]
//! Required coordinates supplied by the T2 runner before migration and execution.
//! Ordinary objects share a tenant; each full-tenant observation owns its planned domain.
use std::sync::OnceLock;

pub fn context() -> &'static serde_json::Value {
    static VALUE: OnceLock<serde_json::Value> = OnceLock::new();
    VALUE.get_or_init(|| {
        let path =
            std::env::var("MDM_CASE_CONTEXT").expect("make t2 must provide MDM_CASE_CONTEXT");
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).expect("read case context"))
                .expect("decode case context");
        for key in ["caseId", "invocationId", "namespace", "tenant", "peer"] {
            assert!(
                value[key].as_str().is_some_and(|v| !v.is_empty()),
                "missing case coordinate {key}"
            );
        }
        value
    })
}

pub fn tenant() -> &'static str {
    context()["tenant"].as_str().unwrap()
}

pub fn peer() -> &'static str {
    context()["peer"].as_str().unwrap()
}

pub fn admin() -> &'static str {
    context()["admin"]
        .as_str()
        .expect("case account was not prepared")
}

pub fn login(value: &str) -> &str {
    match value {
        "admin" => context()["adminLogin"]
            .as_str()
            .expect("case admin was not prepared"),
        "other" => context()["otherLogin"].as_str().unwrap(),
        _ => value,
    }
}

pub fn name(label: &str) -> &'static str {
    // Each test process executes one invocation; the finite fixture labels live with it.
    static NAMES: OnceLock<std::sync::Mutex<std::collections::HashMap<String, &'static str>>> =
        OnceLock::new();
    let mut names = NAMES.get_or_init(Default::default).lock().unwrap();
    names.entry(label.into()).or_insert_with(|| {
        Box::leak(format!("{}-{label}", context()["namespace"].as_str().unwrap()).into_boxed_str())
    })
}

pub fn id(label: &str) -> u128 {
    use std::hash::{Hash, Hasher};
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    label.hash(&mut hash);
    let namespace = u128::from_str_radix(context()["namespace"].as_str().unwrap(), 16).unwrap();
    namespace ^ u128::from(hash.finish())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WorkerOwner {
    Run,
    Case,
    None,
}

pub fn worker_owner() -> WorkerOwner {
    let fixtures = context()["fixtures"].as_array().expect("case fixtures");
    match (
        fixtures.iter().any(|v| v == "shared_worker"),
        fixtures.iter().any(|v| v == "local_worker"),
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
