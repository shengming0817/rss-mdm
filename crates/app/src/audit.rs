//! Closed, credential-free audit facts shared by request finalization and transactions.
//! ref: Rust 1.89.0 library/std/src/sync/poison/mutex.rs
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct Audit(Arc<Context>);
struct Context {
    request_id: Uuid,
    tenant: String,
    state: Mutex<State>,
}
struct State {
    snapshot: Snapshot,
    finalized: bool,
}
#[derive(Clone)]
pub(crate) struct Snapshot {
    pub actor: Option<String>,
    pub instance: Option<String>,
    pub action: &'static str,
    pub target: Option<String>,
    pub operation_id: Option<Uuid>,
    pub registration_id: Option<Uuid>,
    pub write_outcome: WriteOutcome,
    pub software: Option<SoftwareFact>,
    pub management_result: Option<ManagementResult>,
}
#[derive(Clone, Copy)]
pub(crate) enum ManagementResult {
    Performed,
    Replayed,
    Unknown,
}
impl ManagementResult {
    pub fn audit_tag(self) -> &'static str {
        match self {
            Self::Performed => "success",
            Self::Replayed => "replay",
            Self::Unknown => "unknown",
        }
    }
}
/// Product operation projection containing identifiers/digests only, never source content.
#[derive(Clone, serde::Serialize)]
pub(crate) struct SoftwareFact {
    pub operation: String,
    pub publication: Option<String>,
    pub attempt: Option<u64>,
    pub ring: Option<u8>,
    pub binding: Option<String>,
    pub stage: &'static str,
    pub outcome: &'static str,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WriteOutcome {
    CommitNotStarted,
    Unknown,
    Committed,
}
impl WriteOutcome {
    pub fn deadline_error(self) -> crate::Error {
        match self {
            Self::Unknown | Self::Committed => crate::Error::CommitUnknown,
            Self::CommitNotStarted => crate::Error::Unavailable(crate::Failure::RequestDeadline),
        }
    }
}
#[derive(Clone, Copy, serde::Serialize)]
pub(crate) enum FailureReason {
    #[serde(rename = "persistent_audit_unavailable")]
    Persistent,
    #[serde(rename = "transaction_audit_failed")]
    Transaction,
    #[serde(rename = "audit_finalization_cancelled")]
    Cancelled,
}
impl Audit {
    pub fn new(tenant: String, action: &'static str) -> Self {
        Self(Arc::new(Context {
            request_id: Uuid::new_v4(),
            tenant,
            state: Mutex::new(State {
                snapshot: Snapshot {
                    actor: None,
                    instance: None,
                    action,
                    target: None,
                    operation_id: None,
                    registration_id: None,
                    write_outcome: WriteOutcome::CommitNotStarted,
                    software: None,
                    management_result: None,
                },
                finalized: false,
            }),
        }))
    }
    pub(crate) fn transaction_copy(&self) -> Self {
        Self(Arc::new(Context {
            request_id: self.0.request_id,
            tenant: self.0.tenant.clone(),
            state: Mutex::new(State {
                snapshot: self.snapshot(),
                finalized: false,
            }),
        }))
    }
    pub fn request_id(&self) -> Uuid {
        self.0.request_id
    }
    pub fn tenant(&self) -> &str {
        &self.0.tenant
    }
    pub fn snapshot(&self) -> Snapshot {
        self.0.state.lock().expect("audit lock").snapshot.clone()
    }
    pub fn identify(&self, proof: &crate::identity::Principal) {
        let mut state = self.0.state.lock().expect("audit lock");
        state.snapshot.actor = Some(proof.principal_id().into());
        state.snapshot.instance = Some(proof.instance_id().into());
    }
    #[cfg(test)]
    pub fn identify_fixture(&self, actor: &str, instance: &str) {
        let mut state = self.0.state.lock().expect("audit lock");
        state.snapshot.actor = Some(actor.into());
        state.snapshot.instance = Some(instance.into());
    }
    pub(crate) fn identify_operator(&self, actor: &str, instance: &str) {
        let mut state = self.0.state.lock().expect("audit lock");
        state.snapshot.actor = Some(actor.into());
        state.snapshot.instance = Some(instance.into());
    }
    pub(crate) fn identify_service(&self, actor: &str) {
        let mut state = self.0.state.lock().expect("audit lock");
        state.snapshot.actor = Some(actor.into());
        state.snapshot.instance = None;
    }
    pub(crate) fn software(&self, fact: SoftwareFact) {
        self.0.state.lock().expect("audit lock").snapshot.software = Some(fact);
    }
    pub fn set_action(&self, action: &'static str) {
        self.0.state.lock().expect("audit lock").snapshot.action = action;
    }
    pub fn target(&self, target: &str) {
        self.0.state.lock().expect("audit lock").snapshot.target = (target.len() <= 256
            && rss_observation::Id::new(target).is_ok())
        .then(|| target.to_owned());
    }
    pub fn operation(&self, id: Uuid, action: &'static str) {
        let mut state = self.0.state.lock().expect("audit lock");
        state.snapshot.operation_id = Some(id);
        state.snapshot.action = action;
    }
    pub fn identify_device(&self, registration: Uuid) {
        let mut state = self.0.state.lock().expect("audit lock");
        state.snapshot.actor = Some(format!("device:{registration}"));
        state.snapshot.instance = None;
    }
    pub fn registration(&self, id: Uuid) {
        self.0
            .state
            .lock()
            .expect("audit lock")
            .snapshot
            .registration_id = Some(id);
    }
    pub fn management_result(&self, result: ManagementResult) {
        self.0
            .state
            .lock()
            .expect("audit lock")
            .snapshot
            .management_result = Some(result);
    }
    pub fn mark_commit_started(&self) {
        let mut state = self.0.state.lock().expect("audit lock");
        if state.snapshot.write_outcome == WriteOutcome::CommitNotStarted {
            state.snapshot.write_outcome = WriteOutcome::Unknown;
        }
    }
    pub fn mark_committed(&self) {
        let mut state = self.0.state.lock().expect("audit lock");
        assert_eq!(state.snapshot.write_outcome, WriteOutcome::Unknown);
        state.snapshot.write_outcome = WriteOutcome::Committed;
    }
    pub fn finalize(&self, failure: Option<FailureReason>) {
        let event = {
            let mut state = self.0.state.lock().expect("audit lock");
            if state.finalized {
                return;
            }
            state.finalized = true;
            failure.map(|reason| self.0.failure_event(&state.snapshot, reason))
        };
        if let Some(event) = event {
            eprintln!("{event}");
        }
    }
}
impl Context {
    fn failure_event(&self, snapshot: &Snapshot, reason: FailureReason) -> serde_json::Value {
        serde_json::json!({"event":"audit_failure","severity":"error","request_id":self.request_id,"operation_id":snapshot.operation_id,"registration_id":snapshot.registration_id,"action":snapshot.action,"reason":reason,"write_outcome":snapshot.write_outcome})
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        // Drop must still report cancellation if another thread poisoned the lock.
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if !state.finalized {
            eprintln!(
                "{}",
                self.failure_event(&state.snapshot, FailureReason::Cancelled)
            );
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_rejects_values_that_cannot_be_persisted() {
        let audit = Audit::new("tenant".into(), "collection_read");
        for invalid in ["x".repeat(257), "bad\nvalue".into(), String::new()] {
            audit.target(&invalid);
            assert!(audit.snapshot().target.is_none());
        }
        audit.target(&"x".repeat(256));
        assert!(audit.snapshot().target.is_some());
        audit.finalize(None);
    }
    #[test]
    fn cancellation_preserves_operation_and_distinguishes_commit_phase() {
        let a = Audit::new("tenant".into(), "enrollment_create");
        let key = Uuid::new_v4();
        let registration = Uuid::new_v4();
        a.operation(key, "enrollment_create");
        a.registration(registration);
        a.target("sensitive-target-not-for-logs");
        a.identify_fixture("sensitive-actor", "sensitive-instance");
        let event = |reason| a.0.failure_event(&a.snapshot(), reason);
        assert_eq!(
            event(FailureReason::Cancelled)["write_outcome"],
            "commit_not_started"
        );
        a.mark_commit_started();
        let unknown = event(FailureReason::Cancelled);
        assert_eq!(unknown["write_outcome"], "unknown");
        assert_eq!(unknown["operation_id"], key.to_string());
        a.mark_committed();
        a.mark_commit_started(); // A repeated notification cannot regress a known commit.
        for reason in [
            FailureReason::Cancelled,
            FailureReason::Persistent,
            FailureReason::Transaction,
        ] {
            let event = event(reason);
            assert_eq!(event["write_outcome"], "committed");
            assert_eq!(event["action"], "enrollment_create");
            assert_eq!(event["registration_id"], registration.to_string());
            assert!(!event.to_string().contains("sensitive-target"));
            assert!(!event.to_string().contains("sensitive-actor"));
            assert!(!event.to_string().contains("sensitive-instance"));
        }
        a.finalize(None);
    }
}
