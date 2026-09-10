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
    pub client: Option<String>,
    pub action: &'static str,
    pub target: Option<String>,
    pub operation_id: Option<Uuid>,
    pub write_outcome: WriteOutcome,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WriteOutcome {
    CommitNotStarted,
    Unknown,
    Committed,
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
                    client: None,
                    action,
                    target: None,
                    operation_id: None,
                    write_outcome: WriteOutcome::CommitNotStarted,
                },
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
    pub fn identify(&self, proof: &rss_identity_client::VerifiedIdentity) {
        let mut state = self.0.state.lock().expect("audit lock");
        state.snapshot.actor = Some(proof.subject().into());
        state.snapshot.client = Some(proof.client_id().into());
    }
    #[cfg(test)]
    pub fn identify_fixture(&self, actor: &str, client: &str) {
        let mut state = self.0.state.lock().expect("audit lock");
        state.snapshot.actor = Some(actor.into());
        state.snapshot.client = Some(client.into());
    }
    pub fn set_action(&self, action: &'static str) {
        self.0.state.lock().expect("audit lock").snapshot.action = action;
    }
    pub fn target(&self, target: &str) {
        self.0.state.lock().expect("audit lock").snapshot.target = Some(target.into());
    }
    pub fn operation(&self, id: Uuid, action: &'static str) {
        let mut state = self.0.state.lock().expect("audit lock");
        state.snapshot.operation_id = Some(id);
        state.snapshot.action = action;
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
        serde_json::json!({"event":"audit_failure","severity":"error","request_id":self.request_id,"operation_id":snapshot.operation_id,"action":snapshot.action,"reason":reason,"write_outcome":snapshot.write_outcome})
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
    fn cancellation_preserves_operation_and_distinguishes_commit_phase() {
        let a = Audit::new("tenant".into(), "grant_issue");
        let key = Uuid::new_v4();
        a.operation(key, "grant_issue");
        a.target("sensitive-target-not-for-logs");
        a.identify_fixture("sensitive-actor", "sensitive-client");
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
            assert_eq!(event["action"], "grant_issue");
            assert!(!event.to_string().contains("sensitive-target"));
            assert!(!event.to_string().contains("sensitive-actor"));
            assert!(!event.to_string().contains("sensitive-client"));
        }
        a.finalize(None);
    }
}
