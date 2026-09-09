//! Closed, credential-free audit facts shared by request finalization and transactions.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use uuid::Uuid;
#[derive(Clone)]
pub(crate) struct Audit(pub Arc<Context>);
pub(crate) struct Context {
    pub request_id: Uuid,
    pub tenant: String,
    pub fact: Mutex<Fact>,
    pub committed: AtomicBool,
    pub commit_started: AtomicBool,
    pub finalized: AtomicBool,
}
#[derive(Clone)]
pub(crate) struct Fact {
    pub actor: Option<String>,
    pub client: Option<String>,
    pub action: &'static str,
    pub target: Option<String>,
    pub operation_id: Option<Uuid>,
}
impl Audit {
    pub fn new(tenant: String, action: &'static str) -> Self {
        Self(Arc::new(Context {
            request_id: Uuid::new_v4(),
            tenant,
            fact: Mutex::new(Fact {
                actor: None,
                client: None,
                action,
                target: None,
                operation_id: None,
            }),
            committed: AtomicBool::new(false),
            commit_started: AtomicBool::new(false),
            finalized: AtomicBool::new(false),
        }))
    }
    pub fn fact(&self) -> Fact {
        self.0
            .fact
            .lock()
            .expect("audit mutation has no fallible work")
            .clone()
    }
    pub fn identify(&self, proof: &rss_identity_client::VerifiedIdentity) {
        let mut fact = self.0.fact.lock().expect("audit lock");
        fact.actor = Some(proof.subject().into());
        fact.client = Some(proof.client_id().into());
    }
    pub fn target(&self, target: &str) {
        self.0.fact.lock().expect("audit lock").target = Some(target.into());
    }
    pub fn operation(&self, id: Uuid, action: &'static str) {
        let mut f = self.0.fact.lock().expect("audit lock");
        f.operation_id = Some(id);
        f.action = action;
    }
    pub fn alarm(&self, reason: &'static str) {
        eprintln!(
            "{}",
            serde_json::json!({"event":"audit_failure","severity":"error","request_id":self.0.request_id,"operation_id":self.fact().operation_id,"reason":reason})
        );
    }
}
impl Context {
    fn cancellation_event(&self) -> serde_json::Value {
        let fact = self
            .fact
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let outcome = if self.committed.load(Ordering::Acquire) {
            "committed"
        } else if self.commit_started.load(Ordering::Acquire) {
            "unknown"
        } else {
            "commit_not_started"
        };
        serde_json::json!({"event":"audit_failure","severity":"error","request_id":self.request_id,"operation_id":fact.operation_id,"action":fact.action,"reason":"audit_finalization_cancelled","write_outcome":outcome})
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        if !self.finalized.load(Ordering::Acquire) {
            eprintln!("{}", self.cancellation_event());
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
        assert_eq!(
            a.0.cancellation_event()["write_outcome"],
            "commit_not_started"
        );
        a.0.commit_started.store(true, Ordering::Release);
        let event = a.0.cancellation_event();
        assert_eq!(event["write_outcome"], "unknown");
        assert_eq!(event["operation_id"], key.to_string());
        assert!(!event.to_string().contains("sensitive-target"));
        a.0.committed.store(true, Ordering::Release);
        assert_eq!(a.0.cancellation_event()["write_outcome"], "committed");
        a.0.finalized.store(true, Ordering::Release);
    }
}
