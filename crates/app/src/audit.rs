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
    pub writing: AtomicBool,
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
            writing: AtomicBool::new(false),
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
impl Drop for Context {
    fn drop(&mut self) {
        if !self.finalized.load(Ordering::Acquire) {
            eprintln!(
                "{}",
                serde_json::json!({"event":"audit_failure","severity":"error","request_id":self.request_id,"reason":"request_cancelled","write_outcome":"unknown"})
            );
        }
    }
}
