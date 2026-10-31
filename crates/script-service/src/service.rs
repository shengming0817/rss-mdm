//! Script materials bind to the initiating runtime, including Policy participants.
use crate::{Error, agent_facts};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use std::sync::Arc;

/// Application composition sums the concrete owners under the existing device lock.
pub trait DeviceCapacity: Send + Sync {
    fn available_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        device: &'a str,
        now: i64,
    ) -> std::pin::Pin<Box<dyn Future<Output = crate::Result<bool>> + Send + 'a>>;
}

pub struct Materials {
    pub agent_store: Arc<dyn agent_facts::Store>,
    pub source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    pub capacity: Arc<dyn DeviceCapacity>,
    pub instance: String,
    pub content: Option<Arc<rss_mdm_content_service::Store>>,
}
pub struct Transactions {
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) tenant: TenantId,
    pub(crate) instance: String,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) agent_store: Arc<dyn agent_facts::Store>,
    pub(crate) source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    pub(crate) capacity: Arc<dyn DeviceCapacity>,
    pub(crate) policy_reader: rss_mdm_policy_postgres::PolicyReader,
    pub(crate) reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub(crate) content: Option<Arc<rss_mdm_content_service::Store>>,
}
impl Transactions {
    pub async fn bind(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        materials: Arc<Materials>,
    ) -> std::result::Result<Self, Error> {
        let reconcile_messaging = rss_reconcile_postgres::PgMessagingStore::new(
            runtime.clone(),
            tenant,
            crate::transaction::deadline(),
        )
        .await
        .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(runtime.clone(), tenant),
            runtime,
            tenant,
            audit_store,
            reconcile_messaging,
            instance: materials.instance.clone(),
            agent_store: materials.agent_store.clone(),
            source: materials.source.clone(),
            capacity: materials.capacity.clone(),
            content: materials.content.clone(),
        })
    }
    pub fn validate_in(&self, tx: &PgTransaction<'_>) -> crate::Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::Forbidden.into());
        }
        Ok(())
    }
}

pub struct ScriptService {
    pub(crate) transactions: Transactions,
    pub(crate) sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    pub(crate) cursor: rss_mdm_query::cursor::CursorCodec,
}
impl ScriptService {
    pub fn new(
        transactions: Transactions,
        sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
        cursor_key: &[u8],
    ) -> Self {
        Self {
            transactions,
            sessions,
            cursor: rss_mdm_query::cursor::CursorCodec::from_key(ring::hmac::Key::new(
                ring::hmac::HMAC_SHA256,
                cursor_key,
            )),
        }
    }
}
