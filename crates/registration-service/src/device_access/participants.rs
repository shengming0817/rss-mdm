//! Recovery owns material custody; Registration owns binding and task authority.
use crate::agent::Pending;
use rss_mdm_agent_wire::runtime as wire;
use sqlx::PgConnection;
use uuid::Uuid;
#[derive(Clone, Copy)]
pub enum BindingDisposition {
    Current,
    Withdrawn,
}
pub trait AccessRecovery: Send + Sync {
    fn plan<'a>(
        &'a self,
        c: &'a mut PgConnection,
        binding: &'a super::Binding,
        now: i64,
    ) -> Pending<'a, wire::AccessWindowsPlan>;
    fn escrow<'a>(
        &'a self,
        c: &'a mut PgConnection,
        task: &'a wire::AccessTaskSpec,
        value: &'a wire::CredentialEscrow,
    ) -> Pending<'a, Vec<wire::CredentialReceipt>>;
    fn settle<'a>(
        &'a self,
        c: &'a mut PgConnection,
        task: &'a wire::AccessTaskSpec,
        facts: &'a wire::AccessRssFacts,
    ) -> Pending<'a, ()>;
    fn unresolved<'a>(
        &'a self,
        c: &'a mut PgConnection,
        task: &'a wire::AccessTaskSpec,
        disposition: BindingDisposition,
        terminal: bool,
    ) -> Pending<'a, bool>;
    fn unknown<'a>(&'a self, c: &'a mut PgConnection, tenant: Uuid, run: Uuid) -> Pending<'a, ()>;
    fn unbound<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: Uuid,
        binding: Uuid,
        generation: i64,
        revision: i64,
    ) -> Pending<'a, ()>;
}
pub trait PlatformFacts: Send + Sync {
    fn platform_sso_observation<'a>(
        &'a self,
        c: &'a mut PgConnection,
        binding: &'a super::Binding,
        facts: &'a wire::AccessMacPlatformSsoFacts,
    ) -> Pending<'a, bool>;
}
