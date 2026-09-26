//! Atomic composition of planning authority and execution admission.
use crate::authorization::context::AuthorizedPrincipal;
use crate::execution::ExecutionService;
use crate::planning::actions::{
    ActionPlans,
    model::{Change, Create},
};
use crate::{
    Error,
    transaction::{self, TransactionOwner},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgRuntime;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
pub(crate) struct ActionWorkflow {
    pub runtime: Arc<PgRuntime>,
    pub tenant: TenantId,
    pub writer: rss_transactional_messaging_postgres::PgOutboxWriter,
    pub audit: Arc<rss_mdm_audit_integration::AuditStore>,
    pub plans: ActionPlans,
    pub execution: Arc<ExecutionService>,
}
impl ActionWorkflow {
    pub(crate) async fn create_action_plan(
        &self,
        proof: &AuthorizedPrincipal,
        input: &Create,
        audit: &RequestAudit,
    ) -> Result<Value, Error> {
        transaction::run(
            &self.audit,
            &self.runtime,
            self.tenant,
            audit,
            (self, proof, input, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, proof, input, audit) = *ctx;
                    let created = s.plans.create_in(tx, proof, input, audit).await?;
                    if created.created {
                        let now = crate::action_admission::now(tx).await?;
                        s.execution
                            .initialize_action_in(tx, input.operation_id, now)
                            .await?;
                    }
                    Ok(created.response)
                })
            },
            TransactionOwner::Planning,
        )
        .await
    }
    pub(crate) async fn approve_action_plan(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        input: &Change,
        audit: &RequestAudit,
    ) -> Result<Value, Error> {
        transaction::run(
            &self.audit,
            &self.runtime,
            self.tenant,
            audit,
            (self, proof, id, input, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, proof, id, input, audit) = *ctx;
                    let result = s.plans.approve_in(tx, proof, id, input, audit).await?;
                    if result.changed {
                        s.execution.start_action_in(tx, &s.writer, id).await?;
                        s.execution.wake_action_in(tx, id).await?;
                    }
                    Ok(result.response)
                })
            },
            TransactionOwner::Planning,
        )
        .await
    }
    pub(crate) async fn cancel_action_plan(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        input: &Change,
        audit: &RequestAudit,
    ) -> Result<Value, Error> {
        transaction::run(
            &self.audit,
            &self.runtime,
            self.tenant,
            audit,
            (self, proof, id, input, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, proof, id, input, audit) = *ctx;
                    let result = s.plans.cancel_in(tx, proof, id, input, audit).await?;
                    s.execution.wake_action_in(tx, id).await?;
                    Ok(result)
                })
            },
            TransactionOwner::Planning,
        )
        .await
    }
    pub(crate) async fn read_action_plan(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        audit: &RequestAudit,
    ) -> Result<Value, Error> {
        transaction::run(
            &self.audit,
            &self.runtime,
            self.tenant,
            audit,
            (self, proof, id, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, proof, id, audit) = *ctx;
                    s.plans.read_in(tx, proof, id, audit).await
                })
            },
            TransactionOwner::Planning,
        )
        .await
    }
}
