//! Personal Vault sync. The host owns Identity, PostgreSQL and request lifecycle.
//! ref: ring src/signature.rs@2723abbca9e83347d82b056d5b239c6604f786df.
mod storage;
use rss_mdm_agent_wire::vault::*;
use rss_mdm_audit_integration::{AuditIntent, AuditStore, Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_install_support::StorageProfile;
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
pub const OBJECTS: &str = include_str!("../schema/objects.json");
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("vault audit failure")]
    Audit(rss_mdm_audit_integration::ErrorClass),
    #[error("invalid vault request")]
    Invalid,
    #[error("vault authorization rejected")]
    Denied,
    #[error("vault state conflict")]
    Conflict,
    #[error("vault not found")]
    NotFound,
    #[error("vault capacity exceeded")]
    Capacity,
    #[error("vault cursor invalidated")]
    Cursor,
    #[error("vault storage unavailable")]
    Storage,
    #[error("vault commit unknown")]
    CommitUnknown,
    #[error("vault rollback unconfirmed")]
    RollbackFailed,
}
impl From<sqlx::Error> for Error {
    fn from(_: sqlx::Error) -> Self {
        Self::Storage
    }
}
impl From<rss_mdm_agent_wire::runtime::WireError> for Error {
    fn from(_: rss_mdm_agent_wire::runtime::WireError) -> Self {
        Self::Invalid
    }
}
impl From<rss_mdm_audit_integration::Error> for Error {
    fn from(e: rss_mdm_audit_integration::Error) -> Self {
        Self::Audit(e.class())
    }
}
impl From<rss_mdm_audit_integration::InvalidFact> for Error {
    fn from(_: rss_mdm_audit_integration::InvalidFact) -> Self {
        Self::Audit(rss_mdm_audit_integration::ErrorClass::AuditContract)
    }
}
pub struct Service {
    tenant: TenantId,
    installation: Uuid,
    audit: Arc<AuditStore>,
    cursor: rss_mdm_query::cursor::CursorCodec,
}
impl Service {
    pub fn new(
        tenant: TenantId,
        installation: Uuid,
        audit: Arc<AuditStore>,
        cursor: rss_mdm_query::cursor::CursorCodec,
    ) -> Self {
        Self {
            tenant,
            installation,
            audit,
            cursor,
        }
    }
    pub async fn prepare(
        &self,
        actor: &AuthorizedPrincipal,
        audit: &RequestAudit,
        request: Prepare,
    ) -> Result<Challenge, Error> {
        request.validate()?;
        Box::pin(self.transaction(actor, audit, request, |s, c, scope, r| {
            Box::pin(storage::prepare(s, c, scope, r))
        }))
        .await
    }
    pub async fn execute(
        &self,
        actor: &AuthorizedPrincipal,
        audit: &RequestAudit,
        request: Execute,
    ) -> Result<Response, Error> {
        request.challenge.signing_bytes()?;
        if matches!(
            request.challenge.request.action,
            Action::Initialize { .. } | Action::Join { .. } | Action::Remove { .. }
        ) {
            audit.operation(
                request.challenge.request.operation,
                "vault_authorization",
                AuditIntent::Management,
            );
        }
        Box::pin(self.transaction(actor, audit, request, |s, c, scope, r| {
            Box::pin(storage::execute(s, c, scope, r))
        }))
        .await
    }
    async fn transaction<C: Send, R: Send>(
        &self,
        actor: &AuthorizedPrincipal,
        audit: &RequestAudit,
        input: C,
        f: impl for<'a> FnOnce(
            &'a Self,
            &'a mut PgConnection,
            &'a storage::Scope,
            &'a C,
        ) -> std::pin::Pin<
            Box<dyn Future<Output = Result<(R, bool), Error>> + Send + 'a>,
        > + Send,
    ) -> Result<R, Error> {
        if actor.profile() != StorageProfile::Da
            || actor.tenant_id() != self.tenant.to_string()
            || audit.profile() != StorageProfile::Da
        {
            return Err(Error::Denied);
        }
        actor.bind_audit(audit).map_err(|_| Error::Denied)?;
        let session = actor.session().map_err(|_| Error::Denied)?;
        let scope = storage::Scope {
            tenant: Uuid::parse_str(actor.tenant_id()).map_err(|_| Error::Denied)?,
            instance: Uuid::parse_str(actor.instance_id()).map_err(|_| Error::Denied)?,
            principal: Uuid::parse_str(actor.principal_id()).map_err(|_| Error::Denied)?,
        };
        let budget = AuditBudget::new(Duration::from_secs(6));
        // Keep nested transaction futures off native handler/test stacks.
        let attempt = Box::pin(self.audit.write(
            self.tenant,
            &budget.source_control(),
            (self, input, scope, Some(f), session, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (value, replay) = tx
                        .with_connection_context(ctx, |ctx, c| {
                            Box::pin(async move {
                                rss_identity_postgres::recheck_authenticated_session_on(c, ctx.4)
                                    .await
                                    .map_err(|_| Error::Denied)?;
                                let installation: Uuid = sqlx::query_scalar(
                                    "SELECT instance_id FROM rss_da.installation_binding",
                                )
                                .fetch_one(&mut *c)
                                .await?;
                                if installation != ctx.0.installation {
                                    return Err(Error::Denied);
                                }
                                sqlx::query("SELECT set_config('rss.vault_owner',$1,true)")
                                    .bind(ctx.2.owner())
                                    .execute(&mut *c)
                                    .await?;
                                // Serialize initialization, authorization changes, reads and writes for this user.
                                sqlx::query(
                                    "SELECT pg_advisory_xact_lock(hashtextextended($1,2931))",
                                )
                                .bind(format!("{}:{}", ctx.2.tenant, ctx.2.owner()))
                                .execute(&mut *c)
                                .await?;
                                (ctx.3.take().ok_or(Error::Storage)?)(ctx.0, c, &ctx.2, &ctx.1)
                                    .await
                            })
                        })
                        .await?;
                    if !replay && ctx.5.snapshot().intent == AuditIntent::Management {
                        let snapshot = ctx.5.snapshot();
                        // This is the user's key-proof protocol, not an administrator receipt namespace.
                        // Preserve its atomic audit fact without manufacturing an MDM locator.
                        let fact = Fact::observation(
                            ctx.5,
                            &format!(
                                "vault:{}:{}",
                                snapshot.action,
                                snapshot.operation_id.ok_or(Error::Invalid)?
                            ),
                            200,
                            "success",
                            None,
                        )?;
                        ctx.0.audit.append(tx, &fact).await?;
                    }
                    if replay {
                        ctx.5.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        );
                    }
                    ctx.5.mark_commit_started();
                    Ok(value)
                })
            },
        ))
        .await;
        use rss_mdm_audit_integration::TransactionError as T;
        let error = |e| match e {
            T::Operation(e) => e,
            T::Storage(e) => e.into(),
            T::Rollback { .. } => Error::RollbackFailed,
        };
        attempt.fold(
            |v| {
                audit.mark_committed();
                Ok(v)
            },
            |e| Err(error(e)),
            |e| {
                audit.mark_rolled_back();
                Err(error(e))
            },
            |_| {
                audit.mark_rollback_failed();
                Err(Error::RollbackFailed)
            },
            |_| Err(Error::CommitUnknown),
            |e| Err(error(e)),
        )
    }
}
/// Called only by the fenced cold-restore owner, with a journal-frozen fresh UUID.
/// No data root is changed. All pre-restore grants, challenges and receipts cease to authorize.
pub async fn restore_incarnation(
    c: &mut PgConnection,
    incarnation: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE rss_da.vault_epochs SET incarnation=$1")
        .bind(incarnation)
        .execute(&mut *c)
        .await?;
    sqlx::query("UPDATE rss_da.vaults SET incarnation=$1")
        .bind(incarnation)
        .execute(&mut *c)
        .await?;
    sqlx::query("UPDATE rss_da.vault_devices SET active=false")
        .execute(c)
        .await?;
    Ok(())
}
/// Verify exact RLS and privilege ownership at installation and every host startup.
pub async fn verify_catalog(c: &mut PgConnection) -> Result<(), sqlx::Error> {
    for table in [
        "vault_epochs",
        "vaults",
        "vault_devices",
        "vault_entries",
        "vault_nonces",
        "vault_receipts",
    ] {
        let policies:Vec<(String,String,String,bool)>=sqlx::query_as("SELECT p.polname,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid),p.polcmd='*' AND p.polroles=ARRAY[0::oid] AND p.polpermissive FROM pg_policy p JOIN pg_class r ON r.oid=p.polrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='rss_da' AND r.relname=$1").bind(table).fetch_all(&mut *c).await?;
        let normalize = |s: &str| {
            s.chars()
                .filter(|c| !c.is_whitespace() && !['(', ')'].contains(c))
                .collect::<String>()
                .to_lowercase()
        };
        let mut expected =
            "tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid"
                .to_owned();
        if table != "vault_epochs" {
            expected += " AND owner = current_setting('rss.vault_owner'::text, true)";
        }
        if policies.len() != 1
            || policies[0].0 != "isolation"
            || !policies[0].3
            || normalize(&policies[0].1) != normalize(&expected)
            || normalize(&policies[0].2) != normalize(&expected)
        {
            return Err(sqlx::Error::Protocol("vault RLS drift".into()));
        }
        let valid:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE n.nspname='rss_da' AND c.relname=$1 AND a.grantee<>c.relowner AND (a.grantee<>to_regrole('da_identity_runtime')::oid OR a.is_grantable OR a.privilege_type NOT IN('SELECT','INSERT','UPDATE','DELETE'))) AND has_table_privilege('da_identity_runtime','rss_da.'||$1,'SELECT') AND has_table_privilege('da_identity_runtime','rss_da.'||$1,'INSERT') AND CASE WHEN $1='vault_epochs' THEN NOT has_table_privilege('da_identity_runtime','rss_da.'||$1,'UPDATE,DELETE') ELSE has_table_privilege('da_identity_runtime','rss_da.'||$1,'UPDATE') AND has_table_privilege('da_identity_runtime','rss_da.'||$1,'DELETE') END AND NOT has_table_privilege('da_identity_runtime','rss_da.'||$1,'TRUNCATE,REFERENCES,TRIGGER')").bind(table).fetch_one(&mut *c).await?;
        if !valid {
            return Err(sqlx::Error::Protocol("vault privilege drift".into()));
        }
    }
    Ok(())
}
