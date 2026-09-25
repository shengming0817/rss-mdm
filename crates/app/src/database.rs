//! Private connection ownership and tenant transaction configuration.
//! Capability admission checks are composed here on the same connection.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs
use crate::{Error, Failure};
use sqlx::{
    PgPool, Postgres, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::time::Duration;
pub(crate) struct Database {
    pool: PgPool,
}
impl Database {
    pub async fn connect(options: PgConnectOptions) -> Result<Self, Error> {
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(1))
            .connect_with(options)
            .await
            .map_err(db)?;
        if let Err(e) = admission(&pool).await {
            pool.close().await;
            return Err(e);
        }
        Ok(Self { pool })
    }
    /// Host assembly shares this pool with Audit; Database remains its shutdown owner.
    pub(crate) async fn audit_store(
        &self,
        config: &crate::config::AuditConfig,
    ) -> Result<std::sync::Arc<rss_mdm_audit_integration::AuditStore>, Error> {
        let timer = crate::lifecycle::RuntimeTimer;
        let cancel = tokio_util::sync::CancellationToken::new();
        let cutoff = rss_request_context::Deadline::from_timeout(&timer, Duration::from_secs(2))
            .map_err(|_| Error::Configuration(crate::ConfigIssue::Budget))?;
        let control = rss_audit_postgres::Control::new(&timer, cutoff, &cancel);
        rss_mdm_audit_integration::AuditStore::new(self.pool.clone(), config.integrity()?, &control)
            .await
            .map(std::sync::Arc::new)
            .map_err(Error::from)
    }
    pub async fn close(&self) {
        self.pool.close().await;
    }
    pub(crate) async fn begin(&self, tenant: &str) -> Result<Transaction<'_, Postgres>, Error> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        Self::configure_transaction(&mut tx, tenant).await?;
        Ok(tx)
    }
    pub(crate) async fn acquire(&self) -> Result<sqlx::pool::PoolConnection<Postgres>, Error> {
        self.pool.acquire().await.map_err(db)
    }
    pub(crate) async fn configure_transaction(
        tx: &mut Transaction<'_, Postgres>,
        tenant: &str,
    ) -> Result<(), Error> {
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','1000',true),set_config('lock_timeout','1000',true)")
            .bind(tenant).execute(&mut **tx).await.map_err(db)?;
        Ok(())
    }
}

pub(crate) fn db(error: sqlx::Error) -> Error {
    #[cfg(test)]
    eprintln!(
        "test PG error category: {:?}",
        error.as_database_error().and_then(|e| e.code())
    );
    let _ = error;
    Error::Unavailable(Failure::Database)
}

async fn admission(pool: &PgPool) -> Result<(), Error> {
    let mut tx = pool.begin().await.map_err(db)?;
    sqlx::query("SET LOCAL statement_timeout='1s'")
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    let valid: bool = sqlx::query_scalar(r#"
SELECT current_user='mdm_access' AND session_user=current_user
 AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user) OR roleid=(SELECT oid FROM pg_roles WHERE rolname=current_user))
 AND NOT has_database_privilege(current_user,current_database(),'CREATE')
 AND NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname NOT LIKE 'pg_temp_%' AND has_schema_privilege(current_user,oid,'CREATE'))
 AND has_schema_privilege(current_user,'mdm_access','USAGE')
 AND (SELECT count(*)=18 AND bool_and(c.relname IN ('grants','requests','operations','devices','registrations','credentials','report_sources','enrollment_intents','enrollment_certificates','management_sessions','management_messages','collection_runs','authorization_rules','user_groups','authorization_initializations','asset_authority_history','collection_history','agent_bindings') AND c.relrowsecurity AND c.relforcerowsecurity AND c.relowner<>(SELECT oid FROM pg_roles WHERE rolname=current_user)
 AND (CASE WHEN c.relname NOT IN ('asset_authority_history','collection_history') THEN has_table_privilege(current_user,c.oid,'SELECT') ELSE NOT has_table_privilege(current_user,c.oid,'SELECT') AND NOT has_any_column_privilege(current_user,c.oid,'SELECT') END) AND has_table_privilege(current_user,c.oid,'INSERT')=(c.relname NOT IN('asset_authority_history','collection_history'))
 AND NOT has_table_privilege(current_user,c.oid,'UPDATE,TRUNCATE,REFERENCES,TRIGGER')
 AND has_table_privilege(current_user,c.oid,'DELETE')=(c.relname IN ('management_sessions','management_messages'))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_access' AND c.relkind='r')
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_access' AND a.attnum>0 AND NOT a.attisdropped AND NOT(c.relname IN ('registrations','credentials') AND a.attname='state' OR c.relname='report_sources' AND a.attname IN ('enabled','next_command','next_sequence') OR c.relname='requests' AND a.attname IN ('state','password_digest','password_version','credential_ref','expires_at') OR c.relname='management_sessions' AND a.attname IN ('state','last_message','correlation','nonce','client_authenticated','run_id') OR c.relname='collection_runs' AND a.attname IN ('attempts','result','reason','batch','digest','sealed_at','delivery_pending') OR c.relname='enrollment_certificates' AND a.attname='server_nonce' OR c.relname IN ('authorization_rules','user_groups') AND a.attname IN ('revision','document')) AND has_column_privilege(current_user,c.oid,a.attnum,'UPDATE'))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace, LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE n.nspname='mdm_access' AND (a.grantee=0 OR (a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable)))
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n, LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='mdm_access' AND (a.grantee=0 OR (a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable)))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute col JOIN pg_class c ON c.oid=col.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace, LATERAL aclexplode(col.attacl) a WHERE n.nspname='mdm_access' AND (a.grantee=0 OR (a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND (a.is_grantable OR a.privilege_type='REFERENCES'))))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('mdm_access','mdm_apple','pg_catalog','information_schema') AND (n.nspname,c.relname) NOT IN (('rss_audit','heads'),('rss_audit','records'),('rss_ledger','heads'),('rss_ledger','entries'),('mdm_audit','receipts')) AND c.relkind IN ('r','p','v','m','f') AND (has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND c.relkind='S' AND CASE WHEN c.relkind='S' THEN has_sequence_privilege(current_user,c.oid,'SELECT,USAGE,UPDATE') ELSE false END)
 AND (SELECT count(*)=5 AND bool_and((n.nspname,p.proname) IN (('mdm_access','prune_agent_collections'),('rss_audit','reserve'),('rss_audit','append'),('rss_ledger','prepare_append'),('rss_ledger','insert_entry')) AND p.prosecdef AND p.proowner<>(SELECT oid FROM pg_roles WHERE rolname=current_user) AND p.proconfig @> ARRAY[CASE n.nspname WHEN 'rss_audit' THEN 'search_path=pg_catalog, rss_audit' WHEN 'rss_ledger' THEN 'search_path=pg_catalog, rss_ledger' ELSE 'search_path=pg_catalog, pg_temp' END] AND has_function_privilege(current_user,p.oid,'EXECUTE')) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND has_function_privilege(current_user,p.oid,'EXECUTE'))
"#).fetch_one(&mut *tx).await.map_err(db)?;
    let apple: bool = sqlx::query_scalar(include_str!("apple/access-admission.sql"))
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
    let authorization = crate::authorization::admission::verify(&mut tx)
        .await
        .map_err(db)?;
    let enrollment = crate::enrollment::admission::verify(&mut tx)
        .await
        .map_err(db)?;
    let device = crate::device::admission::verify(&mut tx)
        .await
        .map_err(db)?;
    let collection = crate::collection::admission::verify(&mut tx)
        .await
        .map_err(db)?;
    let windows = crate::windows::storage_admission::verify(&mut tx)
        .await
        .map_err(db)?;
    if !valid || !apple || !authorization || !enrollment || !device || !collection || !windows {
        return Err(Error::Unavailable(Failure::AccessAdmission));
    }
    // Canonical catalog rendering must not depend on the role's default "$user" search path.
    sqlx::query("SELECT set_config('search_path','pg_catalog',true)")
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    // Exact tenant policy; extra permissive policies cannot bypass isolation.
    let policies: i64 = sqlx::query_scalar(r#"SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_access' AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid] AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid' AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid)"#).fetch_one(&mut *tx).await.map_err(db)?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_access'").fetch_one(&mut *tx).await.map_err(db)?;
    let retention: i64 = sqlx::query_scalar(r#"SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_access' AND p.polname='expired_only' AND p.polcmd='d' AND NOT p.polpermissive AND p.polroles=ARRAY[0::oid] AND p.polwithcheck IS NULL AND (c.relname='management_sessions' AND lower(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'))='expires_at<clock_timestamp' OR c.relname='management_messages' AND lower(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'))='existsselect1frommdm_access.management_sessionsswheres.tenant_id=management_messages.tenant_idands.registration=management_messages.registrationands.session_id=management_messages.session_idands.expires_at<clock_timestamp')"#).fetch_one(&mut *tx).await.map_err(db)?;
    if policies != 18 || retention != 2 || total != 20 {
        return Err(Error::Unavailable(Failure::AccessAdmission));
    }
    tx.rollback().await.map_err(db)
}

/// Probe each borrowed transaction owner at startup without changing its isolation or pool.
pub(crate) async fn admit_audit_runtime(
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
    store: &rss_mdm_audit_integration::AuditStore,
    tenant: rss_request_context::TenantId,
) -> Result<(), Error> {
    let failure = std::sync::Mutex::new(None);
    runtime
        .local_tx_with_context(
            tenant,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                Duration::from_secs(5),
            ),
            (store, &failure),
            |(store, failure), tx| {
                Box::pin(async move {
                    match store.lock_in(tx).await {
                        Ok(()) => Ok(()),
                        Err(error) => {
                            *failure.lock().expect("startup audit failure") =
                                Some(Error::from(error));
                            Err(rss_audit_postgres::Error::StorageContract.into())
                        }
                    }
                })
            },
        )
        .await
        .fold(
            Ok,
            |_| Err(Error::Unavailable(Failure::Audit)),
            |_| {
                Err(failure
                    .into_inner()
                    .expect("startup audit failure")
                    .unwrap_or(Error::Unavailable(Failure::Audit)))
            },
            |_| Err(Error::RollbackFailed),
            |_| Err(Error::CommitUnknown),
            |_| Err(Error::Unavailable(Failure::Audit)),
        )
}
