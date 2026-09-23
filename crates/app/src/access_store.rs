//! One owner for enrollment transactions, operation recovery and persistent audit.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs
use crate::{Error, Failure, audit::Audit};
use sqlx::{
    PgPool, Postgres, Row, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions},
};
#[cfg(test)]
use std::sync::atomic::Ordering;
use std::time::Duration;
use uuid::Uuid;
pub struct AccessStore {
    pool: PgPool,
    #[cfg(test)]
    fault: std::sync::atomic::AtomicU8,
}
impl AccessStore {
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
        Ok(Self {
            pool,
            #[cfg(test)]
            fault: std::sync::atomic::AtomicU8::new(0),
        })
    }
    #[cfg(test)]
    pub(crate) fn unconnected() -> Self {
        Self {
            pool: PgPoolOptions::new()
                .connect_lazy("postgres://mdm_access@localhost:1/mdm")
                .unwrap(),
            fault: std::sync::atomic::AtomicU8::new(0),
        }
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
    pub(crate) async fn record(
        &self,
        audit: &Audit,
        status: u16,
        result: &str,
    ) -> Result<(), Error> {
        let mut tx = self.begin(audit.tenant()).await?;
        append(&mut tx, audit, status, result, None).await?;
        tx.commit()
            .await
            .map_err(|_| Error::Unavailable(Failure::Audit))
    }
    pub(crate) async fn replay(
        tx: &mut Transaction<'_, Postgres>,
        operation: &Operation<'_>,
    ) -> Result<Option<String>, Error> {
        let Operation {
            actor: proof,
            key,
            digest,
        } = operation;
        let lock = format!(
            "{}:{}:{}:{}",
            proof.tenant,
            proof.subject.len(),
            proof.subject,
            key
        );
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2347))")
            .bind(lock)
            .execute(&mut **tx)
            .await
            .map_err(db)?;
        let old = sqlx::query("SELECT digest,result,instance FROM mdm_access.operations WHERE tenant_id=$1::uuid AND actor=$2 AND operation_id=$3::uuid")
            .bind(proof.tenant).bind(proof.subject).bind(key.to_string()).fetch_optional(&mut **tx).await.map_err(db)?;
        old.map(|old| {
            if old.try_get::<String, _>("digest").map_err(db)? != *digest
                || old.try_get::<String, _>("instance").map_err(db)? != proof.instance
            {
                return Err(Error::Conflict);
            }
            old.try_get("result").map_err(db)
        })
        .transpose()
    }
    pub(crate) async fn finish(
        &self,
        mut tx: Transaction<'_, Postgres>,
        operation: &Operation<'_>,
        result: &str,
        audit: &Audit,
        request: Option<Uuid>,
    ) -> Result<(), Error> {
        let Operation {
            actor: proof,
            key,
            digest,
        } = operation;
        let facts = audit.snapshot();
        if audit.tenant() != proof.tenant
            || facts.actor.as_deref() != Some(proof.subject)
            || facts.instance.as_deref() != Some(proof.instance)
            || facts.operation_id != Some(*key)
        {
            return Err(Error::Forbidden);
        }
        sqlx::query("INSERT INTO mdm_access.operations(tenant_id,actor,operation_id,digest,result,instance) VALUES($1::uuid,$2,$3::uuid,$4,$5,$6)")
            .bind(proof.tenant).bind(proof.subject).bind(key.to_string()).bind(*digest).bind(result).bind(proof.instance).execute(&mut *tx).await.map_err(db)?;
        self.commit_audited(tx, audit, request).await
    }
    pub(crate) async fn commit_audited(
        &self,
        mut tx: Transaction<'_, Postgres>,
        audit: &Audit,
        request: Option<Uuid>,
    ) -> Result<(), Error> {
        append(&mut tx, audit, 200, "success", request).await?;
        #[cfg(test)]
        if self
            .fault
            .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            tx.rollback().await.map_err(db)?;
            return Err(Error::Unavailable(Failure::AccessStore));
        }
        audit.mark_commit_started();
        #[cfg(test)]
        if self
            .fault
            .compare_exchange(3, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // Cancel at COMMIT entry; Drop can still roll this transaction back.
            std::future::pending::<()>().await;
        }
        tx.commit().await.map_err(|_| Error::CommitUnknown)?;
        #[cfg(test)]
        match self.fault.swap(0, Ordering::AcqRel) {
            2 => return Err(Error::CommitUnknown),
            // Real COMMIT succeeded; its acknowledgement never reaches the caller.
            4 => std::future::pending::<()>().await,
            _ => {}
        }
        audit.mark_committed();
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn fail_next(&self, point: u8) {
        self.fault.store(point, Ordering::Release);
    }
}
#[derive(Clone, Copy)]
pub(crate) struct Actor<'a> {
    pub tenant: &'a str,
    pub subject: &'a str,
    pub instance: &'a str,
}
pub(crate) struct Operation<'a> {
    pub actor: Actor<'a>,
    pub key: Uuid,
    pub digest: &'a str,
}

pub(crate) fn db(error: sqlx::Error) -> Error {
    #[cfg(test)]
    eprintln!(
        "test PG error category: {:?}",
        error.as_database_error().and_then(|e| e.code())
    );
    let _ = error;
    Error::Unavailable(Failure::AccessStore)
}
pub(crate) async fn append(
    tx: &mut Transaction<'_, Postgres>,
    audit: &Audit,
    status: u16,
    result: &str,
    registration: Option<Uuid>,
) -> Result<(), Error> {
    append_on_connection(tx, audit, status, result, registration).await
}
pub(crate) async fn append_on_connection(
    connection: &mut sqlx::PgConnection,
    audit: &Audit,
    status: u16,
    result: &str,
    registration: Option<Uuid>,
) -> Result<(), Error> {
    let f = audit.snapshot();
    sqlx::query("INSERT INTO mdm_access.audit(tenant_id,id,request_id,actor,instance,target,operation_id,registration_request,action,result,status,registration_id,software,plan) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7::uuid,$8::uuid,$9,$10,$11,$12::uuid,$13::jsonb,$14::uuid)")
        .bind(audit.tenant()).bind(Uuid::new_v4().to_string()).bind(audit.request_id().to_string()).bind(f.actor).bind(f.instance).bind(f.target).bind(f.operation_id.map(|v|v.to_string())).bind(registration.map(|v|v.to_string())).bind(f.action).bind(result).bind(i32::from(status)).bind(f.registration_id.map(|v|v.to_string())).bind(f.software.map(|v| serde_json::to_string(&v).expect("software fact serialization"))).bind(f.plan.map(|v|v.to_string())).execute(connection).await.map_err(|_| Error::Unavailable(Failure::Audit))?;
    Ok(())
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
 AND (SELECT count(*)=16 AND bool_and(c.relname IN ('grants','requests','operations','audit','devices','registrations','credentials','report_sources','enrollment_intents','enrollment_certificates','management_sessions','management_messages','collection_runs','authorization_rules','user_groups','authorization_initializations') AND c.relrowsecurity AND c.relforcerowsecurity AND c.relowner<>(SELECT oid FROM pg_roles WHERE rolname=current_user)
 AND (CASE WHEN c.relname <> 'audit' THEN has_table_privilege(current_user,c.oid,'SELECT') ELSE NOT has_table_privilege(current_user,c.oid,'SELECT') AND NOT has_any_column_privilege(current_user,c.oid,'SELECT') END) AND has_table_privilege(current_user,c.oid,'INSERT')
 AND NOT has_table_privilege(current_user,c.oid,'UPDATE,TRUNCATE,REFERENCES,TRIGGER')
 AND has_table_privilege(current_user,c.oid,'DELETE')=(c.relname IN ('management_sessions','management_messages'))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_access' AND c.relkind='r')
 AND (SELECT bool_and(has_column_privilege(current_user,'mdm_access.'||t,col,'UPDATE')) FROM unnest(ARRAY['authorization_rules','user_groups']) t CROSS JOIN unnest(ARRAY['revision','document']) col)
 AND NOT has_column_privilege(current_user,'mdm_access.grants','state','UPDATE')
 AND (SELECT bool_and(has_column_privilege(current_user,'mdm_access.requests',col,'UPDATE')) FROM unnest(ARRAY['state','password_digest','password_version','credential_ref','expires_at']) col)
 AND has_column_privilege(current_user,'mdm_access.enrollment_certificates','server_nonce','UPDATE')
 AND (SELECT bool_and(has_column_privilege(current_user,'mdm_access.management_sessions',col,'UPDATE')) FROM unnest(ARRAY['state','last_message','correlation','nonce','client_authenticated','run_id']) col)
 AND has_column_privilege(current_user,'mdm_access.registrations','state','UPDATE')
 AND has_column_privilege(current_user,'mdm_access.credentials','state','UPDATE')
 AND has_column_privilege(current_user,'mdm_access.report_sources','enabled','UPDATE')
 AND (SELECT bool_and(has_column_privilege(current_user,'mdm_access.report_sources',col,'UPDATE')) FROM unnest(ARRAY['next_command','next_sequence']) col)
 AND (SELECT bool_and(has_column_privilege(current_user,'mdm_access.collection_runs',col,'UPDATE')) FROM unnest(ARRAY['attempts','result','reason','batch','digest','sealed_at','delivery_pending']) col)
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_access' AND a.attnum>0 AND NOT a.attisdropped AND NOT(c.relname IN ('registrations','credentials') AND a.attname='state' OR c.relname='report_sources' AND a.attname IN ('enabled','next_command','next_sequence') OR c.relname='requests' AND a.attname IN ('state','password_digest','password_version','credential_ref','expires_at') OR c.relname='management_sessions' AND a.attname IN ('state','last_message','correlation','nonce','client_authenticated','run_id') OR c.relname='collection_runs' AND a.attname IN ('attempts','result','reason','batch','digest','sealed_at','delivery_pending') OR c.relname='enrollment_certificates' AND a.attname='server_nonce' OR c.relname IN ('authorization_rules','user_groups') AND a.attname IN ('revision','document')) AND has_column_privilege(current_user,c.oid,a.attnum,'UPDATE'))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace, LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE n.nspname='mdm_access' AND (a.grantee=0 OR (a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable)))
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n, LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='mdm_access' AND (a.grantee=0 OR (a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable)))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute col JOIN pg_class c ON c.oid=col.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace, LATERAL aclexplode(col.attacl) a WHERE n.nspname='mdm_access' AND (a.grantee=0 OR (a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND (a.is_grantable OR a.privilege_type='REFERENCES'))))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('mdm_access','pg_catalog','information_schema') AND c.relkind IN ('r','p','v','m','f') AND (has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND c.relkind='S' AND CASE WHEN c.relkind='S' THEN has_sequence_privilege(current_user,c.oid,'SELECT,USAGE,UPDATE') ELSE false END)
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND has_function_privilege(current_user,p.oid,'EXECUTE'))
"#).fetch_one(&mut *tx).await.map_err(db)?;
    if !valid {
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
    if policies != 16 || retention != 2 || total != 18 {
        return Err(Error::Unavailable(Failure::AccessAdmission));
    }
    tx.rollback().await.map_err(db)
}
