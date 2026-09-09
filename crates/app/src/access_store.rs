//! One owner for enrollment transactions, operation recovery and persistent audit.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs
use crate::{
    Error, Failure,
    access::EnrollmentPermission,
    audit::Audit,
    enrollment::{Command, Receipt},
};
use sqlx::{
    PgPool, Postgres, Row, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{sync::atomic::Ordering, time::Duration};
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
    async fn begin(&self, tenant: &str) -> Result<Transaction<'_, Postgres>, Error> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','1000',true),set_config('lock_timeout','1000',true)")
            .bind(tenant).execute(&mut *tx).await.map_err(db)?;
        Ok(tx)
    }
    pub(crate) async fn record(
        &self,
        audit: &Audit,
        status: u16,
        result: &str,
    ) -> Result<(), Error> {
        let mut tx = self.begin(&audit.0.tenant).await?;
        append(&mut tx, audit, status, result, None).await?;
        tx.commit()
            .await
            .map_err(|_| Error::Unavailable(Failure::Audit))
    }
    pub(crate) async fn execute(
        &self,
        permission: EnrollmentPermission<'_>,
        key: Uuid,
        command: Command,
        audit: &Audit,
    ) -> Result<Receipt, Error> {
        command.validate()?;
        if key.is_nil() || command.device() != permission.device() {
            return Err(Error::Malformed);
        }
        let proof = permission.proof();
        self.execute_as(
            Actor {
                tenant: proof.tenant_id(),
                subject: proof.subject(),
                client: proof.client_id(),
            },
            key,
            command,
            audit,
        )
        .await
    }
    async fn execute_as(
        &self,
        proof: Actor<'_>,
        key: Uuid,
        command: Command,
        audit: &Audit,
    ) -> Result<Receipt, Error> {
        let mut tx = self.begin(proof.tenant).await?;
        // Stable transaction lock serializes the same operation even before a receipt exists.
        // Hash collisions only serialize unrelated operations; full identity is checked below.
        let lock = format!(
            "{}:{}:{}:{}",
            proof.tenant,
            proof.subject.len(),
            proof.subject,
            key
        );
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2347))")
            .bind(lock)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let old = sqlx::query("SELECT digest,result,client FROM mdm_access.operations WHERE tenant_id=$1::uuid AND actor=$2 AND operation_id=$3::uuid")
            .bind(proof.tenant).bind(proof.subject).bind(key.to_string()).fetch_optional(&mut *tx).await.map_err(db)?;
        let digest = command.digest();
        if let Some(old) = old {
            if old.try_get::<String, _>("digest").map_err(db)? != digest
                || old.try_get::<String, _>("client").map_err(db)? != proof.client
            {
                return Err(Error::Conflict);
            }
            let receipt = serde_json::from_str(&old.try_get::<String, _>("result").map_err(db)?)
                .map_err(|_| Error::Unavailable(Failure::AccessStore))?;
            tx.rollback().await.map_err(db)?;
            return Ok(receipt);
        }
        audit.0.writing.store(true, Ordering::Release);
        let revoke = matches!(command, Command::Revoke { .. });
        let receipt = match command {
            Command::Issue { device_id } => {
                let id = Uuid::new_v4();
                let expiry: i64 = sqlx::query_scalar("INSERT INTO mdm_access.grants(tenant_id,id,actor,client,device,purpose,state,created_at,expires_at) SELECT $1::uuid,$2::uuid,$3,$4,$5,'enrollment','available',now,now+interval '300 seconds' FROM (SELECT clock_timestamp() AS now) t RETURNING floor(extract(epoch FROM expires_at))::bigint")
                    .bind(proof.tenant).bind(id.to_string()).bind(proof.subject).bind(proof.client).bind(device_id).fetch_one(&mut *tx).await.map_err(db)?;
                Receipt {
                    operation_id: key,
                    grant_id: id,
                    request_id: None,
                    status: "issued".into(),
                    expires_at: expiry,
                }
            }
            Command::Consume {
                device_id,
                grant_id,
            }
            | Command::Revoke {
                device_id,
                grant_id,
            } => {
                let row = sqlx::query("SELECT state,floor(extract(epoch FROM expires_at))::bigint AS expiry FROM mdm_access.grants WHERE tenant_id=$1::uuid AND id=$2::uuid AND actor=$3 AND client=$4 AND device=$5 AND purpose='enrollment' FOR UPDATE")
                    .bind(proof.tenant).bind(grant_id.to_string()).bind(proof.subject).bind(proof.client).bind(device_id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Forbidden)?;
                let state: String = row.try_get("state").map_err(db)?;
                if state != "available" {
                    return Err(Error::Conflict);
                }
                let state = if revoke { "revoked" } else { "consumed" };
                // Evaluate expiration after lock acquisition, never with transaction-start time.
                let changed = sqlx::query("UPDATE mdm_access.grants SET state=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid AND ($4 OR expires_at > clock_timestamp())")
                    .bind(proof.tenant).bind(grant_id.to_string()).bind(state).bind(revoke).execute(&mut *tx).await.map_err(db)?;
                if changed.rows_affected() != 1 {
                    return Err(Error::Forbidden);
                }
                let request = if revoke {
                    None
                } else {
                    let id = Uuid::new_v4();
                    sqlx::query("INSERT INTO mdm_access.requests(tenant_id,id,grant_id) VALUES($1::uuid,$2::uuid,$3::uuid)")
                        .bind(proof.tenant).bind(id.to_string()).bind(grant_id.to_string()).execute(&mut *tx).await.map_err(db)?;
                    Some(id)
                };
                Receipt {
                    operation_id: key,
                    grant_id,
                    request_id: request,
                    status: if revoke { "revoked" } else { "accepted" }.into(),
                    expires_at: row.try_get("expiry").map_err(db)?,
                }
            }
        };
        sqlx::query("INSERT INTO mdm_access.operations(tenant_id,actor,operation_id,digest,result,client) VALUES($1::uuid,$2,$3::uuid,$4,$5,$6)")
            .bind(proof.tenant).bind(proof.subject).bind(key.to_string()).bind(digest).bind(serde_json::to_string(&receipt).expect("closed receipt")).bind(proof.client).execute(&mut *tx).await.map_err(db)?;
        append(&mut tx, audit, 200, "success", receipt.request_id).await?;
        #[cfg(test)]
        if self
            .fault
            .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            tx.rollback().await.map_err(db)?;
            return Err(Error::Unavailable(Failure::AccessStore));
        }
        tx.commit().await.map_err(|_| Error::CommitUnknown)?;
        #[cfg(test)]
        if self.fault.swap(0, Ordering::AcqRel) == 2 {
            return Err(Error::CommitUnknown);
        }
        audit.0.committed.store(true, Ordering::Release);
        Ok(receipt)
    }
}
struct Actor<'a> {
    tenant: &'a str,
    subject: &'a str,
    client: &'a str,
}
fn db(_: sqlx::Error) -> Error {
    Error::Unavailable(Failure::AccessStore)
}
async fn append(
    tx: &mut Transaction<'_, Postgres>,
    audit: &Audit,
    status: u16,
    result: &str,
    registration: Option<Uuid>,
) -> Result<(), Error> {
    let f = audit.fact();
    sqlx::query("INSERT INTO mdm_access.audit(tenant_id,id,request_id,actor,client,target,operation_id,registration_request,action,result,status) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7::uuid,$8::uuid,$9,$10,$11)")
        .bind(&audit.0.tenant).bind(Uuid::new_v4().to_string()).bind(audit.0.request_id.to_string()).bind(f.actor).bind(f.client).bind(f.target).bind(f.operation_id.map(|v|v.to_string())).bind(registration.map(|v|v.to_string())).bind(f.action).bind(result).bind(i32::from(status)).execute(&mut **tx).await.map_err(|_| Error::Unavailable(Failure::Audit))?;
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
 AND (SELECT count(*)=4 AND bool_and(c.relname IN ('grants','requests','operations','audit') AND c.relrowsecurity AND c.relforcerowsecurity AND c.relowner<>(SELECT oid FROM pg_roles WHERE rolname=current_user)
 AND has_table_privilege(current_user,c.oid,'SELECT') AND has_table_privilege(current_user,c.oid,'INSERT')
 AND NOT has_table_privilege(current_user,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_access' AND c.relkind='r')
 AND has_column_privilege(current_user,'mdm_access.grants','state','UPDATE')
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_access' AND a.attnum>0 AND NOT a.attisdropped AND NOT(c.relname='grants' AND a.attname='state') AND has_column_privilege(current_user,c.oid,a.attnum,'UPDATE'))
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
    // Exact tenant policy; extra permissive policies cannot bypass isolation.
    let policies: i64 = sqlx::query_scalar(r#"SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_access' AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid] AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid' AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid)"#).fetch_one(&mut *tx).await.map_err(db)?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_access'").fetch_one(&mut *tx).await.map_err(db)?;
    if policies != 4 || total != 4 {
        return Err(Error::Unavailable(Failure::AccessAdmission));
    }
    tx.rollback().await.map_err(db)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::{Connection, Executor, PgConnection, postgres::PgSslMode};
    const TENANT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    fn actor() -> Actor<'static> {
        Actor {
            tenant: TENANT,
            subject: "administrator",
            client: "mdm",
        }
    }
    fn audit(key: Uuid, command: &Command) -> Audit {
        let a = Audit::new(TENANT.into(), command.action());
        a.0.finalized.store(true, Ordering::Release); // no HTTP owner in this PG-only carrier
        a.operation(key, command.action());
        a.target(command.device());
        {
            let mut f = a.0.fact.lock().unwrap();
            f.actor = Some("administrator".into());
            f.client = Some("mdm".into());
        }
        a
    }
    async fn execute(store: &AccessStore, command: Command, key: Uuid) -> Result<Receipt, Error> {
        let a = audit(key, &command);
        store.execute_as(actor(), key, command, &a).await
    }
    fn issue() -> Command {
        Command::Issue {
            device_id: "device".into(),
        }
    }
    fn consume(id: Uuid) -> Command {
        Command::Consume {
            device_id: "device".into(),
            grant_id: id,
        }
    }
    #[tokio::test]
    #[ignore = "make t2: real TLS PostgreSQL, production migrations and minimum role"]
    async fn enrollment_transactions_and_recovery() -> anyhow::Result<()> {
        let options = std::env::var("DATABASE_URL")?
            .parse::<PgConnectOptions>()?
            .username("mdm_access")
            .password("access-fixture")
            .ssl_mode(PgSslMode::VerifyFull)
            .ssl_root_cert(std::env::var("PG_CA_FILE")?);
        let store = std::sync::Arc::new(AccessStore::connect(options.clone()).await?);
        let admin_options = std::env::var("MDM_ADMIN_URL")?
            .parse::<PgConnectOptions>()?
            .ssl_mode(PgSslMode::VerifyFull)
            .ssl_root_cert(std::env::var("PG_CA_FILE")?);
        let mut admin = PgConnection::connect_with(&admin_options).await?;
        let key = Uuid::new_v4();
        let issued = execute(&store, issue(), key).await?;
        assert_eq!(execute(&store, issue(), key).await?, issued);
        assert!(matches!(
            execute(
                &store,
                Command::Issue {
                    device_id: "different".into()
                },
                key
            )
            .await,
            Err(Error::Conflict)
        ));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let id = issued.grant_id;
            tasks.push(tokio::spawn(async move {
                execute(&store, consume(id), Uuid::new_v4()).await
            }));
        }
        let mut successes = 0;
        for task in tasks {
            if task.await?.is_ok() {
                successes += 1;
            }
        }
        assert_eq!(successes, 1);
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_access.requests WHERE tenant_id=$1::uuid AND grant_id=$2::uuid").bind(TENANT).bind(issued.grant_id.to_string()).fetch_one(&mut admin).await?;
        assert_eq!(count, 1);
        let consumed_audits:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_access.audit WHERE tenant_id=$1::uuid AND action='registration_accept' AND result='success'").bind(TENANT).fetch_one(&mut admin).await?;
        assert_eq!(consumed_audits, 1);
        // Real COMMIT succeeds; the caller loses its acknowledgement and restarts.
        let key = Uuid::new_v4();
        store.fault.store(2, Ordering::Release);
        assert!(matches!(
            execute(&store, issue(), key).await,
            Err(Error::CommitUnknown)
        ));
        let restarted = AccessStore::connect(options.clone()).await?;
        let recovered = execute(&restarted, issue(), key).await?;
        assert_eq!(recovered, execute(&restarted, issue(), key).await?);
        let use_key = Uuid::new_v4();
        restarted.fault.store(2, Ordering::Release);
        assert!(matches!(
            execute(&restarted, consume(recovered.grant_id), use_key).await,
            Err(Error::CommitUnknown)
        ));
        let accepted = execute(&store, consume(recovered.grant_id), use_key).await?;
        assert_eq!(accepted.status, "accepted");
        let before_key = Uuid::new_v4();
        store.fault.store(1, Ordering::Release);
        assert!(execute(&store, issue(), before_key).await.is_err());
        assert!(execute(&store, issue(), before_key).await.is_ok());
        let revoked = execute(&store, issue(), Uuid::new_v4()).await?;
        let revoke = Command::Revoke {
            device_id: "device".into(),
            grant_id: revoked.grant_id,
        };
        let revoke_key = Uuid::new_v4();
        assert_eq!(
            execute(&store, revoke.clone(), revoke_key).await?.status,
            "revoked"
        );
        assert_eq!(execute(&store, revoke, revoke_key).await?.status, "revoked");
        assert!(
            execute(&store, consume(revoked.grant_id), Uuid::new_v4())
                .await
                .is_err()
        );
        let expired = execute(&store, issue(), Uuid::new_v4()).await?;
        sqlx::query("UPDATE mdm_access.grants SET created_at=statement_timestamp()-interval '600 seconds',expires_at=statement_timestamp()-interval '300 seconds' WHERE id=$1::uuid").bind(expired.grant_id.to_string()).execute(&mut admin).await?;
        assert!(
            execute(&store, consume(expired.grant_id), Uuid::new_v4())
                .await
                .is_err()
        );
        let live = execute(&store, issue(), Uuid::new_v4()).await?;
        let command = consume(live.grant_id);
        let key = Uuid::new_v4();
        let a = audit(key, &command);
        for identity in [
            Actor {
                tenant: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                ..actor()
            },
            Actor {
                subject: "other",
                ..actor()
            },
            Actor {
                client: "other",
                ..actor()
            },
        ] {
            assert!(
                store
                    .execute_as(identity, key, command.clone(), &a)
                    .await
                    .is_err()
            );
        }
        assert!(
            execute(
                &store,
                Command::Consume {
                    device_id: "other".into(),
                    grant_id: live.grant_id
                },
                Uuid::new_v4()
            )
            .await
            .is_err()
        );
        // Loss of audit INSERT rolls back grants, requests, state and receipts.
        admin
            .execute("REVOKE INSERT ON mdm_access.audit FROM mdm_access")
            .await?;
        let failed_issue = Uuid::new_v4();
        let failed_use = Uuid::new_v4();
        assert!(matches!(
            execute(&store, issue(), failed_issue).await,
            Err(Error::Unavailable(Failure::Audit))
        ));
        assert!(matches!(
            execute(&store, consume(live.grant_id), failed_use).await,
            Err(Error::Unavailable(Failure::Audit))
        ));
        assert!(store.record(&a, 403, "denied").await.is_err());
        assert!(AccessStore::connect(options.clone()).await.is_err());
        admin
            .execute("GRANT INSERT ON mdm_access.audit TO mdm_access")
            .await?;
        assert_eq!(
            execute(&store, consume(live.grant_id), failed_use)
                .await?
                .status,
            "accepted"
        );
        assert_eq!(
            execute(&store, issue(), failed_issue).await?.status,
            "issued"
        );
        let cancelled_key = Uuid::new_v4();
        let lock = format!(
            "{}:{}:{}:{}",
            TENANT,
            "administrator".len(),
            "administrator",
            cancelled_key
        );
        let mut holding = admin.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2347))")
            .bind(lock)
            .execute(&mut *holding)
            .await?;
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                execute(&store, issue(), cancelled_key)
            )
            .await
            .is_err()
        );
        holding.rollback().await?;
        assert!(execute(&store, issue(), cancelled_key).await.is_ok());
        // Runtime cannot cross tenant or modify audit/history.
        let mut connection = PgConnection::connect_with(&options).await?;
        let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.grants")
            .fetch_one(&mut connection)
            .await?;
        assert_eq!(visible, 0);
        for sql in [
            "DELETE FROM mdm_access.audit",
            "UPDATE mdm_access.audit SET result='success'",
            "SELECT * FROM mdm.inventory",
            "SELECT * FROM public.mdm_migrations",
        ] {
            assert!(connection.execute(sql).await.is_err());
        }
        for (grant, revoke) in [
            (
                "GRANT SELECT ON mdm_access.audit TO mdm_access WITH GRANT OPTION",
                "REVOKE GRANT OPTION FOR SELECT ON mdm_access.audit FROM mdm_access",
            ),
            (
                "GRANT UPDATE ON mdm_access.audit TO mdm_access",
                "REVOKE UPDATE ON mdm_access.audit FROM mdm_access",
            ),
            (
                "GRANT SELECT ON mdm.inventory TO mdm_access",
                "REVOKE SELECT ON mdm.inventory FROM mdm_access",
            ),
            (
                "ALTER TABLE mdm_access.grants NO FORCE ROW LEVEL SECURITY",
                "ALTER TABLE mdm_access.grants FORCE ROW LEVEL SECURITY",
            ),
        ] {
            admin.execute(grant).await?;
            let rejected = AccessStore::connect(options.clone()).await.is_err();
            admin.execute(revoke).await?;
            assert!(rejected);
        }
        connection.close().await?;
        admin.close().await?;
        restarted.close().await;
        store.close().await;
        Ok(())
    }
}
