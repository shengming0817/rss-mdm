use super::*;
use crate::{
    AccessStore, Error, Failure,
    access_store::{Actor, Operation, db},
    audit::Audit,
    identity::Principal,
};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

impl AccessStore {
    pub(crate) async fn authorization_snapshot(
        &self,
        proof: &Principal,
    ) -> Result<Snapshot, Error> {
        proof.check_live()?;
        let mut tx = self.begin(proof.tenant_id()).await?;
        let json: String = sqlx::query_scalar("WITH rules AS MATERIALIZED (SELECT * FROM mdm_access.authorization_rules WHERE tenant_id=$1::uuid AND instance=$2::uuid ORDER BY id LIMIT 10001), groups AS MATERIALIZED (SELECT * FROM mdm_access.user_groups WHERE tenant_id=$1::uuid AND instance=$2::uuid ORDER BY id LIMIT 10001) SELECT CASE WHEN (SELECT coalesce(sum(octet_length(document::text)),0) FROM rules)+(SELECT coalesce(sum(octet_length(document::text)),0) FROM groups)<=8388608 THEN jsonb_build_object('rules',coalesce((SELECT jsonb_agg(jsonb_build_object('id',id,'revision',revision,'value',document)) FROM rules),'[]'::jsonb),'groups',coalesce((SELECT jsonb_agg(jsonb_build_object('id',id,'revision',revision,'value',document)) FROM groups),'[]'::jsonb)) ELSE NULL END::text")
            .bind(proof.tenant_id()).bind(proof.instance_id()).fetch_one(&mut *tx).await.map_err(db)?;
        let snapshot: Snapshot = decode(&json)?;
        snapshot.validate(proof.tenant_id(), proof.instance_id())?;
        tx.rollback().await.map_err(db)?;
        proof.check_live()?;
        Ok(snapshot)
    }
    pub(crate) async fn change_rule(
        &self,
        proof: &Principal,
        id: Uuid,
        change: Change<Rule>,
        audit: &Audit,
    ) -> Result<Receipt, Error> {
        proof.require(Permission::AuthorizationWrite, None)?;
        if let Some(value) = &change.value {
            value.validate(proof.tenant_id(), proof.instance_id())?;
        }
        self.change_authorization(proof, Table::Rules, id, change, audit)
            .await
    }
    pub(crate) async fn change_group(
        &self,
        proof: &Principal,
        id: Uuid,
        change: Change<UserGroup>,
        audit: &Audit,
    ) -> Result<Receipt, Error> {
        proof.require(Permission::UserGroupWrite, None)?;
        if let Some(value) = &change.value {
            value.validate(proof.tenant_id(), proof.instance_id())?;
        }
        self.change_authorization(proof, Table::Groups, id, change, audit)
            .await
    }
    async fn change_authorization<T: serde::Serialize>(
        &self,
        proof: &Principal,
        table: Table,
        id: Uuid,
        change: Change<T>,
        audit: &Audit,
    ) -> Result<Receipt, Error> {
        if id.is_nil()
            || change.operation_id.is_nil()
            || change.expected_revision >= i64::MAX as u64
        {
            return Err(Error::Malformed);
        }
        let value = change
            .value
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| Error::Malformed)?;
        if value.as_ref().is_some_and(|v| v.len() > 2 * 1024 * 1024) {
            return Err(Error::Malformed);
        }
        let digest = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&(table.name(), id, &change)).map_err(|_| Error::Malformed)?
            )
        );
        let operation = Operation {
            actor: actor(proof),
            key: change.operation_id,
            digest: &digest,
        };
        audit.operation(change.operation_id, "authorization_write");
        audit.target(&id.to_string());
        let mut tx = self.begin(proof.tenant_id()).await?;
        lock(&mut tx, proof.tenant_id(), proof.instance_id()).await?;
        if let Some(result) = AccessStore::replay(&mut tx, &operation).await? {
            return decode(&result);
        }
        let query = format!(
            "SELECT revision,document IS NULL AS deleted FROM mdm_access.{} WHERE tenant_id=$1::uuid AND instance=$2::uuid AND id=$3::uuid FOR UPDATE",
            table.name()
        );
        let old = sqlx::query(sqlx::AssertSqlSafe(query.as_str()))
            .bind(proof.tenant_id())
            .bind(proof.instance_id())
            .bind(id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;
        let revision = old
            .as_ref()
            .map(|r| r.try_get::<i64, _>("revision"))
            .transpose()
            .map_err(db)?
            .unwrap_or(0);
        if revision as u64 != change.expected_revision
            || old.as_ref().is_some_and(|r| r.get::<bool, _>("deleted"))
            || (revision == 0 && value.is_none())
        {
            return Err(Error::Conflict);
        }
        if revision == 0 {
            let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT count(*) FROM mdm_access.{} WHERE tenant_id=$1::uuid AND instance=$2::uuid",
                table.name()
            )))
            .bind(proof.tenant_id())
            .bind(proof.instance_id())
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
            if count >= 10000 {
                return Err(Error::Conflict);
            }
        }
        let query = format!(
            "INSERT INTO mdm_access.{}(tenant_id,instance,id,revision,document) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5::jsonb) ON CONFLICT(tenant_id,instance,id) DO UPDATE SET revision=excluded.revision,document=excluded.document",
            table.name()
        );
        sqlx::query(sqlx::AssertSqlSafe(query.as_str()))
            .bind(proof.tenant_id())
            .bind(proof.instance_id())
            .bind(id.to_string())
            .bind(revision + 1)
            .bind(value)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let bounded: bool = sqlx::query_scalar("SELECT (SELECT coalesce(sum(octet_length(document::text)),0) FROM mdm_access.authorization_rules WHERE tenant_id=$1::uuid AND instance=$2::uuid)+(SELECT coalesce(sum(octet_length(document::text)),0) FROM mdm_access.user_groups WHERE tenant_id=$1::uuid AND instance=$2::uuid)<=8388608").bind(proof.tenant_id()).bind(proof.instance_id()).fetch_one(&mut *tx).await.map_err(db)?;
        if !bounded {
            return Err(Error::Conflict);
        }
        proof.require(
            match table {
                Table::Rules => Permission::AuthorizationWrite,
                Table::Groups => Permission::UserGroupWrite,
            },
            None,
        )?;
        let receipt = Receipt {
            id,
            revision: (revision + 1) as u64,
            deleted: change.value.is_none(),
        };
        self.finish(
            tx,
            &operation,
            &serde_json::to_string(&receipt).map_err(|_| Error::Malformed)?,
            audit,
            None,
        )
        .await?;
        Ok(receipt)
    }
}
fn actor(proof: &Principal) -> Actor<'_> {
    Actor {
        tenant: proof.tenant_id(),
        subject: proof.principal_id(),
        instance: proof.instance_id(),
    }
}
#[derive(Clone, Copy)]
// SQL identifiers originate only from this closed enum; every request value is bound.
enum Table {
    Rules,
    Groups,
}
impl Table {
    fn name(self) -> &'static str {
        match self {
            Self::Rules => "authorization_rules",
            Self::Groups => "user_groups",
        }
    }
}
fn decode<T: DeserializeOwned>(value: &str) -> Result<T, Error> {
    serde_json::from_str(value).map_err(|_| Error::Unavailable(Failure::AccessStore))
}
async fn lock(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
    instance: &str,
) -> Result<(), Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2363))")
        .bind(format!("{tenant}:{instance}"))
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Initialize {
    pub database: crate::config::Database,
    pub operation_id: Uuid,
    pub user: User,
}
/// Explicit operator command, never invoked by serve. Marker and first rule commit with receipt/audit.
pub async fn initialize(config: Initialize) -> Result<Receipt, Error> {
    if config.database.user != "mdm_access" || config.operation_id.is_nil() {
        return Err(Error::Malformed);
    }
    canonical_uuid(&config.user.instance_id)?;
    canonical_uuid(&config.user.tenant_id)?;
    config
        .user
        .validate(&config.user.tenant_id, &config.user.instance_id)?;
    let store = AccessStore::connect(config.database.options()?).await?;
    let result = store
        .initialize_authorization(config.user, config.operation_id)
        .await;
    store.close().await;
    result
}
impl AccessStore {
    pub(crate) async fn initialize_authorization(
        &self,
        user: User,
        key: Uuid,
    ) -> Result<Receipt, Error> {
        canonical_uuid(&user.instance_id)?;
        canonical_uuid(&user.tenant_id)?;
        user.validate(&user.tenant_id, &user.instance_id)?;
        if key.is_nil() {
            return Err(Error::Malformed);
        }
        let audit = Audit::new(user.tenant_id.clone(), "authorization_initialize");
        audit.identify_operator(&user.principal_id, &user.instance_id);
        audit.operation(key, "authorization_initialize");
        let digest = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&("authorization_initialize", &user))
                    .map_err(|_| Error::Malformed)?
            )
        );
        let operation = Operation {
            actor: Actor {
                tenant: &user.tenant_id,
                instance: &user.instance_id,
                subject: &user.principal_id,
            },
            key,
            digest: &digest,
        };
        let mut tx = self.begin(&user.tenant_id).await?;
        lock(&mut tx, &user.tenant_id, &user.instance_id).await?;
        if let Some(receipt) = AccessStore::replay(&mut tx, &operation).await? {
            audit.finalize(None);
            return decode(&receipt);
        }
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.authorization_initializations WHERE tenant_id=$1::uuid AND instance=$2::uuid)").bind(&user.tenant_id).bind(&user.instance_id).fetch_one(&mut *tx).await.map_err(db)?;
        if exists {
            audit.finalize(None);
            return Err(Error::Conflict);
        }
        let id = Uuid::new_v4();
        let rule = Rule {
            subject: Subject::User { user: user.clone() },
            grants: [
                Permission::AuthorizationRead,
                Permission::AuthorizationWrite,
                Permission::UserGroupRead,
                Permission::UserGroupWrite,
                Permission::DepartmentRead,
            ]
            .into_iter()
            .map(|operation| Grant {
                operation,
                scope: Scope::Tenant,
            })
            .collect(),
        };
        sqlx::query("INSERT INTO mdm_access.authorization_initializations(tenant_id,instance,operation_id,principal) VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid)").bind(&user.tenant_id).bind(&user.instance_id).bind(key.to_string()).bind(&user.principal_id).execute(&mut *tx).await.map_err(db)?;
        sqlx::query("INSERT INTO mdm_access.authorization_rules(tenant_id,instance,id,revision,document) VALUES($1::uuid,$2::uuid,$3::uuid,1,$4::jsonb)").bind(&user.tenant_id).bind(&user.instance_id).bind(id.to_string()).bind(serde_json::to_string(&rule).map_err(|_| Error::Malformed)?).execute(&mut *tx).await.map_err(db)?;
        let receipt = Receipt {
            id,
            revision: 1,
            deleted: false,
        };
        let result = self
            .finish(
                tx,
                &operation,
                &serde_json::to_string(&receipt).map_err(|_| Error::Malformed)?,
                &audit,
                None,
            )
            .await;
        audit.finalize(None);
        result?;
        Ok(receipt)
    }
}
