//! Authored source identity and observation progress have separate coordinates.
use crate::{GroupStore, InTransaction, Rejection, storage::data, store::input};
use rss_mdm_group::{GroupId, GroupSource};
use rss_transactional_messaging_postgres::PgTransaction;

impl GroupStore {
    /// Register an authored definition without advancing observation or authority.
    pub async fn register_source_in(
        &self,
        tx: &mut PgTransaction<'_>,
        group: GroupId,
        revision: u64,
    ) -> InTransaction<()> {
        input!(self.check_transaction(tx)?);
        let revision = input!(i64::try_from(revision).map_err(|_| Rejection::VersionExhausted));
        if revision == 0 {
            return Ok(Err(Rejection::InvalidInput));
        }
        let tenant = self.tenant.to_string();
        let rows = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("INSERT INTO mdm_group.source_state(tenant_id,group_id,definition_version) VALUES($1::uuid,$2::uuid,$3) ON CONFLICT(tenant_id,group_id) DO UPDATE SET definition_version=excluded.definition_version WHERE source_state.definition_version<=excluded.definition_version")
                .bind(tenant).bind(group.to_string()).bind(revision).execute(c).await
        })).await?.rows_affected();
        Ok(if rows == 1 {
            Ok(())
        } else {
            Err(Rejection::VersionConflict)
        })
    }

    /// Capture the current authored identity and immutable membership result under its lock.
    pub async fn capture_source_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: GroupId,
    ) -> InTransaction<GroupSource> {
        self.sources.capture_source_in(tx, id).await
    }

    /// Complete frozen results remain usable across ordinary source advances.
    /// Explicit definition changes and deletion invalidate their authority.
    pub async fn source_current_in(
        &self,
        tx: &mut PgTransaction<'_>,
        source: &GroupSource,
    ) -> InTransaction<bool> {
        self.sources.source_current_in(tx, source).await
    }

    /// Wait on an unfinished source; reject only when a complete replacement supersedes it.
    pub async fn source_ready_in(
        &self,
        tx: &mut PgTransaction<'_>,
        source: &GroupSource,
    ) -> InTransaction<bool> {
        self.sources.source_ready_in(tx, source).await
    }

    /// Advance source authorization independently from membership semantics.
    pub(crate) async fn advance_authority_in(
        &self,
        tx: &mut PgTransaction<'_>,
        group: GroupId,
        authority: u64,
    ) -> InTransaction<bool> {
        input!(self.check_transaction(tx)?);
        let tenant = self.tenant.to_string();
        let previous=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar::<_,i64>("SELECT authority_version FROM mdm_group.source_state WHERE tenant_id=$1::uuid AND group_id=$2::uuid")
                .bind(tenant).bind(group.to_string()).fetch_optional(c).await
        })).await?.unwrap_or(0);
        let changed = authority > data(u64::try_from(previous))?;
        if changed {
            input!(self.advance_source_in(tx, group, authority).await?);
        }
        Ok(Ok(changed))
    }
    async fn advance_source_in(
        &self,
        tx: &mut PgTransaction<'_>,
        group: GroupId,
        value: u64,
    ) -> InTransaction<()> {
        input!(self.check_transaction(tx)?);
        let value = input!(i64::try_from(value).map_err(|_| Rejection::VersionExhausted));
        let sql = "UPDATE mdm_group.source_state SET authority_version=greatest(authority_version,$3) WHERE tenant_id=$1::uuid AND group_id=$2::uuid";
        let tenant = self.tenant.to_string();
        let rows = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query(sql)
                        .bind(tenant)
                        .bind(group.to_string())
                        .bind(value)
                        .execute(c)
                        .await
                })
            })
            .await?
            .rows_affected();
        Ok(if rows == 1 {
            Ok(())
        } else {
            Err(Rejection::NotFound)
        })
    }
}

/// Exact published membership required by a consumer of current results.
/// Unlike frozen source readability, this requires the current head to match.
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
pub struct CurrentMembership {
    /// Group identity in the bound tenant.
    pub id: uuid::Uuid,
    /// Authored group revision.
    pub revision: i64,
    /// Exact immutable published membership run.
    pub member_set: Option<uuid::Uuid>,
    /// Published membership version.
    pub member_version: i64,
}
impl GroupStore {
    /// Return only exact current Endpoint coordinates, preserving each requested version.
    pub async fn current_memberships_in(
        &self,
        tx: &mut PgTransaction<'_>,
        expected: &[CurrentMembership],
    ) -> InTransaction<Vec<CurrentMembership>> {
        input!(self.check_transaction(tx)?);
        if expected.len() > 1600 {
            return Ok(Err(Rejection::CapacityExceeded));
        }
        let tenant = self.tenant.to_string();
        let document = data(serde_json::to_string(expected))?;
        let ids=tx.with_connection(move|c|Box::pin(async move{
            sqlx::query_as::<_,(uuid::Uuid,i64,Option<uuid::Uuid>,i64)>("SELECT x.id,x.revision,x.member_set,x.member_version FROM jsonb_to_recordset($2::jsonb) x(id uuid,revision bigint,member_set uuid,member_version bigint) JOIN mdm_group.groups g ON g.tenant_id=$1::uuid AND g.id=x.id WHERE NOT g.deleted AND g.asset_context='endpoint' AND g.revision=x.revision AND g.member_set IS NOT DISTINCT FROM x.member_set AND g.member_version=x.member_version AND mdm_group.group_current(g.id)")
                .bind(tenant).bind(document).fetch_all(c).await
        })).await?;
        Ok(Ok(ids
            .into_iter()
            .map(
                |(id, revision, member_set, member_version)| CurrentMembership {
                    id,
                    revision,
                    member_set,
                    member_version,
                },
            )
            .collect()))
    }
}
