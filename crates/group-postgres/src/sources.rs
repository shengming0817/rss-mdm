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

/// Frozen membership coordinates whose semantics must still be current.
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
pub struct CurrentMembership {
    /// Group identity in the bound tenant.
    pub id: uuid::Uuid,
    /// Semantic definition revision; descriptive edits do not advance it.
    pub revision: i64,
    /// Exact immutable published membership run.
    pub member_set: Option<uuid::Uuid>,
    /// Published membership version.
    pub member_version: i64,
}
/// Current observation supporting a still-valid frozen membership result.
#[derive(serde::Serialize)]
pub struct CurrentMembershipState {
    /// The exact requested immutable coordinates, after semantic validation.
    #[serde(flatten)]
    pub membership: CurrentMembership,
    /// Latest complete dynamic input; static groups have no predicate input cut.
    pub input_version: Option<String>,
}
impl GroupStore {
    /// Validate semantic Endpoint coordinates and return the latest complete input observation.
    pub async fn current_memberships_in(
        &self,
        tx: &mut PgTransaction<'_>,
        expected: &[CurrentMembership],
    ) -> InTransaction<Vec<CurrentMembershipState>> {
        input!(self.check_transaction(tx)?);
        if expected.len() > 1600 {
            return Ok(Err(Rejection::CapacityExceeded));
        }
        let tenant = self.tenant.to_string();
        let document = data(serde_json::to_string(expected))?;
        let ids=tx.with_connection(move|c|Box::pin(async move{
            sqlx::query_as::<_,(uuid::Uuid,i64,Option<uuid::Uuid>,i64,Option<String>)>("SELECT x.id,x.revision,x.member_set,x.member_version,CASE WHEN g.kind<>'static' THEN head.input_version END FROM jsonb_to_recordset($2::jsonb) x(id uuid,revision bigint,member_set uuid,member_version bigint) JOIN mdm_group.groups g ON g.tenant_id=$1::uuid AND g.id=x.id JOIN mdm_group.source_state s ON(s.tenant_id,s.group_id)=(g.tenant_id,g.id) LEFT JOIN mdm_group.member_runs head ON(head.tenant_id,head.id)=(g.tenant_id,g.member_set) LEFT JOIN mdm_group.member_runs frozen ON(frozen.tenant_id,frozen.id)=(g.tenant_id,x.member_set) WHERE NOT g.deleted AND g.asset_context='endpoint' AND s.definition_version=x.revision AND g.member_version=x.member_version AND mdm_group.group_current(g.id) AND (x.member_set IS NULL AND g.kind='static' AND x.member_version=0 OR frozen.group_id=g.id AND frozen.phase='published' AND (convert_from(frozen.receipt,'UTF8')::jsonb->'group'->>'member_version')::bigint=x.member_version AND frozen.rule_version IS NOT DISTINCT FROM g.rule_version)")
                .bind(tenant).bind(document).fetch_all(c).await
        })).await?;
        Ok(Ok(ids
            .into_iter()
            .map(
                |(id, revision, member_set, member_version, input_version)| {
                    CurrentMembershipState {
                        membership: CurrentMembership {
                            id,
                            revision,
                            member_set,
                            member_version,
                        },
                        input_version,
                    }
                },
            )
            .collect()))
    }
}

impl GroupStore {
    /// Current candidate groups for bounded changed devices. Unknown is retained;
    /// only an explicit current negative membership can suppress reevaluation.
    pub async fn input_candidate_groups_in(
        &self,
        tx: &mut PgTransaction<'_>,
        groups: &[uuid::Uuid],
        devices: &[rss_mdm_agent_wire::DeviceId],
    ) -> InTransaction<Vec<uuid::Uuid>> {
        input!(self.check_transaction(tx)?);
        if groups.len() > 16 || devices.len() > 1000 {
            return Ok(Err(Rejection::CapacityExceeded));
        }
        let groups = groups.to_vec();
        let devices = devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>();
        let result = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT mdm_group.input_candidate_groups($1,$2)")
                        .bind(groups)
                        .bind(devices)
                        .fetch_all(c)
                        .await
                })
            })
            .await?;
        Ok(Ok(result))
    }
}
