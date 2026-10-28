//! Authored source identity and observation progress have separate coordinates.
use crate::{GroupKind, GroupStore, InTransaction, Rejection, storage::data, store::input};
use rss_mdm_group::{GroupId, GroupSource, SourceCoordinates};
use rss_transactional_messaging_postgres::PgTransaction;

enum Coordinate {
    Required,
    Observed,
    Authority,
}

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
        input!(self.check_transaction(tx)?);
        let group = input!(self.lock_reference_target_in(tx, id).await?);
        let tenant = self.tenant.to_string();
        let row = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_as::<_, (i64,i64)>("SELECT definition_version,authority_version FROM mdm_group.source_state WHERE tenant_id=$1::uuid AND group_id=$2::uuid")
                .bind(tenant).bind(id.to_string()).fetch_optional(c).await
        })).await?;
        let (definition, authority) = input!(row.ok_or(Rejection::IncompleteSnapshot));
        Ok(Ok(GroupSource {
            group: id,
            coordinates: SourceCoordinates {
                member_set: input!(self.current_member_set_in(tx, id).await?),
                member_version: data(u64::try_from(group.member_version))?,
                definition_version: data(u64::try_from(definition))?,
                authority_version: data(u64::try_from(authority))?,
                asset_context: group.asset_context,
            },
        }))
    }

    /// Complete frozen results remain usable across ordinary source advances.
    /// Explicit definition changes and deletion invalidate their authority.
    pub async fn source_current_in(
        &self,
        tx: &mut PgTransaction<'_>,
        source: &GroupSource,
    ) -> InTransaction<bool> {
        input!(self.check_transaction(tx)?);
        let current = input!(self.capture_source_in(tx, source.group).await?);
        if current.coordinates.definition_version != source.coordinates.definition_version
            || current.coordinates.asset_context != source.coordinates.asset_context
        {
            return Ok(Ok(false));
        }
        if let Some(run) = source.coordinates.member_set {
            let build = input!(self.build_in(tx, run).await?);
            return Ok(Ok(
                build.request.group == source.group && build.receipt.is_some()
            ));
        }
        let group = input!(self.get_in(tx, source.group).await?);
        Ok(Ok(group.is_some_and(|g| {
            !g.deleted && g.kind == GroupKind::Static
        })))
    }

    /// Wait on an unfinished source; reject only when a complete replacement supersedes it.
    pub async fn source_ready_in(
        &self,
        tx: &mut PgTransaction<'_>,
        source: &GroupSource,
    ) -> InTransaction<bool> {
        if input!(self.source_current_in(tx, source).await?) {
            return Ok(Ok(true));
        }
        let current = input!(self.capture_source_in(tx, source.group).await?);
        if input!(self.source_current_in(tx, &current).await?) {
            return Ok(Err(Rejection::VersionConflict));
        }
        Ok(Ok(false))
    }

    /// Read the committed coverage of a Group calculation, never a global sequence maximum.
    pub async fn observed_input_in(
        &self,
        tx: &mut PgTransaction<'_>,
        group: GroupId,
    ) -> InTransaction<u64> {
        input!(self.check_transaction(tx)?);
        let tenant = self.tenant.to_string();
        let value = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar::<_, i64>("SELECT observed_input FROM mdm_group.source_state WHERE tenant_id=$1::uuid AND group_id=$2::uuid")
                .bind(tenant).bind(group.to_string()).fetch_one(c).await
        })).await?;
        Ok(Ok(data(u64::try_from(value))?))
    }

    /// Require convergence through this committed input watermark.
    pub async fn require_input_in(
        &self,
        tx: &mut PgTransaction<'_>,
        group: GroupId,
        watermark: u64,
    ) -> InTransaction<()> {
        self.advance_source_in(tx, group, watermark, Coordinate::Required)
            .await
    }
    /// Acknowledge only input proven covered by the published result.
    pub async fn observe_input_in(
        &self,
        tx: &mut PgTransaction<'_>,
        group: GroupId,
        watermark: u64,
    ) -> InTransaction<()> {
        self.advance_source_in(tx, group, watermark, Coordinate::Observed)
            .await
    }
    /// Advance source authorization independently from membership semantics.
    pub(crate) async fn advance_authority_in(
        &self,
        tx: &mut PgTransaction<'_>,
        group: GroupId,
        authority: u64,
    ) -> InTransaction<()> {
        self.advance_source_in(tx, group, authority, Coordinate::Authority)
            .await
    }
    async fn advance_source_in(
        &self,
        tx: &mut PgTransaction<'_>,
        group: GroupId,
        value: u64,
        coordinate: Coordinate,
    ) -> InTransaction<()> {
        input!(self.check_transaction(tx)?);
        let value = input!(i64::try_from(value).map_err(|_| Rejection::VersionExhausted));
        let sql = match coordinate {
            Coordinate::Required => {
                "UPDATE mdm_group.source_state SET required_input=greatest(required_input,$3) WHERE tenant_id=$1::uuid AND group_id=$2::uuid"
            }
            Coordinate::Observed => {
                "UPDATE mdm_group.source_state SET observed_input=greatest(observed_input,$3) WHERE tenant_id=$1::uuid AND group_id=$2::uuid"
            }
            Coordinate::Authority => {
                "UPDATE mdm_group.source_state SET authority_version=greatest(authority_version,$3) WHERE tenant_id=$1::uuid AND group_id=$2::uuid"
            }
        };
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
