//! Read-only Group participation, independent of the Group writer profile.
use crate::{
    BuildRequest, DecisionOrigin, DecisionRecord, DecisionValue, MemberBuild,
    decisions::manual,
    model::*,
    storage::{self as db, data, stored_shape},
    store::{active, input},
};
use rss_mdm_group::{GroupId, GroupSource, OperationId, SourceCoordinates};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use sqlx::Row;
use std::sync::Arc;

/// A caller-bound reader of immutable Group results with a narrow reference-lock capability.
pub struct GroupSources {
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
}
impl GroupSources {
    pub(crate) fn bound(runtime: Arc<PgRuntime>, tenant: TenantId) -> Self {
        Self { runtime, tenant }
    }
    /// Admit only the source-reader profile, without Group mutation or Outbox privileges.
    pub async fn bind(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        deadline: OperationDeadline,
    ) -> Result<Self, Error> {
        crate::model::settle(
            runtime
                .local_tx(tenant, deadline, |tx| {
                    Box::pin(async move {
                        crate::admission::verify_sources(tx).await?;
                        Ok(Ok(()))
                    })
                })
                .await,
            None,
        )?;
        Ok(Self::bound(runtime, tenant))
    }
    fn check_transaction(&self, tx: &PgTransaction<'_>) -> InTransaction<()> {
        self.runtime.validate_transaction(tx)?;
        Ok(if self.tenant == tx.tenant_id() {
            Ok(())
        } else {
            Err(Rejection::TenantMismatch)
        })
    }
    async fn locked_group_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: GroupId,
    ) -> Result<Option<Group>, PgError> {
        let row = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query("SELECT * FROM mdm_group.lock_reference_target($1::uuid)")
                        .bind(id.to_string())
                        .fetch_optional(c)
                        .await
                })
            })
            .await?;
        row.map(|row| db::decode_group(id, row)).transpose()
    }
    /// Read Group-owned source facts in the initiating transaction.
    pub(crate) async fn get_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: GroupId,
    ) -> InTransaction<Option<Group>> {
        input!(self.check_transaction(tx)?);
        Ok(Ok(db::group(tx, id, false).await?))
    }

    /// Read Group-owned source facts in the initiating transaction.
    pub async fn lock_reference_target_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: GroupId,
    ) -> InTransaction<Group> {
        input!(self.check_transaction(tx)?);
        let g = input!(
            self.locked_group_in(tx, id)
                .await?
                .ok_or(Rejection::NotFound)
        );
        input!(active(&g));
        Ok(Ok(g))
    }

    /// Read Group-owned source facts in the initiating transaction.
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

    /// Read Group-owned source facts in the initiating transaction.
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
        let group = input!(self.get_in(tx, source.group).await?);
        if let Some(run) = source.coordinates.member_set {
            let build = input!(self.build_in(tx, run).await?);
            return Ok(Ok(group.is_some_and(|g| {
                !g.deleted
                    && build.request.group == source.group
                    && build.request.rule_version == g.rule_version
                    && build.receipt.is_some()
            })));
        }
        Ok(Ok(group.is_some_and(|g| {
            !g.deleted && g.kind == GroupKind::Static
        })))
    }

    /// Read Group-owned source facts in the initiating transaction.
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

    /// Read Group-owned source facts in the initiating transaction.
    pub(crate) async fn current_member_set_in(
        &self,
        tx: &mut PgTransaction<'_>,
        group: GroupId,
    ) -> InTransaction<Option<OperationId>> {
        input!(self.check_transaction(tx)?);
        input!(self.lock_reference_target_in(tx, group).await?);
        let tenant = self.tenant.to_string();
        let raw:Option<String>=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT member_set::text FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(tenant).bind(group.to_string()).fetch_one(c).await
        })).await?;
        Ok(Ok(raw.map(|s| data(OperationId::parse(&s))).transpose()?))
    }

    /// Read Group-owned source facts in the initiating transaction.
    pub async fn build_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
    ) -> InTransaction<MemberBuild> {
        input!(self.check_transaction(tx)?);
        let tenant = self.tenant.to_string();
        let row=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT input,fingerprint,phase,cursor,diff_cursor,object_count,processed_count,member_count,receipt,authority_version FROM mdm_group.member_runs WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(tenant).bind(id.to_string()).fetch_optional(c).await
        })).await?;
        let row = input!(row.ok_or(Rejection::NotFound));
        let document: Vec<u8> = row.try_get("input")?;
        db::document(&document, row.try_get("fingerprint")?)?;
        let request: BuildRequest = data(serde_json::from_slice(&document))?;
        if request.id != id {
            return Err(stored_shape());
        }
        let phase: &str = row.try_get("phase")?;
        if phase == "superseded" {
            return Ok(Err(Rejection::VersionConflict));
        }
        if !matches!(phase, "reading" | "diff" | "ready" | "published") {
            return Err(stored_shape());
        }
        Ok(Ok(MemberBuild {
            published_authority: row
                .try_get::<Option<i64>, _>("authority_version")?
                .map(|v| data(u64::try_from(v)))
                .transpose()?,
            request,
            cursor: row.try_get("cursor")?,
            difference_cursor: row.try_get("diff_cursor")?,
            objects: data(usize::try_from(row.try_get::<i64, _>("object_count")?))?,
            processed: data(usize::try_from(row.try_get::<i64, _>("processed_count")?))?,
            members: data(usize::try_from(row.try_get::<i64, _>("member_count")?))?,
            input_sealed: phase != "reading",
            ready: matches!(phase, "ready" | "published"),
            receipt: row
                .try_get::<Option<Vec<u8>>, _>("receipt")?
                .map(|b| data(serde_json::from_slice(&b)))
                .transpose()?,
        }))
    }

    /// Read Group-owned source facts in the initiating transaction.
    pub(crate) async fn build_members_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
        after: Option<String>,
        limit: usize,
    ) -> InTransaction<Vec<String>> {
        input!(self.check_transaction(tx)?);
        if !(1..=usize::from(rss_mdm_query::MAX_PAGE_LIMIT) + 1).contains(&limit) {
            return Ok(Err(Rejection::InvalidInput));
        }
        let build = input!(self.build_in(tx, id).await?);
        if !build.input_sealed {
            return Ok(Err(Rejection::IncompleteSnapshot));
        }
        if build.request.patch.is_some() {
            let tenant = self.tenant.to_string();
            let group = build.request.group.to_string();
            let base = build.request.base_calculation;
            return Ok(Ok(tx.with_connection(move |c|Box::pin(async move {
                sqlx::query_scalar("SELECT object_id FROM (SELECT DISTINCT ON (m.object_id) m.object_id,m.added FROM mdm_group.member_changes m WHERE m.tenant_id=$1::uuid AND m.group_id=$2::uuid AND ((m.revision<=$3 AND EXISTS(SELECT 1 FROM mdm_group.member_runs r WHERE r.tenant_id=m.tenant_id AND r.id=m.run_id AND r.phase='published' OFFSET 0)) OR m.run_id=$4::uuid) AND m.object_id>coalesce($5::text,'') COLLATE \"C\" ORDER BY m.object_id,m.revision DESC) latest WHERE added ORDER BY object_id LIMIT $6")
                    .bind(tenant).bind(group).bind(base).bind(id.to_string()).bind(after).bind(limit as i64).fetch_all(c).await
            })).await?));
        }
        Ok(Ok(crate::history::metadata(
            tx, id, after, None, limit, true,
        )
        .await?
        .into_iter()
        .map(|r| r.try_get("object_id"))
        .collect::<Result<Vec<String>, sqlx::Error>>()?))
    }

    /// Read Group-owned source facts in the initiating transaction.
    pub async fn build_decisions_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
        after: Option<String>,
        limit: usize,
    ) -> InTransaction<Vec<DecisionRecord>> {
        crate::store::input!(self.check_transaction(tx)?);
        if !(1..=usize::from(rss_mdm_query::MAX_PAGE_LIMIT) + 1).contains(&limit) {
            return Ok(Err(Rejection::InvalidInput));
        }
        let build = crate::store::input!(self.build_in(tx, id).await?);
        if !build.input_sealed {
            return Ok(Err(Rejection::IncompleteSnapshot));
        }
        if build.request.patch.is_some() {
            let devices = crate::store::input!(self.build_members_in(tx, id, after, limit).await?);
            return Ok(Ok(devices.into_iter().map(manual).collect()));
        }
        let rows = crate::history::rows(tx, id, after, limit).await?;
        let mut result = Vec::new();
        for row in rows {
            let bytes: Vec<u8> = row.try_get("evidence")?;
            crate::storage::document(&bytes, row.try_get("evidence_digest")?)?;
            let record: DecisionRecord = data(serde_json::from_slice(&bytes))?;
            if record.device != row.try_get::<String, _>("object_id")?
                || (record.decision == DecisionValue::Match) != row.try_get::<bool, _>("matched")?
                || (record.origin == DecisionOrigin::Manual) != build.request.patch.is_some()
            {
                return Err(stored_shape());
            }
            result.push(record);
        }
        Ok(Ok(result))
    }
}
