//! Bounded immutable membership construction; RSS and the host own worker fencing.
use crate::{
    GroupStore,
    model::*,
    storage::{self as db, data, digest, stored_shape},
    store::input,
};
use rss_contract::Timepoint;
use rss_mdm_group::{Decision, PageInput};
use rss_transactional_messaging_postgres::PgTransaction;
use serde::{Deserialize, Serialize};
use sqlx::Row;

/// Product capacity, independent of per-page evaluator budgets.
pub const MAX_MEMBERS: usize = 1_000_000;
/// Immutable identity of a caller-frozen input. Contains no full asset collection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildRequest {
    /// Idempotency and result identity.
    pub id: OperationId,
    /// Owning group.
    pub group: GroupId,
    /// Expected group CAS revision.
    pub expected: Revision,
    /// Published calculation captured at admission, independent of descriptive edits.
    pub base_calculation: i64,
    /// Exact device changes; absent requests a full rule evaluation.
    pub changed_devices: Option<Vec<String>>,
    /// Rule selected when the input was frozen.
    pub rule_version: Option<String>,
    /// Static membership patch, absent for a dynamic build.
    pub patch: Option<MemberPatch>,
    /// Frozen host input identity, unchanged across all pages and retries.
    pub input_version: String,
    /// Explicit evaluation time, not a validity deadline.
    #[serde(with = "time")]
    pub as_of: Timepoint,
}
/// A bounded explicit membership edit, applied to a frozen prior member set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberPatch {
    /// Device identities to add.
    pub add: Vec<String>,
    /// Device identities to remove; overlap with additions is rejected.
    pub remove: Vec<String>,
}
fn check_build(group: &Group, request: &BuildRequest) -> CommandOutcome<()> {
    crate::store::active(group)?;
    if (request.patch.is_some() && group.revision != request.expected)
        || group.calculation_revision != request.base_calculation
        || group.rule_version != request.rule_version
    {
        return Err(Rejection::VersionConflict);
    }
    if (group.kind == GroupKind::Static) != request.patch.is_some() {
        return Err(Rejection::KindMismatch);
    }
    Ok(())
}
mod time {
    use super::*;
    pub fn serialize<S: serde::Serializer>(value: &Timepoint, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_i64(value.unix_seconds())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Timepoint, D::Error> {
        Timepoint::try_from(i64::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
/// Durable membership construction progress. No partial set is current membership.
#[derive(Clone, Debug)]
pub struct MemberBuild {
    /// Original immutable admission.
    pub request: BuildRequest,
    /// Last input object atomically persisted with its page.
    pub cursor: Option<String>,
    /// Last key whose membership difference has been durably examined.
    pub difference_cursor: Option<String>,
    /// Number of input objects already persisted.
    pub objects: usize,
    /// Devices evaluated in this calculation; deltas do not count unchanged devices.
    pub processed: usize,
    /// Number of matches already persisted.
    pub members: usize,
    /// Whether input enumeration has been sealed.
    pub input_sealed: bool,
    /// Whether the complete difference has been persisted.
    pub ready: bool,
    /// Final result, once explicitly published.
    pub receipt: Option<Receipt>,
}

/// One bounded difference step and the identities examined in that transaction.
/// The host may resolve identity versions for these keys under its frozen input.
pub struct DifferenceStep {
    /// Durable progress after the step.
    pub build: MemberBuild,
    /// Sorted old-or-new member identities, at most 1,000.
    pub devices: Vec<String>,
}

impl GroupStore {
    /// Find live static groups containing any supplied device in their latest
    /// published membership, optionally including every live dynamic group.
    /// Device input is bounded to 1,000 and result pages to 33; `after`
    /// is an exclusive group cursor. Unpublished changes never affect this view.
    pub async fn affected_groups_in(
        &self,
        tx: &mut PgTransaction<'_>,
        devices: &[String],
        include_dynamic: bool,
        after: Option<GroupId>,
        limit: usize,
    ) -> InTransaction<Vec<GroupId>> {
        input!(self.check_transaction(tx)?);
        if devices.len() > 1000 || !(1..=33).contains(&limit) {
            return Ok(Err(Rejection::InvalidInput));
        }
        for device in devices {
            if device.len() > 256 {
                return Ok(Err(Rejection::InvalidInput));
            }
            input!(
                rss_mdm_group::ObjectKey::new(self.tenant, device)
                    .map_err(crate::store::core_rejection)
            );
        }
        let tenant = self.tenant.to_string();
        let devices = devices.to_vec();
        let after = after.map(|id| id.to_string());
        let rows: Vec<String> = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        r#"
                SELECT id::text FROM (
                    SELECT hit.group_id AS id FROM unnest($2::text[]) device
                    CROSS JOIN LATERAL (
                        SELECT latest.group_id FROM (
                            SELECT DISTINCT ON(m.group_id) m.group_id,m.added
                            FROM mdm_group.member_changes m
                            WHERE m.tenant_id=$1::uuid AND m.object_id=device
                                AND ($4::uuid IS NULL OR m.group_id>$4::uuid)
                                AND EXISTS(SELECT 1 FROM mdm_group.member_runs r
                                    WHERE r.tenant_id=m.tenant_id AND r.id=m.run_id AND r.phase='published')
                            ORDER BY m.group_id,m.revision DESC
                        ) latest JOIN mdm_group.groups g ON g.tenant_id=$1::uuid AND g.id=latest.group_id
                        WHERE latest.added AND g.kind='static' AND NOT g.deleted
                        ORDER BY latest.group_id LIMIT $5
                    ) hit
                    UNION
                    (SELECT id FROM mdm_group.groups WHERE tenant_id=$1::uuid
                        AND $3 AND kind='dynamic' AND NOT deleted
                        AND ($4::uuid IS NULL OR id>$4::uuid)
                     ORDER BY id LIMIT $5)
                ) affected ORDER BY id LIMIT $5
            "#,
                    )
                    .bind(tenant)
                    .bind(devices)
                    .bind(include_dynamic)
                    .bind(after)
                    .bind(limit as i64)
                    .fetch_all(c)
                    .await
                })
            })
            .await?;
        Ok(Ok(rows
            .iter()
            .map(|id| data(GroupId::parse(id)))
            .collect::<Result<_, _>>()?))
    }

    /// Read the immutable current member-set handle; None means the initial empty set.
    pub async fn current_member_set_in(
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
    /// Admit immutable metadata, not a whole-tenant blob. The host supplies pages
    /// from one frozen source and protects each mutation with its RSS claim.
    pub async fn begin_build_in(
        &self,
        tx: &mut PgTransaction<'_>,
        request: &BuildRequest,
    ) -> InTransaction<MemberBuild> {
        input!(self.check_transaction(tx)?);
        if request.input_version.is_empty() || request.input_version.len() > 4096 {
            return Ok(Err(Rejection::InvalidInput));
        }
        let document = input!(serde_json::to_vec(request).map_err(|_| Rejection::InvalidInput));
        let fingerprint = digest(&document);
        let group = input!(
            db::group(tx, request.group, true)
                .await?
                .ok_or(Rejection::NotFound)
        );
        let tenant = self.tenant.to_string();
        let id = request.id.to_string();
        let old = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar::<_,Vec<u8>>("SELECT fingerprint FROM mdm_group.member_runs WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(tenant).bind(id).fetch_optional(c).await
        })).await?;
        if let Some(old) = old {
            if old != fingerprint {
                return Ok(Err(Rejection::IdentityConflict));
            }
            return self.build_in(tx, request.id).await;
        }
        if group.revision != request.expected {
            return Ok(Err(Rejection::VersionConflict));
        }
        input!(check_build(&group, request));
        if let Some(patch) = &request.patch {
            if patch.add.len() + patch.remove.len() > 1000
                || patch.add.iter().any(|id| patch.remove.contains(id))
            {
                return Ok(Err(Rejection::InvalidInput));
            }
            for id in patch.add.iter().chain(&patch.remove) {
                if id.len() > 256 {
                    return Ok(Err(Rejection::InvalidInput));
                }
                input!(
                    rss_mdm_group::ObjectKey::new(self.tenant, id)
                        .map_err(crate::store::core_rejection)
                );
            }
        }
        if let Some(devices) = &request.changed_devices {
            if request.patch.is_some()
                || devices.len() > 1000
                || devices.windows(2).any(|v| v[0] >= v[1])
            {
                return Ok(Err(Rejection::InvalidInput));
            }
            for device in devices {
                input!(
                    rss_mdm_group::ObjectKey::new(self.tenant, device)
                        .map_err(crate::store::core_rejection)
                );
            }
        }
        let tenant = self.tenant.to_string();
        let r = request.clone();
        let base_members = if request.changed_devices.is_some() {
            group.member_count as i64
        } else {
            0
        };
        let base_objects = if request.changed_devices.is_some() {
            let previous =
                input!(self.current_member_set_in(tx, group.id).await?).ok_or_else(stored_shape)?;
            input!(self.build_in(tx, previous).await?).objects as i64
        } else {
            0
        };
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("INSERT INTO mdm_group.member_runs(tenant_id,id,group_id,base_revision,rule_version,input_version,fingerprint,input,phase,as_of,base_calculation,floor_revision,member_count,object_count) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,'reading',$9,$10,CASE WHEN $11 THEN (SELECT b.floor_revision FROM mdm_group.groups g JOIN mdm_group.member_runs b ON(b.tenant_id,b.id)=(g.tenant_id,g.member_set) WHERE g.tenant_id=$1::uuid AND g.id=$3::uuid) ELSE $10 END,$12,$13)")
                .bind(tenant).bind(r.id.to_string()).bind(r.group.to_string()).bind(r.expected.get()).bind(r.rule_version)
                .bind(r.input_version).bind(fingerprint).bind(document).bind(r.as_of.unix_seconds()).bind(r.base_calculation).bind(r.changed_devices.is_some()).bind(base_members).bind(base_objects).execute(c).await?;
            Ok(())
        })).await?;
        self.build_in(tx, request.id).await
    }

    /// Read bounded progress and an optional compact publication receipt.
    pub async fn build_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
    ) -> InTransaction<MemberBuild> {
        input!(self.check_transaction(tx)?);
        let tenant = self.tenant.to_string();
        let row=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT input,fingerprint,phase,cursor,diff_cursor,object_count,processed_count,member_count,receipt FROM mdm_group.member_runs WHERE tenant_id=$1::uuid AND id=$2::uuid")
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

    /// Validate and persist a nonempty page with its exclusive cursor. Original
    /// page retries compare their canonical input fingerprint before any writes.
    pub async fn append_build_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
        page: &PageInput<'_>,
    ) -> InTransaction<MemberBuild> {
        input!(self.check_transaction(tx)?);
        let build = input!(self.build_in(tx, id).await?);
        let g = input!(
            db::group(tx, build.request.group, true)
                .await?
                .ok_or(Rejection::NotFound)
        );
        let build = input!(self.build_in(tx, id).await?);
        input!(check_build(&g, &build.request));
        if g.kind != GroupKind::Dynamic {
            return Ok(Err(Rejection::KindMismatch));
        }
        if page.tenant != self.tenant
            || page.version != build.request.input_version
            || g.rule_version != build.request.rule_version
        {
            return Ok(Err(Rejection::VersionConflict));
        }
        let Some(first) = page.objects.first() else {
            return Ok(Err(Rejection::InvalidInput));
        };
        let rule = db::rule(
            tx,
            g.id,
            input!(
                build
                    .request
                    .rule_version
                    .clone()
                    .ok_or(Rejection::KindMismatch)
            ),
        )
        .await?;
        if let Some(devices) = &build.request.changed_devices
            && page.objects.iter().any(|o| {
                devices
                    .binary_search_by(|d| d.as_str().cmp(o.key.id()))
                    .is_err()
            })
        {
            return Ok(Err(Rejection::InvalidInput));
        }
        let evaluated = input!(
            rule.evaluate_page(page, build.request.as_of)
                .map_err(crate::store::core_rejection)
        );
        let fingerprint = db::fingerprint(&[
            &input!(crate::codec::encode_page(page).map_err(|_| Rejection::PageBudgetExceeded)),
            page.after.map_or("", |k| k.id()).as_bytes(),
        ]);
        let tenant = self.tenant.to_string();
        let first_id = first.key.id().to_owned();
        let old=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar::<_,Vec<u8>>("SELECT fingerprint FROM mdm_group.member_pages WHERE tenant_id=$1::uuid AND run_id=$2::uuid AND first_id=$3")
                .bind(tenant).bind(id.to_string()).bind(first_id).fetch_optional(c).await
        })).await?;
        if let Some(old) = old {
            return Ok(if old == fingerprint {
                Ok(build)
            } else {
                Err(Rejection::IdentityConflict)
            });
        }
        if build.input_sealed || build.cursor.as_deref() != page.after.map(|k| k.id()) {
            return Ok(Err(Rejection::InvalidInput));
        }
        if build.request.changed_devices.is_none() && !page_fits(build.objects, page.objects.len())
        {
            return Ok(Err(Rejection::CapacityExceeded));
        }
        let mut ids = Vec::new();
        let mut matches = Vec::new();
        let mut evidence = Vec::new();
        for object in evaluated.objects {
            if object.key.id().len() > 256 {
                return Ok(Err(Rejection::InvalidInput));
            }
            ids.push(object.key.id().to_owned());
            matches.push(object.decision == Decision::Match);
            evidence.push(data(serde_json::to_vec(&crate::decisions::evaluated(
                object,
            )))?);
        }
        self.store_page_in(tx, id, ids, matches, evidence, fingerprint)
            .await
    }
    async fn store_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
        ids: Vec<String>,
        matches: Vec<bool>,
        evidence: Vec<Vec<u8>>,
        fingerprint: Vec<u8>,
    ) -> InTransaction<MemberBuild> {
        if evidence.iter().any(|bytes| bytes.len() > 1024 * 1024)
            || evidence
                .iter()
                .map(|bytes| bytes.len() + 1024)
                .sum::<usize>()
                > 16 * 1024 * 1024
        {
            return Ok(Err(Rejection::PageBudgetExceeded));
        }
        let hashes: Vec<_> = evidence.iter().map(|bytes| digest(bytes)).collect();
        let count = ids.len() as i64;
        let mut members = matches.iter().filter(|v| **v).count() as i64;
        let mut objects = count;
        let build = input!(self.build_in(tx, id).await?);
        if build.request.changed_devices.is_some() {
            let previous = input!(self.current_member_set_in(tx, build.request.group).await?)
                .ok_or_else(stored_shape)?;
            let old = crate::history::metadata(tx, previous, None, Some(ids.clone()), 1000, false)
                .await?;
            objects -= old.len() as i64;
            for row in old {
                members -= i64::from(row.try_get::<bool, _>("matched")?);
            }
        }
        let tenant = self.tenant.to_string();
        let first = ids.first().ok_or_else(stored_shape)?.clone();
        let last = ids.last().ok_or_else(stored_shape)?.clone();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_group.member_rows SELECT $1::uuid,$2::uuid,* FROM unnest($3::text[],$4::boolean[],$5::bytea[],$6::bytea[])")
                .bind(&tenant).bind(id.to_string()).bind(ids).bind(matches).bind(evidence).bind(hashes).execute(&mut *c).await?;
            sqlx::query("INSERT INTO mdm_group.member_pages VALUES($1::uuid,$2::uuid,$3,$4,$5)")
                .bind(&tenant).bind(id.to_string()).bind(first).bind(&last).bind(fingerprint).execute(&mut *c).await?;
            sqlx::query("UPDATE mdm_group.member_runs SET cursor=$3,object_count=object_count+$4,member_count=member_count+$5,processed_count=processed_count+$6 WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(tenant).bind(id.to_string()).bind(last).bind(objects).bind(members).bind(count).execute(c).await?;
            Ok(())
        })).await?;
        self.build_in(tx, id).await
    }

    /// Advance a static patch by one bounded merge page. Static and dynamic
    /// builds share storage, difference computation, CAS and publication.
    pub async fn advance_static_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
    ) -> InTransaction<MemberBuild> {
        input!(self.check_transaction(tx)?);
        let build = input!(self.build_in(tx, id).await?);
        let group = input!(
            db::group(tx, build.request.group, true)
                .await?
                .ok_or(Rejection::NotFound)
        );
        let build = input!(self.build_in(tx, id).await?);
        input!(check_build(&group, &build.request));
        let patch = input!(build.request.patch.clone().ok_or(Rejection::KindMismatch));
        if build.input_sealed {
            return Ok(Ok(build));
        }
        let wanted: std::collections::BTreeMap<String, bool> = patch
            .remove
            .into_iter()
            .map(|id| (id, false))
            .chain(patch.add.into_iter().map(|id| (id, true)))
            .collect();
        let tenant = self.tenant.to_string();
        let group_id = group.id.to_string();
        let selected: Vec<_> = wanted.keys().cloned().collect();
        let old=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT d,coalesce((SELECT m.added FROM mdm_group.member_changes m JOIN mdm_group.member_runs r ON (r.tenant_id,r.id)=(m.tenant_id,m.run_id) WHERE m.tenant_id=$1::uuid AND m.group_id=$2::uuid AND m.object_id=d AND r.phase='published' ORDER BY m.revision DESC LIMIT 1),false) AS present FROM unnest($3::text[]) d")
                .bind(tenant).bind(group_id).bind(selected).fetch_all(c).await
        })).await?;
        let mut ids = Vec::new();
        let mut values = Vec::new();
        for row in old {
            let key: String = row.try_get("d")?;
            let new = *wanted.get(&key).ok_or_else(stored_shape)?;
            if new != row.try_get::<bool, _>("present")? {
                ids.push(key);
                values.push(new);
            }
        }
        let added = values.iter().filter(|v| **v).count();
        let removed = values.len() - added;
        let members = input!(member_count_after_patch(group.member_count, added, removed));
        let tenant = self.tenant.to_string();
        let group_id = group.id.to_string();
        let revision = input!(
            group
                .calculation_revision
                .checked_add(1)
                .ok_or(Rejection::VersionExhausted)
        );
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_group.member_changes(tenant_id,run_id,object_id,group_id,revision,added) SELECT $1::uuid,$2::uuid,d,$3::uuid,$4,v FROM unnest($5::text[],$6::boolean[]) AS p(d,v)")
                .bind(&tenant).bind(id.to_string()).bind(group_id).bind(revision).bind(ids).bind(values).execute(&mut *c).await?;
            sqlx::query("UPDATE mdm_group.member_runs SET object_count=$3,member_count=$3,processed_count=$3,added=$4,removed=$5,phase='diff' WHERE tenant_id=$1::uuid AND id=$2::uuid AND phase='reading'")
                .bind(tenant).bind(id.to_string()).bind(members as i64).bind(added as i64).bind(removed as i64).execute(c).await?;Ok(())
        })).await?;
        self.build_in(tx, id).await
    }

    /// Seal a host-confirmed complete enumeration. This transition is separate
    /// from pages; an empty page is never used as implicit completeness evidence.
    pub async fn seal_build_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
        objects: usize,
    ) -> InTransaction<MemberBuild> {
        input!(self.check_transaction(tx)?);
        let build = input!(self.build_in(tx, id).await?);
        let group = input!(
            db::group(tx, build.request.group, true)
                .await?
                .ok_or(Rejection::NotFound)
        );
        let build = input!(self.build_in(tx, id).await?);
        input!(check_build(&group, &build.request));
        if build.input_sealed {
            return Ok(Ok(build));
        }
        if objects != build.processed {
            return Ok(Err(Rejection::IncompleteSnapshot));
        }
        if !build.input_sealed {
            input!(self.seal_missing_delta_in(tx, id, &build).await?);
            let tenant = self.tenant.to_string();
            tx.with_connection(move |c|Box::pin(async move {
                sqlx::query("UPDATE mdm_group.member_runs SET phase='diff' WHERE tenant_id=$1::uuid AND id=$2::uuid AND phase='reading'")
                    .bind(tenant).bind(id.to_string()).execute(c).await?;Ok(())
            })).await?;
        }
        self.build_in(tx, id).await
    }

    /// Merge at most 1,000 keys from two immutable member sets, persisting their
    /// difference and cursor together. Publication never performs this large work.
    pub async fn advance_difference_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
    ) -> InTransaction<DifferenceStep> {
        input!(self.check_transaction(tx)?);
        let build = input!(self.build_in(tx, id).await?);
        let group = input!(
            db::group(tx, build.request.group, true)
                .await?
                .ok_or(Rejection::NotFound)
        );
        input!(check_build(&group, &build.request));
        let build = input!(self.build_in(tx, id).await?);
        if build.ready {
            return Ok(Ok(DifferenceStep {
                build,
                devices: vec![],
            }));
        }
        if !build.input_sealed {
            return Ok(Err(Rejection::IncompleteSnapshot));
        }
        let previous = input!(self.current_member_set_in(tx, group.id).await?);
        if let Some(step) = input!(self.static_difference_in(tx, id, &build, previous).await?) {
            return Ok(Ok(step));
        }
        if build.request.changed_devices.is_some() {
            return self.delta_difference_in(tx, id, &build, previous).await;
        }
        let after = build.difference_cursor.clone();
        let old = if let Some(previous) = previous {
            input!(
                self.build_members_in(tx, previous, after.clone(), 1000)
                    .await?
            )
        } else {
            vec![]
        };
        let new = input!(self.build_members_in(tx, id, after.clone(), 1000).await?);
        let DifferencePage {
            devices,
            ids,
            changes,
            more,
        } = difference_page(old, new);
        let last = devices.last().cloned().or(after);
        let added = changes.iter().filter(|v| **v).count() as i64;
        let removed = changes.len() as i64 - added;
        let tenant = self.tenant.to_string();
        let dynamic = build.request.patch.is_none();
        tx.with_connection(move |c|Box::pin(async move {
            if dynamic {
                sqlx::query("INSERT INTO mdm_group.member_changes(tenant_id,run_id,object_id,group_id,revision,added) SELECT r.tenant_id,r.id,d,r.group_id,r.base_calculation+1,v FROM mdm_group.member_runs r CROSS JOIN unnest($3::text[],$4::boolean[]) AS p(d,v) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid")
                    .bind(&tenant).bind(id.to_string()).bind(ids).bind(changes).execute(&mut *c).await?;
            }
            sqlx::query("UPDATE mdm_group.member_runs SET diff_cursor=$3,added=added+$4,removed=removed+$5,phase=$6 WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(tenant).bind(id.to_string()).bind(last).bind(if dynamic {added}else{0}).bind(if dynamic {removed}else{0}).bind(if more {"diff"}else{"ready"}).execute(c).await?;Ok(())
        })).await?;
        let build = input!(self.build_in(tx, id).await?);
        Ok(Ok(DifferenceStep { build, devices }))
    }

    async fn static_difference_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
        build: &MemberBuild,
        previous: Option<OperationId>,
    ) -> InTransaction<Option<DifferenceStep>> {
        // A static edit already has its complete difference. If the host's
        // immutable input is unchanged, only edited identities need refreshing;
        // prior identity authority remains valid for every unchanged member.
        if build.request.patch.is_some() {
            let same_input = match previous {
                None => true,
                Some(previous) => {
                    input!(self.build_in(tx, previous).await?)
                        .request
                        .input_version
                        == build.request.input_version
                }
            };
            if same_input {
                let tenant = self.tenant.to_string();
                let devices=tx.with_connection(move |c|Box::pin(async move {
                    let devices=sqlx::query_scalar::<_,String>("SELECT object_id FROM mdm_group.member_changes WHERE tenant_id=$1::uuid AND run_id=$2::uuid ORDER BY object_id LIMIT 1000")
                        .bind(&tenant).bind(id.to_string()).fetch_all(&mut *c).await?;
                    sqlx::query("UPDATE mdm_group.member_runs SET phase='ready',diff_cursor=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid")
                        .bind(tenant).bind(id.to_string()).bind(devices.last()).execute(c).await?;Ok(devices)
                })).await?;
                return Ok(Ok(Some(DifferenceStep {
                    build: input!(self.build_in(tx, id).await?),
                    devices,
                })));
            }
        }
        Ok(Ok(None))
    }

    /// Publish only a sealed, fully compared set under group CAS. The host declares
    /// the group Outbox partition and composes reference invalidation, audit and its
    /// input-watermark/RSS claim checks in this same transaction.
    pub async fn publish_build_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
    ) -> InTransaction<Receipt> {
        input!(self.check_transaction(tx)?);
        let build = input!(self.build_in(tx, id).await?);
        let mut group = input!(
            db::group(tx, build.request.group, true)
                .await?
                .ok_or(Rejection::NotFound)
        );
        let build = input!(self.build_in(tx, id).await?);
        if let Some(receipt) = build.receipt {
            return Ok(Ok(receipt));
        }
        input!(check_build(&group, &build.request));
        if !build.ready || group.rule_version != build.request.rule_version {
            return Ok(Err(Rejection::VersionConflict));
        }
        let tenant = self.tenant.to_string();
        let counts=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT added,removed FROM mdm_group.member_runs WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(tenant).bind(id.to_string()).fetch_one(c).await
        })).await?;
        let added = data(usize::try_from(counts.try_get::<i64, _>("added")?))?;
        let removed = data(usize::try_from(counts.try_get::<i64, _>("removed")?))?;
        group.calculation_revision = input!(
            group
                .calculation_revision
                .checked_add(1)
                .ok_or(Rejection::VersionExhausted)
        );
        if build
            .request
            .patch
            .as_ref()
            .is_some_and(|p| !p.add.is_empty() || !p.remove.is_empty())
        {
            group.revision = input!(group.revision.next());
        }
        group.member_count = build.members;
        let tenant = self.tenant.to_string();
        let owner = group.id.to_string();
        let semantic_changed = if build.request.patch.is_some() {
            added != 0 || removed != 0
        } else {
            tx.with_connection(move |c| Box::pin(async move {
                sqlx::query_scalar::<_,bool>("WITH latest AS (SELECT DISTINCT ON(m.object_id) m.object_id,convert_from(m.evidence,'UTF8')::jsonb->>'decision' AS decision FROM mdm_group.member_rows m JOIN mdm_group.member_runs r ON(r.tenant_id,r.id)=(m.tenant_id,m.run_id) WHERE m.tenant_id=$1::uuid AND r.group_id=$2::uuid AND r.phase='published' AND r.base_calculation >= coalesce((SELECT floor_revision FROM mdm_group.member_runs WHERE tenant_id=$1::uuid AND id=(SELECT member_set FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2::uuid)),0) ORDER BY m.object_id,r.base_calculation DESC), current AS (SELECT object_id,convert_from(evidence,'UTF8')::jsonb->>'decision' AS decision FROM mdm_group.member_rows WHERE tenant_id=$1::uuid AND run_id=$3::uuid) SELECT CASE WHEN $4 THEN EXISTS(SELECT 1 FROM current n LEFT JOIN latest o USING(object_id) WHERE n.decision<>coalesce(o.decision,'no_match')) ELSE EXISTS((SELECT * FROM latest WHERE decision<>'no_match' EXCEPT SELECT * FROM current WHERE decision<>'no_match') UNION ALL (SELECT * FROM current WHERE decision<>'no_match' EXCEPT SELECT * FROM latest WHERE decision<>'no_match')) END")
                    .bind(tenant).bind(owner).bind(id.to_string()).bind(build.request.changed_devices.is_some()).fetch_one(c).await
            })).await?
        };
        if semantic_changed {
            group.member_version = group.calculation_revision;
        }
        let receipt = Receipt {
            operation: id,
            group,
            added,
            removed,
        };
        if semantic_changed {
            self.append(
                tx,
                build.request.as_of,
                crate::event::ChangeKind::MembersChanged,
                &receipt,
            )
            .await?;
        }
        db::save_group(tx, &receipt.group, false).await?;
        let tenant = self.tenant.to_string();
        let group = receipt.group.id;
        let document = data(serde_json::to_vec(&receipt))?;
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("UPDATE mdm_group.groups SET member_set=$3::uuid WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(&tenant).bind(group.to_string()).bind(id.to_string()).execute(&mut *c).await?;
            sqlx::query("UPDATE mdm_group.member_runs SET phase='published',receipt=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid AND phase='ready'")
                .bind(tenant).bind(id.to_string()).bind(document).execute(c).await?;Ok(())
        })).await?;
        Ok(Ok(receipt))
    }

    /// Read one page of a sealed build's members. The immutable build identity is
    /// the cursor's version; callers must authorize the owning group on every read.
    pub async fn build_members_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
        after: Option<String>,
        limit: usize,
    ) -> InTransaction<Vec<String>> {
        input!(self.check_transaction(tx)?);
        if !(1..=1000).contains(&limit) {
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
}

fn page_fits(current: usize, added: usize) -> bool {
    current.saturating_add(added) <= MAX_MEMBERS
}

fn member_count_after_patch(
    current: usize,
    added: usize,
    removed: usize,
) -> std::result::Result<usize, Rejection> {
    current
        .checked_add(added)
        .and_then(|n| n.checked_sub(removed))
        .filter(|n| *n <= MAX_MEMBERS)
        .ok_or(Rejection::CapacityExceeded)
}

struct DifferencePage {
    devices: Vec<String>,
    ids: Vec<String>,
    changes: Vec<bool>,
    more: bool,
}
fn difference_page(old: Vec<String>, new: Vec<String>) -> DifferencePage {
    let full = old.len() == 1000 || new.len() == 1000;
    let mut keys = std::collections::BTreeMap::<String, (bool, bool)>::new();
    for key in old {
        keys.entry(key).or_default().0 = true;
    }
    for key in new {
        keys.entry(key).or_default().1 = true;
    }
    let more = full || keys.len() > 1000;
    let mut devices = Vec::new();
    let mut ids = Vec::new();
    let mut changes = Vec::new();
    for (key, (old, new)) in keys.into_iter().take(1000) {
        devices.push(key.clone());
        if old != new {
            ids.push(key);
            changes.push(new);
        }
    }
    DifferencePage {
        devices,
        ids,
        changes,
        more,
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    #[test]
    fn member_limits_reject_overflow_without_allocating_members() {
        assert!(page_fits(MAX_MEMBERS - 1, 1));
        assert!(!page_fits(MAX_MEMBERS, 1));
        assert!(!page_fits(usize::MAX, 1));
        assert_eq!(member_count_after_patch(MAX_MEMBERS, 1, 1), Ok(MAX_MEMBERS));
        assert_eq!(
            member_count_after_patch(MAX_MEMBERS, 1, 0),
            Err(Rejection::CapacityExceeded)
        );
        assert_eq!(
            member_count_after_patch(0, 0, 1),
            Err(Rejection::CapacityExceeded)
        );
        assert_eq!(
            member_count_after_patch(usize::MAX, 1, 1),
            Err(Rejection::CapacityExceeded)
        );
    }
}
