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
    if group.revision != request.expected || group.rule_version != request.rule_version {
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
    /// Number of input objects already persisted.
    pub objects: usize,
    /// Number of matches already persisted.
    pub members: usize,
    /// Whether input enumeration has been sealed.
    pub input_sealed: bool,
    /// Whether the complete difference has been persisted.
    pub ready: bool,
    /// Final result, once explicitly published.
    pub receipt: Option<Receipt>,
}

impl GroupStore {
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
        let tenant = self.tenant.to_string();
        let r = request.clone();
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("INSERT INTO mdm_group.member_runs(tenant_id,id,group_id,base_revision,rule_version,input_version,fingerprint,input,phase,as_of) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,'reading',$9)")
                .bind(tenant).bind(r.id.to_string()).bind(r.group.to_string()).bind(r.expected.get()).bind(r.rule_version)
                .bind(r.input_version).bind(fingerprint).bind(document).bind(r.as_of.unix_seconds()).execute(c).await?;
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
            sqlx::query("SELECT input,fingerprint,phase,cursor,object_count,member_count,receipt FROM mdm_group.member_runs WHERE tenant_id=$1::uuid AND id=$2::uuid")
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
            objects: data(usize::try_from(row.try_get::<i64, _>("object_count")?))?,
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
        input!(crate::store::dynamic(&g, build.request.expected));
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
        let evaluated = input!(
            rule.evaluate_page(page, build.request.as_of)
                .map_err(crate::store::core_rejection)
        );
        // Encoding is bounded by a page. The legacy aggregate encoder is removed
        // when the adapter's callers switch to the page storage format.
        let source = rss_mdm_group::Snapshot {
            tenant: page.tenant,
            id: page.id.into(),
            version: page.version.into(),
            dictionary_version: page.dictionary_version.into(),
            complete: false,
            coverage: page.coverage.clone(),
            objects: page.objects.to_vec(),
        };
        let fingerprint = db::fingerprint(&[
            &data(crate::codec::encode_snapshot(&source))?,
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
        if build.input_sealed
            || build.cursor.as_deref() != page.after.map(|k| k.id())
            || build.objects.saturating_add(page.objects.len()) > MAX_MEMBERS
        {
            return Ok(Err(Rejection::InvalidInput));
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
            let explanations:Vec<_>=object.explanations.iter().map(|e|serde_json::json!({"path":e.path,"outcome":match e.outcome {
                rss_mdm_group::Outcome::Match=>"match",rss_mdm_group::Outcome::NoMatch=>"no_match",
                rss_mdm_group::Outcome::Unknown(reason)=>match reason {rss_mdm_group::UnknownReason::Null=>"null",rss_mdm_group::UnknownReason::Missing=>"missing",rss_mdm_group::UnknownReason::Deleted=>"deleted",rss_mdm_group::UnknownReason::Unsupported=>"unsupported",rss_mdm_group::UnknownReason::Conflict=>"conflict"}
            }})).collect();
            evidence.push(data(serde_json::to_vec(&serde_json::json!({"decision":match object.decision {Decision::Match=>"match",Decision::NoMatch=>"no_match",Decision::Unknown=>"unknown"},"explanations":explanations})))?);
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
        let count = ids.len() as i64;
        let members = matches.iter().filter(|v| **v).count() as i64;
        let tenant = self.tenant.to_string();
        let first = ids.first().ok_or_else(stored_shape)?.clone();
        let last = ids.last().ok_or_else(stored_shape)?.clone();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_group.member_rows SELECT $1::uuid,$2::uuid,* FROM unnest($3::text[],$4::boolean[],$5::bytea[])")
                .bind(&tenant).bind(id.to_string()).bind(ids).bind(matches).bind(evidence).execute(&mut *c).await?;
            sqlx::query("INSERT INTO mdm_group.member_pages VALUES($1::uuid,$2::uuid,$3,$4,$5)")
                .bind(&tenant).bind(id.to_string()).bind(first).bind(&last).bind(fingerprint).execute(&mut *c).await?;
            sqlx::query("UPDATE mdm_group.member_runs SET cursor=$3,object_count=object_count+$4,member_count=member_count+$5 WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(tenant).bind(id.to_string()).bind(last).bind(count).bind(members).execute(c).await?;
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
        let tenant = self.tenant.to_string();
        let after = build.cursor.clone();
        let remove = patch.remove.clone();
        let mut ids:std::collections::BTreeSet<String>=tx.with_connection(move |c|Box::pin(async move {
            let rows:Vec<String>=sqlx::query_scalar("SELECT m.object_id FROM mdm_group.member_rows m JOIN mdm_group.groups g ON (g.tenant_id,g.member_set)=(m.tenant_id,m.run_id) WHERE g.tenant_id=$1::uuid AND g.id=$2::uuid AND m.matched AND NOT(m.object_id=ANY($3)) AND ($4::text IS NULL OR m.object_id>$4 COLLATE \"C\") ORDER BY m.object_id LIMIT 1001")
                .bind(tenant).bind(group.id.to_string()).bind(remove).bind(after).fetch_all(c).await?;
            Ok(rows.into_iter().collect())
        })).await?;
        ids.extend(
            patch
                .add
                .into_iter()
                .filter(|id| build.cursor.as_ref().is_none_or(|after| id > after)),
        );
        let more = ids.len() > 1000;
        let ids: Vec<_> = ids.into_iter().take(1000).collect();
        if build.objects.saturating_add(ids.len()) > MAX_MEMBERS {
            return Ok(Err(Rejection::InvalidInput));
        }
        let next = if ids.is_empty() {
            build
        } else {
            let fingerprint = digest(&data(serde_json::to_vec(&ids))?);
            let evidence = vec![b"{\"origin\":\"manual\"}".to_vec(); ids.len()];
            input!(
                self.store_page_in(
                    tx,
                    id,
                    ids.clone(),
                    vec![true; ids.len()],
                    evidence,
                    fingerprint
                )
                .await?
            )
        };
        if more {
            Ok(Ok(next))
        } else {
            self.seal_build_in(tx, id, next.objects).await
        }
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
        if objects != build.objects {
            return Ok(Err(Rejection::IncompleteSnapshot));
        }
        if !build.input_sealed {
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
    ) -> InTransaction<MemberBuild> {
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
            return Ok(Ok(build));
        }
        if !build.input_sealed {
            return Ok(Err(Rejection::IncompleteSnapshot));
        }
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c|Box::pin(async move {
            let row=sqlx::query("SELECT r.diff_cursor,g.member_set::text FROM mdm_group.member_runs r JOIN mdm_group.groups g ON (g.tenant_id,g.id)=(r.tenant_id,r.group_id) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid")
                .bind(&tenant).bind(id.to_string()).fetch_one(&mut *c).await?;
            let cursor:Option<String>=row.try_get("diff_cursor")?;
            let previous:Option<String>=row.try_get("member_set")?;
            let mut keys=std::collections::BTreeMap::<String,(bool,bool)>::new();
            for (version,old) in [(previous,true),(Some(id.to_string()),false)] {
                if let Some(version)=version {
                    let rows:Vec<String>=sqlx::query_scalar("SELECT object_id FROM mdm_group.member_rows WHERE tenant_id=$1::uuid AND run_id=$2::uuid AND matched AND ($3::text IS NULL OR object_id>$3 COLLATE \"C\") ORDER BY object_id LIMIT 1001")
                        .bind(&tenant).bind(version).bind(&cursor).fetch_all(&mut *c).await?;
                    for key in rows {let pair=keys.entry(key).or_default();if old {pair.0=true;}else{pair.1=true;}}
                }
            }
            let more=keys.len()>1000;
            let mut last=cursor;let mut ids=Vec::new();let mut changes=Vec::new();
            for (key,(old,new)) in keys.into_iter().take(1000) {
                last=Some(key.clone());
                if old!=new {ids.push(key);changes.push(new);}
            }
            let added=changes.iter().filter(|v|**v).count() as i64;
            let removed=changes.len() as i64-added;
            sqlx::query("INSERT INTO mdm_group.member_changes SELECT $1::uuid,$2::uuid,* FROM unnest($3::text[],$4::boolean[])")
                .bind(&tenant).bind(id.to_string()).bind(ids).bind(changes).execute(&mut *c).await?;
            sqlx::query("UPDATE mdm_group.member_runs SET diff_cursor=$3,added=added+$4,removed=removed+$5,phase=$6 WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(tenant).bind(id.to_string()).bind(last).bind(added).bind(removed).bind(if more {"diff"}else{"ready"}).execute(c).await?;
            Ok(())
        })).await?;
        self.build_in(tx, id).await
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
        group.revision = input!(group.revision.next());
        group.member_count = build.members;
        if added != 0 || removed != 0 {
            group.member_version = group.revision.get();
        }
        let receipt = Receipt {
            operation: id,
            group,
            added,
            removed,
        };
        if added != 0 || removed != 0 {
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
        let tenant = self.tenant.to_string();
        Ok(Ok(tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT object_id FROM mdm_group.member_rows WHERE tenant_id=$1::uuid AND run_id=$2::uuid AND matched AND ($3::text IS NULL OR object_id>$3 COLLATE \"C\") ORDER BY object_id LIMIT $4")
                .bind(tenant).bind(id.to_string()).bind(after).bind(limit as i64).fetch_all(c).await
        })).await?))
    }
}
