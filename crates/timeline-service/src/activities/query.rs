use super::{model::*, projection};
use crate::{Error, FactView, Timeline};
use rss_mdm_agent_wire::activities::*;
use rss_mdm_audit_integration::{
    activity::Activity,
    budget::{AuditBudget, RuntimeTimer},
};
use rss_request_context::{Clock, Deadline};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use std::time::Duration;
use uuid::Uuid;

impl Timeline {
    pub async fn activities(
        &self,
        reader: &Reader<'_>,
        query: &Query,
        changes: bool,
    ) -> Result<ManagementActivityPage, Error> {
        self.activity_page(reader, query, changes, None).await
    }
    async fn activity_page(
        &self,
        reader: &Reader<'_>,
        query: &Query,
        changes: bool,
        id: Option<&str>,
    ) -> Result<ManagementActivityPage, Error> {
        query.validate()?;
        if query.view.as_deref() == Some("personal")
            && !matches!(reader, Reader::Agent { user: Some(_), .. })
        {
            return Err(Error::Forbidden);
        }
        let budget = AuditBudget::new(Duration::from_secs(5));
        let initial = self
            .audit
            .read(
                self.tenant,
                &budget.control(),
                (self, reader, query, changes),
                |ctx, tx| {
                    Box::pin(async move {
                        tx.with_connection_context(ctx, |(s, r, q, changes), c| {
                            Box::pin(async move {
                                let scope = s.activity_scope(c, r).await?;
                                let binding = binding(&scope, q)?;
                                decode(s, q, &binding, *changes)?;
                                let batch = s.prepare_on(c).await?;
                                Ok::<_, Error>((scope.binding, batch))
                            })
                        })
                        .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                crate::service::transaction_error,
                crate::service::transaction_error,
                crate::service::transaction_error,
                crate::service::transaction_error,
                crate::service::transaction_error,
            )?;
        let now = RuntimeTimer.now();
        self.write_batch(
            &initial.1,
            Deadline::at(now + Duration::from_secs(2)),
            Deadline::at(now + Duration::from_millis(1500)),
        )
        .await?;
        self.audit
            .read(
                self.tenant,
                &budget.control(),
                (self, reader, query, changes, id, initial.0),
                |ctx, tx| {
                    Box::pin(async move {
                        tx.with_connection_context(ctx, |(s, r, q, changes, id, expected), c| {
                            Box::pin(async move {
                                let scope = s.activity_scope(c, r).await?;
                                if &scope.binding != expected {
                                    return Err(Error::Conflict);
                                }
                                let page = s.read_activities(c, &scope, q, *changes, *id).await?;
                                if s.activity_scope(c, r).await?.binding != scope.binding {
                                    return Err(Error::Conflict);
                                }
                                Ok(page)
                            })
                        })
                        .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                crate::service::transaction_error,
                crate::service::transaction_error,
                crate::service::transaction_error,
                crate::service::transaction_error,
                crate::service::transaction_error,
            )
    }
    pub async fn activity_detail(
        &self,
        reader: &Reader<'_>,
        id: &str,
        personal: bool,
    ) -> Result<ManagementActivityDetail, Error> {
        if !crate::model::identifier(id) {
            return Err(Error::Malformed);
        }
        if personal && !matches!(reader, Reader::Agent { user: Some(_), .. }) {
            return Err(Error::Forbidden);
        }
        let expected = self.activity_binding(reader).await?;
        let page = self
            .activity_page(reader, &Query::default(), false, Some(id))
            .await?;
        let activity = page.items.into_iter().next().ok_or(Error::NotFound)?;
        let mut query = Query {
            view: personal.then(|| "personal".into()),
            limit: Some(50),
            ..Query::default()
        };
        if activity.links.batch.is_some() {
            query.batch = activity.links.batch;
        } else if activity.links.task.is_some() {
            query.task = activity.links.task;
        } else if activity.links.operation.is_some() {
            query.operation = activity.links.operation;
        } else if activity.links.request.is_some() {
            query.request = activity.links.request;
        } else {
            query.policy = activity.links.policy;
        }
        // Related rows remain independently authorized; never traverse an arbitrary parent target set.
        let related = if query.request.is_some()
            || query.batch.is_some()
            || query.policy.is_some()
            || query.task.is_some()
            || query.operation.is_some()
        {
            Some(self.activities(reader, &query, false).await?)
        } else {
            None
        };
        let (mut parents, truncated) = self.policy_parents(reader, &activity, &expected).await?;
        let mut missing = page
            .coverage
            .into_iter()
            .flat_map(|c| c.reasons)
            .collect::<Vec<_>>();
        if truncated {
            missing.push("policy_history_truncated".into());
        }
        if activity.links.version.is_some() && parents.is_empty() {
            missing.push("policy_fact_unavailable".into());
        }
        parents.extend(related.as_ref().map_or_else(Vec::new, |p| {
            p.items.iter().filter(|a| a.id != id).cloned().collect()
        }));
        if self.activity_binding(reader).await? != expected {
            return Err(Error::Conflict);
        }
        Ok(ManagementActivityDetail {
            activity,
            personal,
            related: parents,
            related_cursor: related.and_then(|p| p.next_cursor),
            missing,
            as_of: page.as_of,
        })
    }
    async fn activity_binding(&self, reader: &Reader<'_>) -> Result<String, Error> {
        let budget = AuditBudget::new(Duration::from_secs(5));
        self.audit
            .read(self.tenant, &budget.control(), (self, reader), |ctx, tx| {
                Box::pin(async move {
                    tx.with_connection_context(ctx, |(s, r), c| {
                        Box::pin(
                            async move { Ok::<_, Error>(s.activity_scope(c, r).await?.binding) },
                        )
                    })
                    .await
                })
            })
            .await
            .fold(
                Ok,
                crate::service::transaction_error,
                crate::service::transaction_error,
                crate::service::transaction_error,
                crate::service::transaction_error,
                crate::service::transaction_error,
            )
    }
    async fn policy_parents(
        &self,
        reader: &Reader<'_>,
        activity: &ManagementActivity,
        expected: &str,
    ) -> Result<(Vec<ManagementActivity>, bool), Error> {
        let (Some(policy), Some(version)) = (activity.links.policy, activity.links.version) else {
            return Ok((Vec::new(), false));
        };
        let budget = AuditBudget::new(Duration::from_secs(5));
        self.audit.read(self.tenant,&budget.control(),(self,reader,policy,version,expected),|ctx,tx|Box::pin(async move {
            tx.with_connection_context(ctx,|(s,r,policy,version,expected),c|Box::pin(async move {
                if s.activity_scope(c,r).await?.binding!=*expected {return Err(Error::Conflict);}
                // An authorized device fact grants only the exact immutable Policy parent,
                // never current membership or arbitrary other targets of the same Policy.
                let mut rows=sqlx::query("SELECT document,digest,activity,activity_digest FROM mdm_timeline.facts WHERE tenant_id=$1::uuid AND activity->>'kind'='policy' AND activity->'links'->>'policy'=$2 AND activity->'links'->>'version'=$3 AND activity->'target'='null'::jsonb ORDER BY recorded_at DESC,position DESC LIMIT 51").bind(s.tenant.to_string()).bind(policy.to_string()).bind(version.to_string()).fetch_all(c).await?;
                let truncated=rows.len()>50;rows.truncate(50);
                Ok((rows.iter().map(decode_row).collect::<Result<Vec<_>,_>>()?,truncated))
            })).await
        })).await.fold(Ok,crate::service::transaction_error,crate::service::transaction_error,crate::service::transaction_error,crate::service::transaction_error,crate::service::transaction_error)
    }

    async fn read_activities(
        &self,
        c: &mut PgConnection,
        scope: &Scope,
        q: &Query,
        changes: bool,
        id: Option<&str>,
    ) -> Result<ManagementActivityPage, Error> {
        let binding = binding(scope, q)?;
        let prior = decode(self, q, &binding, changes)?;
        let (current, caught_up, now) = self.activity_heads(c, scope).await?;
        let token = match prior {
            Some(mut p) => {
                for old in &p.through {
                    let live = current
                        .iter()
                        .find(|w| w.device == old.device)
                        .ok_or(Error::Conflict)?;
                    if (!old.generation.is_nil() && old.generation != live.generation)
                        || old.revision > live.revision
                    {
                        return Err(Error::Conflict);
                    }
                }
                if changes && p.after.is_none() {
                    p.since = p.through;
                    p.through = current.clone();
                    p.as_of = now;
                    p.caught_up = caught_up;
                }
                p
            }
            None => Cursor {
                binding: binding.clone(),
                changes,
                through: current.clone(),
                since: Vec::new(),
                after: None,
                as_of: now,
                caught_up,
            },
        };
        let mut sql = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "SELECT f.document,f.digest,f.activity,f.activity_digest,e.device,e.revision,f.recorded_at,f.position FROM mdm_timeline.activity_entries e JOIN mdm_timeline.facts f ON(f.tenant_id,f.position)=(e.tenant_id,e.position) WHERE e.tenant_id=",
        );
        scope_filter(&mut sql, self.tenant, scope, &token, changes)?;
        if let Some(id) = id {
            sql.push(" AND f.source||':'||f.event_id=")
                .push_bind(id.to_owned());
        }
        filters(&mut sql, q);
        if let Some((at, device, rev)) = &token.after {
            if changes {
                sql.push(" AND (e.device,e.revision)>(")
                    .push_bind(device.clone())
                    .push(",")
                    .push_bind(*rev)
                    .push(")");
            } else {
                sql.push(" AND (f.recorded_at,e.device,e.revision)<(")
                    .push_bind(*at)
                    .push(",")
                    .push_bind(device.clone())
                    .push(",")
                    .push_bind(*rev)
                    .push(")");
            }
        }
        sql.push(if changes {
            " ORDER BY e.device,e.revision"
        } else {
            " ORDER BY f.recorded_at DESC,e.device DESC,e.revision DESC"
        })
        .push(" LIMIT ")
        .push_bind((q.limit.unwrap_or(50) + 1) as i64);
        let mut rows = sql.build().fetch_all(&mut *c).await?;
        let more = rows.len() > q.limit.unwrap_or(50);
        rows.truncate(q.limit.unwrap_or(50));
        let mut items = Vec::new();
        let mut last = None;
        for row in rows {
            items.push(decode_row(&row)?);
            last = Some((
                row.try_get("recorded_at")?,
                row.try_get("device")?,
                row.try_get("revision")?,
            ));
        }
        let next_cursor = if more {
            let mut next = token.clone();
            next.after = last;
            Some(encode(self, &next)?)
        } else {
            None
        };
        let sync = Cursor {
            binding,
            changes: true,
            through: token.through.clone(),
            since: Vec::new(),
            after: None,
            as_of: token.as_of,
            caught_up: token.caught_up,
        };
        let mut retained = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "SELECT min(f.recorded_at) FROM mdm_timeline.activity_entries e JOIN mdm_timeline.facts f ON(f.tenant_id,f.position)=(e.tenant_id,e.position) WHERE e.tenant_id=",
        );
        scope_filter(&mut retained, self.tenant, scope, &token, false)?;
        let retained_from: Option<i64> = retained.build_query_scalar().fetch_one(&mut *c).await?;
        let caught_up = token.caught_up;
        // A partial catch-up cannot establish completeness, even if the page is empty.
        let mut reasons = scope.reasons.clone();
        if !caught_up {
            reasons.push("source_catchup_pending".into());
        }
        Ok(ManagementActivityPage {
            items,
            next_cursor,
            sync_cursor: encode(self, &sync)?,
            as_of: token.as_of,
            retained_from,
            coverage: vec![ActivityCoverage {
                source: "mdm.business".into(),
                complete: caught_up && reasons.is_empty(),
                reasons,
            }],
        })
    }
    async fn activity_heads(
        &self,
        c: &mut PgConnection,
        scope: &Scope,
    ) -> Result<(Vec<Watermark>, bool, i64), Error> {
        let devices = scope
            .members
            .iter()
            .map(|m| m.device.clone())
            .collect::<Vec<_>>();
        // Heads and source coverage must share one statement snapshot. A later commit
        // remains discoverable by the anti-join and receives a later publication revision.
        let row=sqlx::query("SELECT COALESCE((SELECT jsonb_agg(jsonb_build_object('device',device,'generation',generation,'revision',revision)) FROM mdm_timeline.activity_streams WHERE tenant_id=$1::uuid AND device=ANY($2)),'[]'::jsonb) AS heads, NOT EXISTS(SELECT 1 FROM rss_audit.records r WHERE r.tenant_id=$1::uuid AND r.source_id='mdm.business' AND NOT EXISTS(SELECT 1 FROM mdm_timeline.facts f WHERE f.tenant_id=r.tenant_id AND f.source=r.source_id AND f.event_id=r.event_id)) AS caught_up,extract(epoch FROM statement_timestamp())::bigint AS observed").bind(self.tenant.to_string()).bind(devices).fetch_one(c).await?;
        let rows: Vec<Watermark> =
            serde_json::from_value(row.try_get("heads")?).map_err(|_| Error::Integrity)?;
        let heads = scope
            .members
            .iter()
            .map(|m| {
                let found = rows.iter().find(|v| v.device == m.device);
                Watermark {
                    device: m.device.clone(),
                    generation: found.map_or(Uuid::nil(), |v| v.generation),
                    revision: found.map_or(0, |v| v.revision),
                }
            })
            .collect();
        Ok((heads, row.try_get("caught_up")?, row.try_get("observed")?))
    }
}
fn filters(sql: &mut sqlx::QueryBuilder<sqlx::Postgres>, q: &Query) {
    if let Some(from) = q.from {
        sql.push(" AND f.recorded_at>=").push_bind(from);
    }
    if let Some(until) = q.until {
        sql.push(" AND f.recorded_at<").push_bind(until);
    }
    for (column, value) in [
        ("f.source", q.source.clone()),
        ("f.activity->>'kind'", q.kind.clone()),
    ] {
        if let Some(value) = value {
            sql.push(" AND ").push(column).push("=").push_bind(value);
        }
    }
    if let Some(status) = &q.status {
        sql.push(" AND ").push_bind(status.clone()).push(" IN(f.activity->>'delivery',f.activity->>'execution',f.activity->>'decision',f.activity->>'reporting',f.activity->>'effect')");
    }
    for (key, value) in [
        ("policy", q.policy),
        ("request", q.request),
        ("batch", q.batch),
        ("task", q.task),
        ("operation", q.operation),
    ] {
        if let Some(value) = value {
            sql.push(" AND f.activity->'links'->>'")
                .push(key)
                .push("'=")
                .push_bind(value.to_string());
        }
    }
}
fn binding(scope: &Scope, q: &Query) -> Result<String, Error> {
    rss_mdm_query::cursor::fingerprint(&json!([scope.binding, q.binding()]))
        .map_err(|_| Error::Integrity)
}
fn decode(s: &Timeline, q: &Query, binding: &str, changes: bool) -> Result<Option<Cursor>, Error> {
    q.cursor
        .as_ref()
        .map(|raw| {
            let token = rss_contract::PageCursor::parse(raw).map_err(|_| Error::Malformed)?;
            let value: Cursor = s
                .key
                .decode(&token, "management-activities")
                .map_err(|_| Error::Conflict)?;
            if value.binding != binding || value.changes != changes {
                return Err(Error::Conflict);
            }
            Ok(value)
        })
        .transpose()
}
fn encode(s: &Timeline, cursor: &Cursor) -> Result<String, Error> {
    s.key
        .encode("management-activities", cursor)
        .map(|v| v.as_str().to_owned())
        .map_err(|_| Error::Integrity)
}

fn scope_filter(
    sql: &mut sqlx::QueryBuilder<sqlx::Postgres>,
    tenant: rss_request_context::TenantId,
    scope: &Scope,
    token: &Cursor,
    changes: bool,
) -> Result<(), Error> {
    sql.push_bind(tenant.to_string()).push("::uuid AND (");
    for (i, m) in scope.members.iter().enumerate() {
        if i > 0 {
            sql.push(" OR ");
        }
        let head = token
            .through
            .iter()
            .find(|h| h.device == m.device)
            .ok_or(Error::Conflict)?;
        let since = token
            .since
            .iter()
            .find(|h| h.device == m.device)
            .map_or(0, |h| h.revision);
        sql.push("(e.device=")
            .push_bind(m.device.clone())
            .push(" AND e.revision<=")
            .push_bind(head.revision);
        if changes {
            sql.push(" AND e.revision>").push_bind(since);
        }
        // A root may own a current declared MDM user channel, but never a superseded child.
        sql.push(" AND (f.activity->'target'->>'registration'=").push_bind(m.registration.to_string()).push(" AND (f.activity->'target'->>'generation')::bigint=").push_bind(m.generation)
                .push(" OR EXISTS(SELECT 1 FROM mdm_access.registrations child WHERE child.tenant_id=e.tenant_id AND child.id::text=f.activity->'target'->>'registration' AND child.generation=(f.activity->'target'->>'generation')::bigint AND child.device=e.device AND child.parent_id=").push_bind(m.registration).push(" AND child.parent_generation=").push_bind(m.generation).push(" AND child.state='active')))");
    }
    if scope.members.is_empty() {
        sql.push("false");
    }
    sql.push(")");
    if let Some(user) = &scope.personal {
        sql.push(" AND f.activity->'user'->>'instance'=")
            .push_bind(user.instance.to_string())
            .push(" AND f.activity->'user'->>'principal'=")
            .push_bind(user.principal.to_string())
            .push(" AND f.activity->'user'->>'osIdentity'=")
            .push_bind(user.os_identity.clone())
            .push(" AND (f.activity->'user'->>'generatedUid') IS NOT DISTINCT FROM ")
            .push_bind(user.generated_uid.clone());
    }
    Ok(())
}

fn decode_row(row: &sqlx::postgres::PgRow) -> Result<ManagementActivity, Error> {
    let document: serde_json::Value = row.try_get("document")?;
    if Sha256::digest(serde_json::to_vec(&document).map_err(|_| Error::Integrity)?).as_slice()
        != row.try_get::<Vec<u8>, _>("digest")?
    {
        return Err(Error::Integrity);
    }
    let view: FactView = serde_json::from_value(document).map_err(|_| Error::Integrity)?;
    let raw: serde_json::Value = row.try_get("activity")?;
    if Sha256::digest(serde_json::to_vec(&raw).map_err(|_| Error::Integrity)?).as_slice()
        != row.try_get::<Vec<u8>, _>("activity_digest")?
    {
        return Err(Error::Integrity);
    }
    let activity: Activity = serde_json::from_value(raw).map_err(|_| Error::Integrity)?;
    projection::summary(&view, &activity)
}
