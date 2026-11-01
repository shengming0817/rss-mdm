use crate::{
    Error, Failure,
    sources::{Pending, ResultDetail, ResultDevices, ResultPage, ScopeInput},
    transaction::{Fault, Result, checked_input, stored},
};
use rss_mdm_scope_postgres::{Publication, ScopeBinding};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;
pub struct ScopeProjection {
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    scope: ScopeBinding,
}
impl ScopeProjection {
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.scope.profile()
    }
    pub fn new(
        profile: rss_mdm_install_support::StorageProfile,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
    ) -> Self {
        Self {
            scope: ScopeBinding::new(profile, runtime.clone(), tenant),
            runtime,
            tenant,
        }
    }
    fn validate(&self, tx: &PgTransaction<'_>) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::Forbidden.into());
        }
        Ok(())
    }
    async fn admit(&self, tx: &mut PgTransaction<'_>) -> Result<()> {
        let profile = self.profile();

        self.validate(tx)?;
        tx.with_connection(move |c| {
            Box::pin(async move {
                rss_mdm_scope_postgres::verify_authority(profile, c).await?;
                let valid: bool =
                    sqlx::query_scalar(rss_mdm_scope_postgres::projection_admission_sql(profile))
                        .bind(true)
                        .fetch_one(c)
                        .await?;
                if !valid {
                    return Err(sqlx::Error::Protocol(
                        "Scope projection admission rejected".into(),
                    ));
                }
                Ok(())
            })
        })
        .await?;
        Ok(())
    }
    async fn advance(&self, tx: &mut PgTransaction<'_>, p: &Publication) -> Result<bool> {
        let profile = self.profile();

        self.admit(tx).await?;
        let head = self.scope.head_in(tx, p.scope, true).await?;
        if head.revision != p.definition_revision || head.resolution != p.previous_resolution {
            return Err(Error::Conflict.into());
        }
        let tenant = self.tenant.to_string();
        let id = p.run;
        let scope = p.scope;
        let previous = head.resolution;
        let epoch = i64::try_from(head.calculation_revision)
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Conflict)?;
        let row = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query(crate::storage_profile::sql(profile).projection_advance_1)
                        .bind(&tenant)
                        .bind(id)
                        .bind(scope)
                        .bind(previous)
                        .bind(epoch)
                        .execute(&mut *c)
                        .await?;
                    sqlx::query(crate::storage_profile::sql(profile).projection_advance_2)
                        .bind(tenant)
                        .bind(id)
                        .fetch_one(c)
                        .await
                })
            })
            .await?;
        if row.try_get::<Option<Uuid>, _>("previous_resolution")? != previous
            || row.try_get::<Uuid, _>("scope")? != scope
        {
            return Err(Error::Conflict.into());
        }
        match row.try_get::<&str, _>("phase")? {
            "sources" => {
                self.stage(tx, id, row.try_get("source_cursor")?).await?;
                Ok(false)
            }
            "project" => {
                let run = self.scope.run_in(tx, id).await?.ok_or(Error::NotFound)?;
                let input: ScopeInput = stored(serde_json::from_value(run.input))?;
                self.project(tx, id, &input, &row).await?;
                Ok(false)
            }
            "ready" => Ok(true),
            _ => Err(Error::Conflict.into()),
        }
    }
    async fn stage(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        after: Option<String>,
    ) -> Result<()> {
        let profile = self.profile();

        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| {
            Box::pin(async move {
                let rows = sqlx::query_as::<_, (String, serde_json::Value)>(
                    crate::storage_profile::sql(profile).projection_stage_1,
                )
                .bind(&tenant)
                .bind(id)
                .bind(after)
                .fetch_all(&mut *c)
                .await?;
                let more = rows.len() > 1000;
                let last = rows.iter().take(1000).next_back().map(|r| r.0.clone());
                let inputs: Vec<_> = rows.into_iter().take(1000).map(|r| r.1).collect();
                sqlx::query(crate::storage_profile::sql(profile).projection_stage_2)
                    .bind(&tenant)
                    .bind(id)
                    .bind(inputs)
                    .execute(&mut *c)
                    .await?;
                sqlx::query(crate::storage_profile::sql(profile).projection_stage_3)
                    .bind(tenant)
                    .bind(id)
                    .bind(last)
                    .bind(if more { "sources" } else { "project" })
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        Ok(())
    }
    async fn project(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        frozen: &ScopeInput,
        progress: &sqlx::postgres::PgRow,
    ) -> Result<()> {
        let profile = self.profile();

        let after: Option<String> = progress.try_get("projection_cursor")?;
        let previous: Option<Uuid> = progress.try_get("previous_resolution")?;
        let epoch: i64 = progress.try_get("next_entry")?;
        let hashes: serde_json::Value = progress.try_get("channel_hashes")?;
        let tenant = self.tenant;
        let page = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_as::<_, (String, String, String)>(
                        crate::storage_profile::sql(profile).projection_project_1,
                    )
                    .bind(tenant.to_string())
                    .bind(id)
                    .bind(after)
                    .fetch_all(c)
                    .await
                })
            })
            .await?;
        let mut hashes: std::collections::BTreeMap<String, String> =
            stored(serde_json::from_value(hashes))?;
        for (channel, device, _) in page.iter().take(16) {
            let channel = match channel.as_str() {
                "agent" => rss_mdm_inventory::Channel::Agent,
                "mdm" => rss_mdm_inventory::Channel::Mdm,
                _ => return Err(Error::Malformed.into()),
            };
            let device = device.clone();
            let frozen = frozen.clone();
            let row_hash = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        let result = crate::channels::targets::explanation_on(
                            profile, c, tenant, id, &frozen, channel, &device, None,
                        )
                        .await
                        .map_err(|_| sqlx::Error::Protocol("scope projection invalid".into()))?;
                        let identities: Vec<serde_json::Value> = sqlx::query_scalar(
                            crate::storage_profile::sql(profile).projection_project_2,
                        )
                        .bind(tenant.to_string())
                        .bind(id)
                        .bind(channel.as_str())
                        .bind(&device)
                        .fetch_all(&mut *c)
                        .await?;
                        let target = identities
                            .first()
                            .ok_or_else(|| sqlx::Error::Protocol("scope target missing".into()))?
                            .clone();
                        let excluded = result.as_ref().is_some_and(|r| {
                            r.reasons
                                .contains(&rss_mdm_scope::ExclusionReason::ExplicitExclusion)
                        });
                        let pending = !excluded
                            && (identities.len() != 1
                                || result.as_ref().is_some_and(|r| {
                                    r.reasons.iter().any(|r| {
                                        matches!(
                                            r,
                                            rss_mdm_scope::ExclusionReason::UnknownTarget
                                                | rss_mdm_scope::ExclusionReason::UnknownLimitation
                                                | rss_mdm_scope::ExclusionReason::UnknownExclusion
                                        )
                                    })
                                }));
                        let matched =
                            !pending && result.as_ref().is_some_and(|r| r.reasons.is_empty());
                        let entry = if matched || pending {
                            sqlx::query_scalar::<_, i64>(
                                crate::storage_profile::sql(profile).projection_project_3,
                            )
                            .bind(tenant.to_string())
                            .bind(previous)
                            .bind(channel.as_str())
                            .bind(&device)
                            .bind(&target)
                            .fetch_optional(&mut *c)
                            .await?
                            .unwrap_or(if matched { epoch } else { 0 })
                        } else {
                            0
                        };
                        sqlx::query(crate::storage_profile::sql(profile).projection_project_4)
                            .bind(tenant.to_string())
                            .bind(id)
                            .bind(channel.as_str())
                            .bind(&device)
                            .bind(matched)
                            .bind(pending)
                            .bind(&target)
                            .bind(entry)
                            .execute(c)
                            .await?;
                        Ok(serde_json::json!([device, matched, pending, target]))
                    })
                })
                .await?;
            use sha2::Digest;
            let key = channel.as_str();
            let old = hashes.get(key).ok_or(Error::Malformed)?;
            let bytes = checked_input(serde_json::to_vec(&row_hash))?;
            let mut digest = sha2::Sha256::new();
            digest.update(old.as_bytes());
            digest.update((bytes.len() as u64).to_be_bytes());
            digest.update(bytes);
            hashes.insert(key.into(), format!("{:x}", digest.finalize()));
        }
        let hashes = checked_input(serde_json::to_value(hashes))?;
        let next = page.iter().take(16).next_back().map(|r| r.2.clone());
        let more = page.len() > 16;
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(crate::storage_profile::sql(profile).projection_project_5)
                    .bind(tenant.to_string())
                    .bind(id)
                    .bind(next)
                    .bind(if more { "project" } else { "ready" })
                    .bind(hashes)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        Ok(())
    }
    async fn publish(&self, tx: &mut PgTransaction<'_>, p: &Publication) -> Result<bool> {
        let profile = self.profile();

        self.admit(tx).await?;
        let head = self.scope.head_in(tx, p.scope, true).await?;
        if head.revision != p.definition_revision || head.resolution != p.previous_resolution {
            return Err(Error::Conflict.into());
        }
        let tenant = self.tenant.to_string();
        let id = p.run;
        let previous = p.previous_resolution;
        let changed = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    let row = sqlx::query_as::<_, (bool, bool, i64, i64)>(
                        crate::storage_profile::sql(profile).projection_publish_1,
                    )
                    .bind(&tenant)
                    .bind(id)
                    .bind(previous)
                    .fetch_optional(&mut *c)
                    .await?;
                    let Some((agent, mdm, a, m)) = row else {
                        return Ok(None);
                    };
                    let a = a.checked_add(i64::from(agent)).ok_or_else(|| {
                        sqlx::Error::Protocol("projection revision overflow".into())
                    })?;
                    let m = m.checked_add(i64::from(mdm)).ok_or_else(|| {
                        sqlx::Error::Protocol("projection revision overflow".into())
                    })?;
                    sqlx::query(crate::storage_profile::sql(profile).projection_publish_2)
                        .bind(tenant)
                        .bind(id)
                        .bind(a)
                        .bind(m)
                        .execute(c)
                        .await?;
                    Ok(Some(agent || mdm))
                })
            })
            .await?;
        changed.ok_or(Error::Conflict.into())
    }
}
fn source_error(e: crate::channels::SourceError) -> Fault {
    use crate::channels::SourceError as E;
    match e {
        E::Storage(e) => Fault::Sql(e),
        E::Missing => Error::NotFound.into(),
        E::Conflict => Error::Conflict.into(),
        E::Capacity => Error::Unavailable(Failure::Capacity).into(),
        E::Invariant => Error::Unavailable(Failure::Storage).into(),
    }
}
impl ScopeProjection {
    pub(crate) fn advance_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a Publication,
    ) -> Pending<'a, bool, Fault> {
        Box::pin(self.advance(tx, p))
    }
    pub(crate) fn publish_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a Publication,
    ) -> Pending<'a, bool, Fault> {
        Box::pin(self.publish(tx, p))
    }
    pub(crate) fn result_devices_on<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        page: ResultPage<'a>,
    ) -> Pending<'a, ResultDevices, Fault> {
        let profile = self.profile();

        Box::pin(async move {
            let ResultPage {
                tenant,
                scope,
                run,
                channel,
                after,
                limit,
            } = page;
            if tenant != self.tenant {
                return Err(Error::Forbidden.into());
            }
            let page = crate::channels::targets::result_devices_on(
                profile, c, tenant, scope, run, channel, after, limit,
            )
            .await
            .map_err(source_error)?;
            let current = sqlx::query_scalar::<_, bool>(
                crate::storage_profile::sql(profile).projection_result_devices_on_1,
            )
            .bind(tenant.to_string())
            .bind(scope)
            .bind(run)
            .fetch_one(c)
            .await?;
            Ok(ResultDevices {
                result: page.result,
                devices: page.devices,
                current,
            })
        })
    }
    pub(crate) fn result_detail_on<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        member: crate::sources::ResultMember<'a>,
    ) -> Pending<'a, ResultDetail, Fault> {
        let profile = self.profile();

        Box::pin(async move {
            let crate::sources::ResultMember {
                tenant,
                scope,
                run,
                channel,
                device,
                objects,
            } = member;
            if tenant != self.tenant {
                return Err(Error::Forbidden.into());
            }
            let status = crate::channels::targets::result_admission_on(
                profile, c, tenant, scope, run, channel, device,
            )
            .await
            .map_err(source_error)?;
            let explanation = crate::channels::targets::result_explanation_on(
                profile, c, tenant, scope, run, channel, device,
            )
            .await
            .map_err(source_error)?;
            use crate::channels::ScopeAdmission as A;
            let available = matches!(status, A::Eligible { .. })
                && crate::channels::targets::result_available_on(
                    profile,
                    c,
                    tenant,
                    scope,
                    run,
                    channel,
                    device,
                    Some(objects),
                )
                .await
                .map_err(source_error)?;
            Ok(ResultDetail {
                available,
                matched: matches!(status, A::Eligible { .. }),
                pending: status == A::Pending,
                entry: if let A::Eligible { entry } = status {
                    entry
                } else {
                    0
                },
                explanation,
            })
        })
    }
}
