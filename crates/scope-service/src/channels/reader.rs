//! Concrete Scope read capability. Reads borrow the caller's snapshot and never settle it.
use super::*;
use rss_request_context::TenantId;
use serde_json::Value;
use sqlx::PgConnection;
use std::sync::Arc;
use uuid::Uuid;
pub struct ChannelTargets {
    profile: rss_mdm_install_support::StorageProfile,
    pub objects: Option<Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>>,
}
impl ChannelTargets {
    pub fn required_objects(
        &self,
    ) -> Result<&Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>, sqlx::Error> {
        self.objects
            .as_ref()
            .ok_or_else(|| sqlx::Error::Protocol("object participant is not configured".into()))
    }
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    pub fn new(
        profile: rss_mdm_install_support::StorageProfile,
        objects: Option<Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>>,
    ) -> Self {
        Self { profile, objects }
    }
}
impl ChannelTargets {
    pub fn query_coordinate_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
    ) -> Pending<'a, String> {
        Box::pin(query_coordinate_on(self.profile(), c, tenant, scope))
    }

    pub fn lifecycle_objects_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        after: Option<&'a str>,
        limit: usize,
    ) -> Pending<'a, Vec<DeviceAssignment>> {
        let profile = self.profile();

        Box::pin(super::targets::lifecycle_objects_on(
            profile,
            self.objects.as_deref(),
            c,
            tenant,
            scope,
            after,
            limit,
        ))
    }
    pub fn rollout_input_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scopes: &'a [Uuid],
        channel: Channel,
    ) -> Pending<'a, Option<Vec<ScopeResult>>> {
        let profile = self.profile();

        Box::pin(async move {
            let mut runs = Vec::new();
            for scope in scopes {
                let status = rss_mdm_scope_postgres::state_on(profile, c, tenant, *scope).await?;
                if status["state"] != "fresh" {
                    return Ok(None);
                }
                let (run, revision) = sqlx::query_as::<_, (Uuid, i64)>(
                    crate::storage_profile::sql(profile).channels_reader_rollout_input_on_1,
                )
                .bind(tenant.to_string())
                .bind(scope)
                .bind(channel.as_str())
                .fetch_one(&mut *c)
                .await?;
                runs.push(ScopeResult { run, revision });
            }
            Ok(Some(runs))
        })
    }
    pub fn rollout_devices_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        runs: &'a [Uuid],
        channel: Channel,
        after: Option<&'a str>,
    ) -> Pending<'a, RolloutPage> {
        let profile = self.profile();

        Box::pin(async move {
            let (root, stage) = match runs {
                [root, stage, ..] => (root, stage),
                _ => return Err(SourceError::Invariant),
            };
            let mut rows = sqlx::query_as::<_, (String, Value, bool)>(
                crate::storage_profile::sql(profile).channels_reader_rollout_devices_on_1,
            )
            .bind(tenant.to_string())
            .bind(root)
            .bind(stage)
            .bind(&runs[2..])
            .bind(after)
            .bind(channel.as_str())
            .fetch_all(c)
            .await?;
            let has_more = rows.len() > 16;
            rows.truncate(16);
            let after = rows.last().map(|r| r.0.clone());
            let scanned = rows.len() as u64;
            let targets = rows
                .into_iter()
                .filter(|r| r.2)
                .map(|r| serde_json::from_value(r.1).map_err(|_| SourceError::Invariant))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(RolloutPage {
                targets,
                after,
                has_more,
                scanned,
            })
        })
    }
    pub fn preview_scope_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        after: Option<&'a str>,
    ) -> Pending<'a, ScopePreview> {
        let profile = self.profile();

        Box::pin(super::targets::devices_on(
            profile, c, tenant, scope, channel, after,
        ))
    }

    pub fn assignment_objects_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        after: Option<&'a str>,
        limit: usize,
    ) -> Pending<'a, Vec<AssignmentObject>> {
        let profile = self.profile();

        Box::pin(super::targets::objects_on(
            profile,
            self.objects.as_deref(),
            c,
            tenant,
            scope,
            channel,
            after,
            limit,
        ))
    }
    pub fn evidence_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        device: &'a str,
    ) -> Pending<'a, Vec<DeviceObject>> {
        let profile = self.profile();

        Box::pin(super::targets::evidence_on(
            profile,
            self.objects.as_deref(),
            c,
            tenant,
            scope,
            channel,
            device,
        ))
    }
    pub fn evidence_valid_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        channel: Channel,
        device: &'a str,
        evidence: &'a [DeviceObject],
    ) -> Pending<'a, bool> {
        Box::pin(super::targets::evidence_valid_on(
            self.profile(),
            self.objects.as_deref(),
            c,
            tenant,
            channel,
            device,
            evidence,
        ))
    }

    pub fn admission_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        scope: Uuid,
        channel: Channel,
        device: &'a str,
    ) -> Pending<'a, ScopeAdmission> {
        let profile = self.profile();

        Box::pin(super::targets::admission_on(
            profile,
            self.objects.as_deref(),
            c,
            tenant,
            scope,
            channel,
            device,
        ))
    }
}

/// Scope and source coordinates share the caller's transaction; no result-set scan is needed.
pub async fn query_coordinate_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
) -> Result<String, SourceError> {
    let stamp: Value =
        sqlx::query_scalar(crate::storage_profile::sql(profile).channels_query_coordinate)
            .bind(tenant.to_string())
            .bind(scope)
            .fetch_optional(c)
            .await?
            .ok_or(SourceError::Missing)?;
    rss_mdm_query::cursor::fingerprint(&stamp).map_err(|_| SourceError::Invariant)
}
