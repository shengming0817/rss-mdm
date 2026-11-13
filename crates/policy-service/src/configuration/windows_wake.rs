//! Eligibility participates in the wake claimant's audit transaction; it grants no dispatch rights.
use super::*;
use sqlx::Row;
impl Transactions {
    /// Read-only discovery from committed work. A candidate grants no wake or dispatch rights.
    /// The caller advances by the last returned device even when no channel is usable.
    pub async fn windows_wake_candidates_in(
        &self,
        c: &mut sqlx::PgConnection,
        after: Option<rss_mdm_agent_wire::DeviceId>,
    ) -> std::result::Result<Vec<rss_mdm_agent_wire::DeviceId>, Error> {
        sqlx::query_scalar("SELECT device FROM mdm_planning.configuration_windows_wake_candidates($1) WHERE current_setting('rss.tenant_id')::uuid=$2::uuid ORDER BY device")
            .bind(after.map(|id|id.into_uuid())).bind(self.tenant.to_string()).fetch_all(c).await.and_then(crate::configuration::device_ids).map_err(db)
    }

    pub async fn windows_wake_pending_in(
        &self,
        c: &mut sqlx::PgConnection,
        device: &rss_mdm_agent_wire::DeviceId,
    ) -> std::result::Result<bool, Error> {
        let tenant = self.tenant.to_string();
        rss_mdm_registration_service::device::store::lock_channel(
            rss_mdm_install_support::StorageProfile::Mdm,
            c,
            &tenant,
            device,
            rss_mdm_inventory::Channel::Mdm,
        )
        .await?;
        let row=sqlx::query("SELECT q.windows_profile FROM mdm_access.devices AS r INNER JOIN mdm_access.requests AS q ON (q.tenant_id, q.id) = (r.tenant_id, r.request_id) WHERE r.tenant_id = CAST($1 AS uuid) AND r.id = $2 AND r.state = 'active' AND EXISTS (SELECT 1 FROM mdm_access.credentials AS c WHERE c.tenant_id = r.tenant_id AND c.device = r.id AND c.state = 'active' AND c.purpose = 'primary') FOR SHARE OF r")
            .bind(&tenant).bind(device.into_uuid()).fetch_optional(&mut *c).await.map_err(db)?;
        let Some(row) = row else { return Ok(false) };
        if !rss_mdm_registration_service::device::store::active_source_in(
            rss_mdm_install_support::StorageProfile::Mdm,
            c,
            &tenant,
            device,
            rss_mdm_inventory::ReportSource::MdmWindows,
        )
        .await?
        {
            return Ok(false);
        }
        let user_context = row
            .try_get::<Option<String>, _>("windows_profile")
            .map_err(db)?
            .as_deref()
            == Some("Full");
        let mut after = Uuid::nil();
        loop {
            let rows=sqlx::query("SELECT id,device,input_context,request,authority::text FROM mdm_planning.configuration_windows_pending_operations($1,$2)")
                .bind(device.into_uuid()).bind(after).fetch_all(&mut *c).await.map_err(db)?;
            let count = rows.len();
            for row in rows {
                after = row.try_get("id").map_err(db)?;
                let input =
                    input_storage::open_row(&self.protection, self.tenant, after, &row, "request")?;
                if !input.target.matches_windows_context(user_context) {
                    continue;
                }
                let authority: authority::Authority =
                    serde_json::from_str(&row.try_get::<String, _>("authority").map_err(db)?)
                        .map_err(|_| Error::Malformed)?;
                let now: i64 = sqlx::query_scalar(
                    "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
                )
                .fetch_one(&mut *c)
                .await
                .map_err(db)?;
                if authority
                    .valid(
                        self.source.as_ref(),
                        c,
                        &self.protection,
                        &input.task.permissions()?,
                        now,
                    )
                    .await?
                    && authority.dispatch_ready(self.source.as_ref(), c).await?
                {
                    return Ok(true);
                }
            }
            if count < 64 {
                break;
            }
        }
        Ok(false)
    }
}
