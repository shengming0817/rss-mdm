//! Eligibility participates in the wake claimant's audit transaction; it grants no dispatch rights.
use super::*;
use sqlx::Row;
impl Service {
    /// Read-only discovery from committed work. A candidate grants no wake or dispatch rights.
    /// The caller advances by the last returned device even when no channel is usable.
    pub async fn windows_wake_candidates_in(
        &self,
        c: &mut sqlx::PgConnection,
        after: &str,
    ) -> std::result::Result<Vec<String>, Error> {
        sqlx::query_scalar("SELECT device FROM mdm_devices.windows_wake_candidates($1) WHERE current_setting('rss.tenant_id')::uuid=$2::uuid ORDER BY device")
            .bind(after).bind(self.transactions.tenant.to_string()).fetch_all(c).await.map_err(database::db)
    }

    pub async fn windows_wake_pending_in(
        &self,
        c: &mut sqlx::PgConnection,
        device: &str,
    ) -> std::result::Result<bool, Error> {
        let tenant = self.transactions.tenant.to_string();
        crate::control::authorization::lock_shared_on(
            rss_mdm_install_support::StorageProfile::Mdm,
            c,
            &tenant,
            &self.transactions.instance,
        )
        .await?;
        crate::control::device::store::lock_channel(
            rss_mdm_install_support::StorageProfile::Mdm,
            c,
            &tenant,
            device,
            rss_mdm_inventory::Channel::Mdm,
        )
        .await?;
        let row=sqlx::query("SELECT q.windows_profile FROM mdm_access.devices AS r INNER JOIN mdm_access.requests AS q ON (q.tenant_id, q.id) = (r.tenant_id, r.request_id) WHERE r.tenant_id = CAST($1 AS uuid) AND r.id = $2 AND r.state = 'active' AND EXISTS (SELECT 1 FROM mdm_access.credentials AS c WHERE c.tenant_id = r.tenant_id AND c.device = r.id AND c.state = 'active' AND c.purpose = 'primary') FOR SHARE OF r")
            .bind(&tenant).bind(device).fetch_optional(&mut *c).await.map_err(database::db)?;
        let Some(row) = row else { return Ok(false) };
        if !crate::control::device::store::active_source_in(
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
            .map_err(database::db)?
            .as_deref()
            == Some("Full");
        let mut after = Uuid::nil();
        loop {
            let rows=sqlx::query("SELECT id,device,input_context,request,authority::text FROM mdm_devices.windows_pending_operations($1,$2)")
                .bind(device).bind(after).fetch_all(&mut *c).await.map_err(database::db)?;
            let count = rows.len();
            for row in rows {
                after = row.try_get("id").map_err(database::db)?;
                let input = input_storage::open_row(
                    &self.transactions.protection,
                    self.transactions.tenant,
                    after,
                    &row,
                    "request",
                )?;
                if !input.target.matches_windows_context(user_context) {
                    continue;
                }
                let authority: authority::Authority = serde_json::from_str(
                    &row.try_get::<String, _>("authority")
                        .map_err(database::db)?,
                )
                .map_err(|_| Error::Malformed)?;
                let now: i64 = sqlx::query_scalar(
                    "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
                )
                .fetch_one(&mut *c)
                .await
                .map_err(database::db)?;
                if authority
                    .valid(
                        c,
                        &self.transactions.protection,
                        &input.task.permissions()?,
                        now,
                    )
                    .await?
                    && authority.dispatch_ready(c).await?
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
