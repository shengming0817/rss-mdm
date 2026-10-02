//! Eligibility participates in the wake claimant's audit transaction; it grants no dispatch rights.
use super::*;
use sqlx::Row;
impl ExecutionService {
    pub async fn windows_wake_pending_in(
        &self,
        c: &mut sqlx::PgConnection,
        device: &str,
        registration: Uuid,
        generation: i64,
    ) -> std::result::Result<bool, Error> {
        let tenant = self.tenant.to_string();
        crate::authorization::lock_on(c, &tenant, &self.instance).await?;
        crate::device::store::lock_channel(c, &tenant, device, rss_mdm_inventory::Channel::Mdm)
            .await?;
        let row=sqlx::query("SELECT q.windows_profile FROM mdm_access.registrations r JOIN mdm_access.requests q ON(q.tenant_id,q.id)=(r.tenant_id,r.request_id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.device=$3 AND r.generation=$4 AND r.state='active' AND EXISTS(SELECT 1 FROM mdm_access.credentials c WHERE c.tenant_id=r.tenant_id AND c.registration=r.id AND c.state='active') FOR SHARE OF r")
            .bind(&tenant).bind(registration).bind(device).bind(generation).fetch_optional(&mut *c).await.map_err(database::db)?;
        let Some(row) = row else { return Ok(false) };
        if !crate::device::store::active_source_in(
            c,
            &tenant,
            registration,
            rss_mdm_inventory::ReportSource::MdmWindows,
        )
        .await?
        {
            return Ok(false);
        }
        let user_context = (row
            .try_get::<Option<String>, _>("windows_profile")
            .map_err(database::db)?
            .as_deref()
            == Some("Full"))
        .then_some(registration);
        let mut after = Uuid::nil();
        loop {
            let rows=sqlx::query("SELECT id,device,registration,registration_generation,input_context,request,approval::text FROM mdm_commands.windows_pending_operations($1,$2,$3)")
                .bind(registration).bind(generation).bind(after).fetch_all(&mut *c).await.map_err(database::db)?;
            let count = rows.len();
            for row in rows {
                after = row.try_get("id").map_err(database::db)?;
                let input =
                    input_storage::open_row(&self.protection, self.tenant, after, &row, "request")?;
                if !input.target.matches_windows_context(user_context) {
                    continue;
                }
                let authority: authority::ExecutionAuthority = serde_json::from_str(
                    &row.try_get::<String, _>("approval").map_err(database::db)?,
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
        let mut after = Uuid::nil();
        let target = crate::Target {
            device: device.into(),
            registration,
            generation,
        };
        loop {
            let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND registration=$2 AND source='mdm.windows' AND sealed_at IS NULL AND id>$3 AND (deadline IS NULL OR deadline>clock_timestamp()) ORDER BY id LIMIT 64")
            .bind(&tenant).bind(registration).bind(after).fetch_all(&mut *c).await.map_err(database::db)?;
            for id in &ids {
                after = *id;
                if crate::actions::native_collection::eligible_target_on(
                    self.source.as_ref(),
                    c,
                    self.tenant,
                    &target,
                    *id,
                )
                .await?
                {
                    return Ok(true);
                }
            }
            if ids.len() < 64 {
                return Ok(false);
            }
        }
    }
}
