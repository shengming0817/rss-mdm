//! Actual PG rollback and permission failures through the authenticated HTTP API.
use super::*;
use sha2::{Digest, Sha256};
impl Client {
    pub(super) async fn without_firewall_write(
        &mut self,
        pg: &mut sqlx::PgConnection,
        path: &str,
        request: &Value,
    ) -> anyhow::Result<()> {
        let rules: Vec<(String, Value)> = sqlx::query_as(
            "SELECT id::text,document FROM mdm_access.authorization_rules WHERE tenant_id=$1::uuid",
        )
        .bind(TENANT)
        .fetch_all(&mut *pg)
        .await?;
        for (id, document) in &rules {
            let mut reduced = document.clone();
            if let Some(grants) = reduced["grants"].as_array_mut() {
                grants.retain(|g| g["operation"] != "firewall_write");
            }
            sqlx::query("UPDATE mdm_access.authorization_rules SET document=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(TENANT).bind(id).bind(reduced).execute(&mut *pg).await?;
        }
        let denied = self
            .browser
            .call(&self.router, Method::POST, path, Some(request.clone()))
            .await?;
        for (id, document) in rules {
            sqlx::query("UPDATE mdm_access.authorization_rules SET document=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(TENANT).bind(id).bind(document).execute(&mut *pg).await?;
        }
        ensure!(
            denied.0 == StatusCode::FORBIDDEN,
            "cancel/replay bypassed FirewallWrite: {denied:?}"
        );
        Ok(())
    }
    pub(super) async fn cancel_rejections(
        &mut self,
        plan: Uuid,
        path: &str,
        request: &Value,
    ) -> anyhow::Result<()> {
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
        let before = effects(&mut pg).await?;
        for deadline in [0, i64::MAX] {
            let mut invalid = request.clone();
            invalid["deadline"] = deadline.into();
            let denied = self
                .browser
                .call(&self.router, Method::POST, path, Some(invalid))
                .await?;
            ensure!(
                denied.0 == StatusCode::BAD_REQUEST,
                "cancel-only invalid deadline accepted: {denied:?}"
            );
        }
        self.without_firewall_write(&mut pg, path, request).await?;
        ensure!(
            effects(&mut pg).await? == before,
            "rejected cancellation persisted effects"
        );
        let executions: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM mdm_commands.plan_executions WHERE plan=$1::uuid",
        )
        .bind(plan.to_string())
        .fetch_one(&mut pg)
        .await?;
        ensure!(executions == 0);
        Ok(())
    }
    pub(super) async fn preview_failures(
        &mut self,
        policy: &str,
        scope: Uuid,
        revision: u64,
        device: &str,
    ) -> anyhow::Result<()> {
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
        for (edition, generation, code) in [
            (0, 1, "platform_unsupported"),
            (48, 2, "capability_unknown"),
        ] {
            sqlx::query("UPDATE mdm_commands.capabilities c SET edition=$3,generation=$4 FROM mdm_access.registrations r WHERE c.tenant_id=r.tenant_id AND c.registration=r.id AND r.tenant_id=$1::uuid AND r.device=$2").bind(TENANT).bind(device).bind(edition).bind(generation).execute(&mut pg).await?;
            let rejected = self.submit_product(&format!("policies/{policy}/previews"), json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":{"scope":scope,"expectedRevision":revision}})).await?;
            let rejected = self
                .wait_preview(rejected["statusUrl"].as_str().unwrap())
                .await?;
            ensure!(
                rejected["failure"] == code
                    && rejected["failureDetail"]["device"] == device
                    && rejected["failureDetail"]["stage"] == "preview",
                "device preview reason lost: {rejected:?}"
            );
        }
        sqlx::query("UPDATE mdm_commands.capabilities c SET edition=48,generation=1 FROM mdm_access.registrations r WHERE c.tenant_id=r.tenant_id AND c.registration=r.id AND r.tenant_id=$1::uuid AND r.device=$2").bind(TENANT).bind(device).execute(&mut pg).await?;
        Ok(())
    }
    pub(super) async fn rollback_plan(
        &mut self,
        plan: Uuid,
        frozen: &Value,
        path: &str,
        request: &Value,
    ) -> anyhow::Result<()> {
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
        let second = frozen["devices"][1].as_str().unwrap();
        let before = effects(&mut pg).await?;
        sqlx::query("UPDATE mdm_commands.capabilities c SET os_version='10.0.22621.0' FROM mdm_access.registrations r WHERE c.tenant_id=r.tenant_id AND c.registration=r.id AND r.tenant_id=$1::uuid AND r.device=$2").bind(TENANT).bind(second).execute(&mut pg).await?;
        let stale = self
            .browser
            .call(&self.router, Method::POST, path, Some(request.clone()))
            .await?;
        ensure!(
            stale.0 == StatusCode::CONFLICT
                && stale.1["code"] == "stale_plan"
                && stale.1["device"] == second
                && stale.1["stage"] == "execute",
            "stale device reason lost: {stale:?}"
        );
        ensure!(effects(&mut pg).await? == before);
        sqlx::query("UPDATE mdm_commands.capabilities c SET os_version='10.0.19045.0' FROM mdm_access.registrations r WHERE c.tenant_id=r.tenant_id AND c.registration=r.id AND r.tenant_id=$1::uuid AND r.device=$2").bind(TENANT).bind(second).execute(&mut pg).await?;
        let digest = Sha256::digest(format!("{plan}:{second}"));
        let collision = Uuid::from_bytes(digest[..16].try_into().unwrap());
        // Collision is checked inside the second create_in, after the first target's
        // operation, command, outbox, owner and success audit have all been inserted.
        sqlx::query("INSERT INTO mdm_commands.requests(tenant_id,id,plan,fingerprint,response) VALUES($1::uuid,$2::uuid,$3::uuid,$4,'{}')").bind(TENANT).bind(collision.to_string()).bind(plan.to_string()).bind(vec![0u8;32]).execute(&mut pg).await?;
        let before = effects(&mut pg).await?;
        let rejected = self
            .browser
            .call(&self.router, Method::POST, path, Some(request.clone()))
            .await?;
        ensure!(
            rejected.0 == StatusCode::CONFLICT,
            "second-target failure: {rejected:?}"
        );
        ensure!(effects(&mut pg).await? == before, "partial batch persisted");
        sqlx::query("DELETE FROM mdm_commands.requests WHERE tenant_id=$1::uuid AND id=$2::uuid")
            .bind(TENANT)
            .bind(collision.to_string())
            .execute(&mut pg)
            .await?;
        Ok(())
    }
}
async fn effects(pg: &mut sqlx::PgConnection) -> anyhow::Result<Vec<String>> {
    let mut effects = Vec::new();
    for table in [
        "mdm_commands.operations",
        "rss_device_command.commands",
        "rss_transactional_messaging.outbox",
        "mdm_commands.firewall_owners",
        "mdm_commands.plan_executions",
        "mdm_commands.requests",
        "mdm_access.audit",
    ] {
        let filter = if table == "mdm_access.audit" {
            " AND result='success' AND action IN('command_accept','plan_execute')"
        } else {
            ""
        };
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text)::text,'[]') FROM ",
        );
        query
            .push(table)
            .push(" t WHERE tenant_id=")
            .push_bind(TENANT)
            .push("::uuid")
            .push(filter);
        effects.push(query.build_query_scalar().fetch_one(&mut *pg).await?);
    }
    Ok(effects)
}
