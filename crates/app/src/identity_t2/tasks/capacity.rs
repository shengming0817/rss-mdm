use super::*;

pub(super) async fn verify(
    author: &mut Browser,
    reviewer: &mut Browser,
    router: &Router,
    resource: Uuid,
    commands: &crate::commands::Commands,
) -> Result<()> {
    let now = pg("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")?
        .trim()
        .parse::<i64>()?;
    let active = pg(&format!(
        "SELECT count(*) FROM mdm_commands.action_runs WHERE device='{DEVICE_ID}' AND state->>'execution' IN ('not_started','running') AND state->>'cancellation'<>'confirmed' AND deadline>{now}"
    ))?
    .trim()
    .parse::<i64>()?;
    ensure!(active < 128, "capacity fixture requires room: {active}");
    pg(&format!(
        "INSERT INTO mdm_commands.action_runs(tenant_id,id,plan,device,registration,generation,occurrence,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint) SELECT source.tenant_id,gen_random_uuid(),source.plan,source.device,source.registration,source.generation,'capacity-fixture:'||n,{now},{now},{},source.state,false,source.dispatch_fingerprint FROM (SELECT * FROM mdm_commands.action_runs WHERE device='{DEVICE_ID}' AND state->>'execution'='not_started' ORDER BY created_at DESC LIMIT 1) source CROSS JOIN generate_series(1,{}) n",
        now + 3_600,
        128 - active
    ))?;
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.action_runs WHERE device='{DEVICE_ID}' AND state->>'execution' IN ('not_started','running') AND state->>'cancellation'<>'confirmed' AND deadline>{now}"
        ))?
        .trim()
            == "128"
    );

    let manual = Uuid::new_v4();
    post(
        author,
        router,
        "/api/v3/script-plans",
        json!({"operationId":manual,"resource":resource,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default","parameters":{},"devices":[DEVICE_ID],"schedule":{"trigger":{"kind":"manual"},"notBefore":now-1,"until":now+3_600,"jitterSeconds":0,"window":null},"runLifetimeSeconds":300}),
    )
    .await?;
    let approval = reviewer
        .call(
            router,
            Method::POST,
            &format!("/api/v3/script-plans/{manual}/approve"),
            Some(json!({"operationId":Uuid::new_v4()})),
        )
        .await?;
    ensure!(
        approval.0 == StatusCode::CONFLICT,
        "manual capacity: {approval:?}"
    );
    ensure!(
        pg(&format!(
            "SELECT reviewer IS NULL AND NOT EXISTS(SELECT 1 FROM mdm_commands.action_runs WHERE plan='{manual}') FROM mdm_commands.action_plans WHERE id='{manual}'"
        ))?
        .trim()
            == "t",
        "manual capacity failure was not atomic"
    );

    let timer = Uuid::new_v4();
    post(
        author,
        router,
        "/api/v3/script-plans",
        json!({"operationId":timer,"resource":resource,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default","parameters":{},"devices":[DEVICE_ID],"schedule":{"trigger":{"kind":"interval","anchor":now-60,"seconds":60},"notBefore":now-60,"until":now+3_600,"jitterSeconds":0,"window":null,"misfire":"coalesce_one"},"runLifetimeSeconds":300}),
    )
    .await?;
    post(
        reviewer,
        router,
        &format!("/api/v3/script-plans/{timer}/approve"),
        json!({"operationId":Uuid::new_v4()}),
    )
    .await?;
    let before = pg(&format!(
        "SELECT scan_at FROM mdm_commands.action_plans WHERE id='{timer}'"
    ))?;
    commands.scan_action_fixture(timer, now).await?;
    ensure!(
        pg(&format!(
            "SELECT scan_at FROM mdm_commands.action_plans WHERE id='{timer}'"
        ))? == before,
        "capacity-blocked timer advanced its cursor"
    );
    let blocked = pg(&format!(
        "SELECT blocked_at FROM mdm_commands.action_plans WHERE id='{timer}'"
    ))?
    .trim()
    .parse::<i64>()?;
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.action_runs WHERE plan='{timer}'"
        ))?
        .trim()
            == "0"
    );

    pg("DELETE FROM mdm_commands.action_runs WHERE occurrence LIKE 'capacity-fixture:%'")?;
    commands.scan_action_fixture(timer, blocked + 60).await?;
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.action_runs WHERE plan='{timer}'"
        ))?
        .trim()
            == "1",
        "timer retry did not produce the original occurrence first"
    );
    ensure!(
        pg(&format!(
            "SELECT scan_at={blocked} AND blocked_at IS NULL FROM mdm_commands.action_plans WHERE id='{timer}'"
        ))?
        .trim()
            == "t"
    );
    ensure!(
        pg(&format!(
            "SELECT occurrence FROM mdm_commands.action_runs WHERE plan='{timer}'"
        ))?
        .trim()
            == format!("timer:{blocked}")
    );
    for plan in [manual, timer] {
        post(
            author,
            router,
            &format!("/api/v3/script-plans/{plan}/cancel"),
            json!({"operationId":Uuid::new_v4()}),
        )
        .await?;
    }
    Ok(())
}
