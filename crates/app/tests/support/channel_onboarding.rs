//! Approved controlled samples: these bytes prove server admission, not OS signing or installation.
use super::*;
use sha2::{Digest, Sha256};
pub(crate) fn bytes() -> Vec<u8> {
    case::name("controlled-rss-agent-installer")
        .as_bytes()
        .to_vec()
}
pub(crate) fn pin(windows: bool) -> Value {
    let identity = if windows {
        json!({"platform":"windows","product":"12345678-1234-4234-8234-123456789abc","publisher":"RSS controlled publisher"})
    } else {
        json!({"platform":"macos","receipt":"com.rss.agent.pkg","bundle":"com.rss.agent","team":"RSS1234567"})
    };
    json!({"content_origin":"https://mdm.example.test","packages":{if windows{"windows_x86_64"}else{"macos_aarch64"}:{"identity":identity,"package":"RSS.Agent","version":"1.2.3","sha256":Sha256::digest(bytes()).to_vec()}}})
}
pub(crate) async fn grants(user: &Browser, router: &Router) -> Result<()> {
    let subject = browser_subject(user, router).await?;
    let mut grants = identity::device_grants(
        None,
        &[
            "enrollment",
            "inventory_read",
            "software_deploy",
            "operation_read",
            "operation_cancel",
        ],
    )?;
    for name in [
        "resource_read",
        "resource_write",
        "software_read",
        "software_write",
        "software_approve",
        "software_withdraw",
        "policy_read",
        "policy_write",
        "scope_read",
        "scope_write",
        "group_read",
        "group_write",
        "group_recompute",
    ] {
        grants.push(crate::authorization::Grant {
            operation: serde_json::from_value(json!(name))?,
            scope: crate::authorization::Scope::Tenant,
        });
    }
    identity::set_grants(case_tenant(), &subject, grants).await
}
pub(crate) async fn publish(
    user: &mut Browser,
    router: &Router,
    _device: &str,
    windows: bool,
) -> Result<Uuid> {
    publish_until(user, router, _device, windows, None).await
}
pub(crate) async fn publish_until(
    user: &mut Browser,
    router: &Router,
    _device: &str,
    windows: bool,
    until: Option<i64>,
) -> Result<Uuid> {
    use software::write;
    grants(user, router).await?;
    let source = Uuid::new_v4();
    let source_path = format!("/api/v3/software/sources/{source}/revisions/1");
    let registered=write(user,router,&source_path,0,json!({"action":"register","definition":{"id":source,"revision":"1","protocol":{"kind":"private"}}})).await?;
    write(
        user,
        router,
        &source_path,
        1,
        json!({"action":"approve","evidence":["controlled-source"]}),
    )
    .await?;
    let resource = Uuid::new_v4();
    let path = format!("/api/v3/resources/{resource}");
    write(
        user,
        router,
        &path,
        0,
        json!({"action":"create","kind":"software"}),
    )
    .await?;
    let platform = if windows { "windows" } else { "macos" };
    let arch = if windows { "x86_64" } else { "aarch64" };
    let detect = if windows {
        json!({"kind":"msi_product","productCode":"{12345678-1234-4234-8234-123456789abc}","version":"1.2.3"})
    } else {
        json!({"kind":"pkg_receipt","receipt":"com.rss.agent.pkg","version":"1.2.3"})
    };
    let definition = json!({"source":registered["snapshot"],"package":"RSS.Agent","version":"1.2.3","artifacts":{"package":{"reference":"agent-installer","length":bytes().len(),"sha256":Sha256::digest(bytes()).to_vec()}},"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[],"behavior":{"kind":if windows{"msi"}else{"pkg"},"installer":"package","scope":"system","install":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place","uninstall":null,"detect":detect,"upgradeInvocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}}},"signatures":[],"provenance":{"kind":"private"},"export":{"kind":"disabled"}});
    write(user,router,&path,1,json!({"action":"version","version":"v1","kind":"software","variants":[{"platform":platform,"architecture":arch,"key":"default","declaration":{"kind":"software","definition":definition}}]})).await?;
    let request=Request::builder().method(Method::POST).uri(format!("{path}/content?version=v1&variant=default&platform={platform}&architecture={arch}&operation={}",Uuid::new_v4()))
        .header("host","mdm.example.test").header("origin","https://mdm.example.test").header("x-identity-request","1").header("x-csrf-token",user.csrf.as_ref().unwrap())
        .header("cookie",user.cookies.iter().map(|(k,v)|format!("{k}={v}")).collect::<Vec<_>>().join("; ")).header("content-type","application/octet-stream").body(Body::from(bytes()))?;
    {
        let _guard = software::content_setup_guard().await?;
        let response = router.clone().oneshot(request).await?;
        ensure!(
            response.status() == StatusCode::CREATED,
            "upload: {:?}",
            response.status()
        );
    }
    write(
        user,
        router,
        &path,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let approved = write(
        user,
        router,
        &format!("/api/v3/software/resources/{resource}/versions/v1"),
        0,
        json!({"action":"approve","evidence":["controlled-agent"]}),
    )
    .await?;
    let group = Uuid::new_v4();
    crate::test_support::planning_http::call(user,router,&format!("/api/v2/groups/{group}"),0,json!({"action":"create","name":"Agent missing","description":"","criteria":{"kind":"predicate","field":"channel.agent.installation","op":"eq","value":{"kind":"string","value":"absent"}}})).await?;
    let scope = Uuid::new_v4();
    write(user,router,&format!("/api/v2/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"group","id":group}],"limitations":null,"exclusions":[]}})).await?;
    let policy = Uuid::new_v4();
    let mut input = json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"ensure_agent_installed","resource":{"kind":"software","id":resource,"version":"v1","variants":{if windows{"windows_x86_64"}else{"macos_aarch64"}:"default"}},"admissionOperation":approved["admission"]["operation"],"runLifetimeSeconds":600}}});
    if let Some(until) = until {
        input["definition"]["action"]["schedule"] = json!({"trigger":{"kind":"check_in","minimumSeconds":60},"notBefore":0,"until":until,"jitterSeconds":0,"window":null,"misfire":{"kind":"coalesce_one"}});
    }
    write(
        user,
        router,
        &format!("/api/v2/policies/{policy}"),
        0,
        input,
    )
    .await?;
    Ok(policy)
}
pub(crate) async fn operation(policy: Uuid) -> Result<Uuid> {
    tokio::time::timeout(Duration::from_secs(30),async{loop{
        let id=pg(&format!("SELECT o.id FROM mdm_commands.operations o JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(o.tenant_id,o.policy_version) JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id='{}' AND v.policy='{policy}' AND d.status IN('published','received','applied')",case_tenant()))?;
        if !id.trim().is_empty(){return Ok::<_,anyhow::Error>(Uuid::parse_str(id.trim())?);}tokio::time::sleep(Duration::from_millis(100)).await;
    }}).await.map_err(|error| {
        let diagnosis=pg(&format!("SELECT jsonb_build_object('clock',(SELECT revision FROM mdm.asset_clock WHERE tenant_id='{tenant}'),'dispatch',(SELECT to_jsonb(d) FROM mdm_planning.asset_dispatch d WHERE tenant_id='{tenant}'),'groups',(SELECT jsonb_agg(to_jsonb(g)) FROM mdm_group.groups g WHERE tenant_id='{tenant}'),'jobs',(SELECT jsonb_agg(jsonb_build_object('kind',kind,'done',completed,'failure',failure,'forwarded',forwarded)) FROM mdm_automation.automation_jobs WHERE tenant_id='{tenant}'),'configuration',(SELECT jsonb_agg(to_jsonb(c)) FROM mdm_planning.configuration_devices c WHERE tenant_id='{tenant}'))",tenant=case_tenant())).unwrap_or_else(|_|"diagnostic unavailable".into());
        anyhow::anyhow!("installation wait: {error}; {diagnosis}")
    })?
}

pub(crate) async fn diagnosis(
    user: &mut Browser,
    router: &Router,
    policy: Uuid,
    device: &str,
) -> Result<Value> {
    let reply = user
        .call(
            router,
            Method::GET,
            &format!("/api/v2/policies/{policy}/devices"),
            None,
        )
        .await?;
    ensure!(reply.0 == StatusCode::OK, "Policy devices: {reply:?}");
    reply.1["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["device"] == device)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing device diagnosis: {:?}", reply.1))
}
