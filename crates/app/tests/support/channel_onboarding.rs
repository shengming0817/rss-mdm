//! Approved controlled samples: these bytes prove server admission, not OS signing or installation.
use super::{http::*, process::*, runtime::*, *};
pub(crate) fn installation_grants() -> Result<Vec<crate::authorization::Grant>> {
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
        "software_read",
        "software_write",
        "software_withdraw",
        "policy_read",
        "policy_write",
        "scope_read",
        "scope_write",
    ] {
        grants.push(crate::authorization::Grant {
            operation: serde_json::from_value(json!(name))?,
            scope: crate::authorization::Scope::Tenant,
        });
    }
    Ok(grants)
}
pub(crate) async fn publish(
    user: &mut Browser,
    router: &Router,
    device: &str,
    planning: &crate::planning::Planning,
    content: &rss_mdm_content_service::Store,
    windows: bool,
) -> Result<Uuid> {
    publish_until(user, router, device, planning, content, windows, None).await
}
pub(crate) async fn publish_until(
    user: &mut Browser,
    router: &Router,
    device: &str,
    planning: &crate::planning::Planning,
    content: &rss_mdm_content_service::Store,
    windows: bool,
    until: Option<i64>,
) -> Result<Uuid> {
    publish_format(
        user,
        router,
        device,
        planning,
        content,
        windows,
        until,
        ("msi", "1.2.3"),
    )
    .await
}
pub(crate) async fn publish_msix(
    user: &mut Browser,
    router: &Router,
    device: &str,
    planning: &crate::planning::Planning,
    content: &rss_mdm_content_service::Store,
) -> Result<Uuid> {
    publish_format(
        user,
        router,
        device,
        planning,
        content,
        true,
        None,
        ("msix", "1.2.3.0"),
    )
    .await
}
#[expect(
    clippy::too_many_arguments,
    reason = "specific publication prerequisites without an application container"
)]
async fn publish_format(
    user: &mut Browser,
    router: &Router,
    device: &str,
    planning: &crate::planning::Planning,
    content: &rss_mdm_content_service::Store,
    windows: bool,
    until: Option<i64>,
    package: (&str, &str),
) -> Result<Uuid> {
    let (format, _) = package;
    use software::write;
    let mut grants = installation_grants()?;
    if !windows {
        for operation in [
            crate::authorization::Permission::GroupRead,
            crate::authorization::Permission::GroupWrite,
            crate::authorization::Permission::GroupRecompute,
        ] {
            grants.push(crate::authorization::Grant {
                operation,
                scope: crate::authorization::Scope::Tenant,
            });
        }
    }
    identity::seed_grants(case_tenant(), &prepared_subject(user)?, grants).await?;
    let published = seed_package(
        &planning.runtime,
        planning.tenant,
        content,
        windows,
        package,
    )
    .await?;

    if format == "exe" || device.is_empty() {
        return Ok(published.release_id);
    }
    let scope = Uuid::new_v4();
    if windows {
        agent_execution::seed_scope(planning, scope, json!([{"kind":"device","id":device}]))
            .await?;
    } else {
        let group = Uuid::new_v4();
        crate::test_support::planning_http::call(user,router,&format!("/api/v1/groups/{group}"),0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":"Agent missing","description":""},"criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"channel.agent.installation","op":"eq","value":{"kind":"string","value":"absent"}}}})).await?;
        write(user,router,&format!("/api/v1/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"group","id":group}],"limitations":null,"exclusions":[]}})).await?;
    }
    let policy = Uuid::new_v4();
    let mut input = json!({"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"ensure_agent_installed","packages":{if windows{"windows_x86_64"}else{"macos_aarch64"}:published.release_id},"runLifetimeSeconds":3600}}});
    if let Some(until) = until {
        input["definition"]["action"]["schedule"] = json!({"trigger":{"kind":"check_in","minimumSeconds":60},"notBefore":0,"until":until,"jitterSeconds":0,"window":null,"misfire":{"kind":"coalesce_one"}});
    }
    write(
        user,
        router,
        &format!("/api/v1/policies/{policy}"),
        0,
        input,
    )
    .await?;
    Ok(policy)
}
pub(crate) async fn seed_package(
    runtime: &Arc<rss_transactional_messaging_postgres::PgRuntime>,
    tenant: rss_request_context::TenantId,
    content: &rss_mdm_content_service::Store,
    windows: bool,
    package: (&str, &str),
) -> Result<rss_mdm_agent_wire::enroll::configuration::Package> {
    let (format, version) = package;
    let msix = format == "msix";
    let package_bytes = match format {
        "msix" => installer_fixtures::msix(version, false),
        "exe" => installer_fixtures::exe(version),
        _ if windows => installer_fixtures::msi(Some(version), false),
        _ => installer_fixtures::pkg(version),
    };
    let platform = if windows { "windows" } else { "macos" };
    let arch = if windows { "x86_64" } else { "aarch64" };
    let detect = if windows {
        json!({"kind":"msi_product","productCode":"{12345678-1234-4234-8234-123456789abc}","version":"1.2.3"})
    } else {
        json!({"kind":"pkg_receipt","receipt":"com.rss.agent.pkg","version":"1.2.3"})
    };
    let invocation = json!({"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
    let mut behavior = json!({"kind":if windows{"msi"}else{"pkg"},"installer":"package","scope":"system","install":invocation,"upgradeInvocation":invocation,"upgrade":"in_place","uninstall":null,"detect":detect});
    if msix {
        behavior = json!({"kind":"msix","container":{"kind":"package","installer":"package"},"identity":{"name":"RSS.Agent","publisher":"CN=RSS","version":version.split('.').map(str::parse::<u16>).collect::<std::result::Result<Vec<_>,_>>()?,"architecture":"x86_64","resourceId":""},"dependencies":[],"deployment":{"kind":"device_provisioning"},"minimumOs":[10,0,19041,0],"requireSideload":true,"allowUnsigned":false,"uninstall":false,"invocation":{"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place"});
    }
    if format == "exe" {
        behavior["kind"] = json!("exe");
        behavior["layout"] = json!({"rss-agent.exe":"package"});
        behavior["detect"] = json!({"kind":"registry","scope":"system","key":"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\rss-agent","value":"DisplayVersion","version":"1.2.3"});
    }
    let source = rss_mdm_software_service::catalog::SourceDefinition {
        id: Uuid::new_v4().to_string(),
        revision: "1".into(),
        protocol: rss_mdm_software_service::catalog::SourceProtocol::Private,
    };
    let snapshot = runtime
        .local_tx(tenant, crate::identity::deadline(), move |tx| {
            Box::pin(async move {
                rss_mdm_software_service::catalog::fixture::source_in(tx, source)
                    .await
                    .map_err(|e| {
                        rss_transactional_messaging_postgres::PgError::from(sqlx::Error::Protocol(
                            e.to_string(),
                        ))
                    })
            })
        })
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    let resource = Uuid::new_v4();
    let definition = json!({"material":{"format":if windows {format}else{"pkg"},"installer":"package"},"source":snapshot,"package":format!("Private.{resource}"),"version":version,"artifacts":{"package":{"reference":"package","length":package_bytes.len(),"sha256":rss_mdm_resource::Digest::of(&package_bytes).bytes()}},"behavior":behavior,"reboot":"report","downgrade":"deny","dependencies":[],"signatures":[],"provenance":{"kind":"private"},"export":{"kind":"disabled"}});
    let stored =
        software_execution::seed_resource(runtime, tenant, resource, platform, arch, definition)
            .await?;
    let artifact = rss_mdm_resource::Artifact::new(
        rss_mdm_resource::Id::new("package")?,
        package_bytes.len() as u64,
        rss_mdm_resource::Digest::of(&package_bytes),
    )?;
    rss_mdm_content_service::fixture::artifact(
        content,
        &artifact,
        package_bytes,
        crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)? + 86400,
    )
    .await?;
    software_execution::seed_enabled(runtime, content, &stored).await?;
    let target = serde_json::from_value(json!({"platform":platform,"architecture":arch}))?;
    let published = runtime
        .local_tx(tenant, crate::identity::deadline(), move |tx| {
            Box::pin(async move {
                rss_mdm_software_service::agent_packages::fixture_release_in(
                    tx, &stored, target, "default",
                )
                .await
                .map_err(|e| {
                    rss_transactional_messaging_postgres::PgError::from(sqlx::Error::Protocol(
                        e.to_string(),
                    ))
                })
            })
        })
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    Ok(published)
}

pub(crate) async fn operation(policy: Uuid) -> Result<Uuid> {
    tokio::time::timeout(Duration::from_secs(30),async{loop{
        let id=pg(&format!("SELECT o.id FROM mdm_commands.operations o JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(o.tenant_id,o.policy_version) JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id='{}' AND v.policy='{policy}' AND o.authority->>'stage'='install' AND d.status IN('published','received','applied')",case_tenant()))?;
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
            &format!("/api/v1/policies/{policy}/assignments"),
            None,
        )
        .await?;
    ensure!(reply.0 == StatusCode::OK, "Policy assignments: {reply:?}");
    reply.1["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| {
            i["target"]["device"] == device
                || (i["object"]["kind"] == "endpoint" && i["object"]["id"] == device)
        })
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing device diagnosis: {:?}", reply.1))
}

pub(crate) async fn publish_exe(
    user: &mut Browser,
    router: &Router,
    device: &str,
    planning: &crate::planning::Planning,
    content: &rss_mdm_content_service::Store,
) -> Result<Uuid> {
    publish_format(
        user,
        router,
        device,
        planning,
        content,
        true,
        None,
        ("exe", "1.2.3"),
    )
    .await
}

/// Admit a release without configuring a Policy or starting group automation.
pub(crate) async fn publish_macos_release(
    user: &mut Browser,
    router: &Router,
    planning: &crate::planning::Planning,
    content: &rss_mdm_content_service::Store,
) -> Result<Uuid> {
    publish_format(
        user,
        router,
        "",
        planning,
        content,
        false,
        None,
        ("pkg", "1.2.3"),
    )
    .await
}

pub(crate) async fn publish_msix_release(
    user: &mut Browser,
    router: &Router,
    planning: &crate::planning::Planning,
    content: &rss_mdm_content_service::Store,
    version: &str,
) -> Result<Uuid> {
    publish_format(
        user,
        router,
        "",
        planning,
        content,
        true,
        None,
        ("msix", version),
    )
    .await
}
