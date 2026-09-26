//! Real HTTP planning admission over published Scope results and current grants.
use super::*;
pub(super) async fn verify(
    author: &mut Browser,
    router: &Router,
    resource: Uuid,
    base: &Value,
    grants: &[crate::authorization::Grant],
) -> Result<()> {
    use crate::authorization::{Grant, Permission, Scope};
    let subject = browser_subject(author, router).await?;
    let mut expanded = grants.to_vec();
    for operation in [
        Permission::ScopeRead,
        Permission::ScopeWrite,
        Permission::ScriptExecute,
        Permission::OperationCancel,
    ] {
        expanded.push(Grant {
            operation,
            scope: if matches!(operation, Permission::ScopeRead | Permission::ScopeWrite) {
                Scope::Tenant
            } else {
                Scope::AllDevices
            },
        });
    }
    crate::identity_fixture::set_grants(TENANT, &subject, expanded).await?;
    let group = Uuid::new_v4();
    let scope = Uuid::new_v4();
    let group_path = format!("/api/v2/groups/{group}");
    let scope_path = format!("/api/v2/scopes/{scope}");
    post(author,router,&group_path,json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"create","name":"scope-boundary","description":"","criteria":null}})).await?;
    post(author,router,&scope_path,json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":{"targets":[{"kind":"group","id":group}],"limitations":null,"exclusions":[]}}})).await?;
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let template = json!({"resource":resource,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default","parameters":{},"scopeRef":{"id":scope,"resolutionRevision":1},"schedule":{"trigger":{"kind":"manual"},"notBefore":now,"until":now+3600,"jitterSeconds":0,"window":null},"runLifetimeSeconds":300});
    let mut request = template.clone();
    request["operationId"] = json!(Uuid::new_v4());
    let unavailable = author
        .call(router, Method::POST, "/api/v3/script-plans", Some(request))
        .await?;
    ensure!(
        unavailable.0 == StatusCode::CONFLICT && unavailable.1["code"] == "scope_unavailable",
        "unpublished: {unavailable:?}"
    );
    let automation = start_automation(base).await?;
    let mut previous = 0;
    for count in [0usize, 256, 257] {
        if count > 0 {
            // Seed physical device/registration facts; membership, resolution and plans use product APIs.
            let start = if count == 256 { 0 } else { 256 };
            let mut seed = String::new();
            for n in start..count {
                let device = format!("bound-{group}-{n:03}");
                let grant = Uuid::new_v4();
                let request = Uuid::new_v4();
                let registration = Uuid::new_v4();
                seed.push_str(&format!("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{TENANT}','{grant}','operator','mdm','{device}','enrollment','consumed',clock_timestamp()+interval '60 seconds');INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source) VALUES('{TENANT}','{request}','{grant}','mdm.windows');INSERT INTO mdm_access.devices VALUES('{TENANT}','{device}');INSERT INTO mdm_access.registrations VALUES('{TENANT}','{registration}','{device}','mdm',1,'{request}','active');INSERT INTO mdm_access.credentials(tenant_id,id,registration,channel,locator,state) VALUES('{TENANT}',gen_random_uuid(),'{registration}','mdm',encode(sha256(convert_to('{registration}','UTF8')),'hex'),'active');INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,coverage,enabled) VALUES('{TENANT}','{registration}','mdm.windows',gen_random_uuid(),'{{}}',true);"));
            }
            pg(&seed)?;
            let (_, current) = author.call(router, Method::GET, &group_path, None).await?;
            let members: Vec<_> = (start..count)
                .map(|n| format!("bound-{group}-{n:03}"))
                .collect();
            let changed=post(author,router,&group_path,json!({"operationId":Uuid::new_v4(),"expectedRevision":current["group"]["revision"],"input":{"action":"members","add":members,"remove":[]}})).await?;
            if let Some(task) = changed["task"].as_str() {
                await_task(author, router, &format!("{group_path}/tasks/{task}")).await?;
            }
        }
        let resolution = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let (_, value) = author.call(router, Method::GET, &scope_path, None).await?;
                if value["resolutionRevision"]
                    .as_u64()
                    .is_some_and(|v| v > previous)
                {
                    return Ok::<_, anyhow::Error>(value["resolutionRevision"].as_u64().unwrap());
                }
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
        })
        .await??;
        previous = resolution;
        let id = Uuid::new_v4();
        let mut request = template.clone();
        request["operationId"] = json!(id);
        request["scopeRef"]["resolutionRevision"] = json!(resolution);
        let response = author
            .call(
                router,
                Method::POST,
                "/api/v3/script-plans",
                Some(request.clone()),
            )
            .await?;
        match count {
            0 => ensure!(
                response.0 == StatusCode::BAD_REQUEST
                    && response.1["code"] == "action_targets_empty",
                "empty: {response:?}"
            ),
            256 => {
                ensure!(
                    response.0 == StatusCode::ACCEPTED && response.1["targetCount"] == 256,
                    "256: {response:?}"
                );
                post(
                    author,
                    router,
                    &format!("/api/v3/script-plans/{id}/cancel"),
                    json!({"operationId":Uuid::new_v4()}),
                )
                .await?;
                let tenant = Uuid::new_v4();
                let foreign = Uuid::new_v4();
                pg(&format!(
                    "INSERT INTO mdm_planning.scopes(tenant_id,id,revision) VALUES('{tenant}','{foreign}',1)"
                ))?;
                request["operationId"] = json!(Uuid::new_v4());
                request["scopeRef"]["id"] = json!(foreign);
                let hidden = author
                    .call(router, Method::POST, "/api/v3/script-plans", Some(request))
                    .await?;
                ensure!(
                    hidden.0 == StatusCode::NOT_FOUND && hidden.1["code"] == "scope_not_found",
                    "cross tenant: {hidden:?}"
                );
            }
            257 => ensure!(
                response.0 == StatusCode::BAD_REQUEST
                    && response.1["code"] == "action_target_limit",
                "257: {response:?}"
            ),
            _ => unreachable!(),
        }
    }
    ensure!(automation.shutdown().join().await?.is_clean());
    crate::identity_fixture::set_grants(TENANT, &subject, grants.to_vec()).await?;
    Ok(())
}
