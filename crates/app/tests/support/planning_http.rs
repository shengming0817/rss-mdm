use super::{http::*, process::*, runtime::*, *};
use anyhow::Context;
pub(crate) struct Server(pub(crate) tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub(crate) async fn call(
    browser: &mut Browser,
    router: &Router,
    path: &str,
    revision: u64,
    input: Value,
) -> Result<Value> {
    let (status, result) = settled_write(
        browser,
        router,
        path,
        json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":revision,"input":input}),
    )
    .await?;
    if status == StatusCode::CONFLICT && path.starts_with("/api/v1/groups/") {
        let current = browser.call(router, Method::GET, path, None).await?;
        anyhow::bail!(
            "group write at expected revision {revision}: {status} {result}; observed {current:?}"
        );
    }
    ensure!(
        status == StatusCode::OK || status == StatusCode::ACCEPTED,
        "planning request {path}: {status} {result}"
    );
    if let Some(task) = result["task"].as_str() {
        let status_url = result["statusUrl"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{path}/tasks/{task}"));
        await_task(browser, router, &status_url).await?;
    }
    Ok(result)
}
// Normal writes can collide with the live automation worker's serializable
// transaction. Retry the exact identity/body; injected failures bypass this helper.
pub(crate) async fn settled_write(
    browser: &mut Browser,
    router: &Router,
    path: &str,
    body: Value,
) -> Result<(StatusCode, Value)> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let result = browser
                .call(router, Method::POST, path, Some(body.clone()))
                .await?;
            if result.0 != StatusCode::SERVICE_UNAVAILABLE {
                return Ok(result);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("planning write did not settle")?
}
pub(crate) async fn await_ingress() -> Result<()> {
    let settled=tokio::time::timeout(Duration::from_secs(90),async {
        loop {
            let ready=pg(&format!("SELECT coalesce((SELECT consumed FROM mdm_planning.asset_dispatch WHERE tenant_id='{TENANT}'),0)=coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id='{TENANT}'),0) AND NOT EXISTS(SELECT 1 FROM mdm_automation.automation_jobs WHERE tenant_id='{TENANT}' AND NOT completed)", TENANT = case_tenant()))?;
            if ready.trim()=="t" { return Ok::<_,anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }).await;
    if let Ok(outcome) = settled {
        return outcome;
    }
    let progress = pg(&format!(
        "SELECT jsonb_build_object('clock',(SELECT revision FROM mdm.asset_clock WHERE tenant_id='{TENANT}'),'checkpoint',(SELECT to_jsonb(d)-'cursor' FROM mdm_planning.asset_dispatch d WHERE tenant_id='{TENANT}'),'jobs',(SELECT jsonb_agg(p) FROM (SELECT j.id,j.kind,j.forwarded,j.failure,r.phase,r.object_count FROM mdm_automation.automation_jobs j LEFT JOIN mdm_group.member_runs r ON (r.tenant_id,r.id)=(j.tenant_id,j.id) WHERE j.tenant_id='{TENANT}' AND NOT j.completed ORDER BY j.id LIMIT 16)p))",
        TENANT = case_tenant()
    ))?;
    anyhow::bail!("fixture ingress did not settle: {progress}")
}

/// Prepare an active native input without Resource publication or upload side effects.
pub(crate) async fn native_configuration_resource(
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
    tenant: rss_request_context::TenantId,
    content: &rss_mdm_content_service::Store,
    id: uuid::Uuid,
    platform: &str,
    architecture: &str,
    input: Value,
) -> Result<()> {
    native_configuration_bytes(
        runtime,
        tenant,
        content,
        id,
        platform,
        architecture,
        &serde_json::to_vec(&input)?,
    )
    .await
}

/// Prepare immutable native bytes, including unsigned Apple Profile data.
pub(crate) async fn native_configuration_bytes(
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
    tenant: rss_request_context::TenantId,
    content: &rss_mdm_content_service::Store,
    id: uuid::Uuid,
    platform: &str,
    architecture: &str,
    bytes: &[u8],
) -> Result<()> {
    use rss_mdm_resource::{Artifact, Declaration, Digest, Id, Kind, Variant, Version};
    let artifact = Artifact::new(
        Id::new("native-input")?,
        bytes.len() as u64,
        Digest::of(bytes),
    )?;
    let version = Version::new(
        tenant,
        Id::new(id.to_string())?,
        Id::new("v1")?,
        Kind::Configuration,
        vec![Variant::new(
            serde_json::from_value(json!(platform))?,
            serde_json::from_value(json!(architecture))?,
            Id::new("default")?,
            Declaration::Configuration {
                artifact: artifact.clone(),
            },
        )],
    )?;
    rss_mdm_content_service::fixture::native_configuration(
        content,
        &artifact,
        bytes.to_vec(),
        crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)? + 86400,
    )
    .await?;
    runtime
        .local_tx(tenant, crate::identity::deadline(), move |tx| {
            Box::pin(async move {
                rss_mdm_resource_postgres::fixture::active_version_in(
                    tx,
                    version,
                    rss_contract::Timepoint::try_from(1_i64).unwrap(),
                )
                .await
            })
        })
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    Ok(())
}
pub(crate) fn windows_configuration() -> Value {
    json!({"target":{"kind":"device"},"apply":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./Device/Vendor/MSFT/Policy/Config/Experience/AllowCortana","instance":[],"operation":"replace","value":{"type":"integer","value":"1"}}}},"remove":null})
}

/// Ordinary native consumers need an active template, not Resource publication tests.
pub(crate) async fn seed_native_template(
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
    tenant: rss_request_context::TenantId,
    id: uuid::Uuid,
    platform: rss_mdm_resource::Platform,
    template: rss_mdm_resource::NativeCollectionDefinition,
) -> Result<()> {
    use rss_mdm_resource::{
        Architecture, Artifact, Declaration, Digest, Id, Kind, Variant, Version,
    };
    let bytes = template.canonical();
    let artifact = Artifact::new(
        Id::new("native-template")?,
        bytes.len() as u64,
        Digest::of(&bytes),
    )?;
    let version = Version::new(
        tenant,
        Id::new(id.to_string())?,
        Id::new("v1")?,
        Kind::NativeCollection,
        [if platform == rss_mdm_resource::Platform::MacOS {
            Architecture::Aarch64
        } else {
            Architecture::X86_64
        }]
        .into_iter()
        .map(|architecture| {
            Variant::new(
                platform,
                architecture,
                Id::new("default").expect("fixed id"),
                Declaration::NativeCollection {
                    artifact: artifact.clone(),
                    definition: template.clone(),
                },
            )
        })
        .collect(),
    )?;
    runtime
        .local_tx(tenant, crate::identity::deadline(), move |tx| {
            Box::pin(async move {
                rss_mdm_resource_postgres::fixture::active_version_in(
                    tx,
                    version,
                    rss_contract::Timepoint::try_from(1_i64).expect("fixture time"),
                )
                .await
            })
        })
        .await
        .fold(
            Ok,
            |e| Err(anyhow::anyhow!(e)),
            |e| Err(anyhow::anyhow!(e)),
            |_| Err(anyhow::anyhow!("template rollback unconfirmed")),
            |_| Err(anyhow::anyhow!("template commit unconfirmed")),
            |e| Err(anyhow::anyhow!(e)),
        )
}
