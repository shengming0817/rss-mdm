//! Registration consumes the original Software installation, with real certificate/source checks.
use super::software_t2::support::{audit, context, now, schedule, software};
use crate::{
    authority_t2_support::Context, command_runtime_t2_support as command,
    native_identity_t2_support as identity,
};
use anyhow::Result;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rss_mdm_agent_wire::{enroll as wire, runtime as w};
use rss_mdm_registration_service::{agent, certificate_issuance as agent_pki};
use rss_mdm_software_service::deployment as owner;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;
mod activation;
pub(super) mod support;

#[tokio::test]
#[ignore = "T2: real bootstrap identity and dispatched Software installation authorize one device-bound native grant"]
async fn native_grant_binds_original_device_and_replays_once() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let n = identity::seed(&c, "windows").await?;
    let other = identity::seed(&c, "windows").await?;
    let installation = Uuid::new_v4();
    let bootstrap = Uuid::new_v4();
    let materials = support::materials(&c, &n, installation, bootstrap).await?;
    let resources = command::Prepared::open(&c, false, |_| {}).await?;
    let authority = Arc::new(
        rss_mdm_software_service::deployment::managed_registration::AuthorityReader {
            tenant: c.tenant,
            instance: resources.config.identity.instance_id.clone(),
            source: Arc::new(crate::assembly::software_sources::Source(
                resources.source.clone(),
            )),
            inventory: Arc::new(crate::assembly::software_sources::Inventory),
            lifecycle: Arc::new(crate::assembly::software_sources::Lifecycle),
            protection: resources.protection.clone(),
            software_distribution: resources.config.software_distribution,
        },
    );
    support::installation(
        &c,
        &n,
        &resources.protection,
        installation,
        bootstrap,
        &materials,
    )
    .await?;
    let service = support::service(
        &c,
        &n,
        authority.clone(),
        resources.protection.clone(),
        &materials,
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let _client = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
    let (server, _) = listener.accept().await?;
    let gateway =
        rss_mdm_certificate::GatewayConnection::from_stream(&server, "127.0.0.1".parse()?)?;
    let peer = gateway.client_certificate(&std::fs::read_to_string(
        materials.directory.join("bootstrap.pem"),
    )?)?;
    let mut input: wire::NativeGrantRequest = serde_json::from_value(json!({
        "wireVersion":1,"operationId":Uuid::new_v4(),"installationOperation":installation,
        "secret":URL_SAFE_NO_PAD.encode([7;32]),"csr":STANDARD.encode(&materials.csr),
        "runtime":{"capabilities":["inventory.collect.v1"],"platform":"windows","architecture":"x86_64","executionContext":context()}
    }))?;
    input.runtime.capabilities = vec![w::Capability::InventoryCollectionV1];
    input.validate()?;
    let request = audit(&c);
    // Certificate subject mismatch cannot create a grant, even for an otherwise valid request.
    input.installation_operation = Uuid::new_v4();
    let before = support::bootstrap(&c, bootstrap).await?;
    let failure = service
        .native_grant(&peer, &input, &request)
        .await
        .expect_err("wrong binding denied");
    assert!(matches!(failure.code, wire::ErrorCode::PermissionDenied));
    assert_eq!(support::bootstrap(&c, bootstrap).await?, before);
    assert_eq!(support::counts(&c).await?, (1, 0));
    input.installation_operation = installation;
    // A bootstrap bound to a different device cannot authorize the current native source.
    let mut tx = command::seed_transaction(&c).await?;
    sqlx::query(
        "UPDATE mdm_access.agent_bootstraps SET source=jsonb_set(source,'{device}',to_jsonb($3::text)) WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(bootstrap)
    .bind(other.device.into_uuid())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let before = support::bootstrap(&c, bootstrap).await?;
    let failure = service
        .native_grant(&peer, &input, &request)
        .await
        .expect_err("wrong binding denied");
    assert!(matches!(failure.code, wire::ErrorCode::PermissionDenied));
    assert_eq!(support::bootstrap(&c, bootstrap).await?, before);
    assert_eq!(support::counts(&c).await?, (1, 0));
    let mut tx = command::seed_transaction(&c).await?;
    sqlx::query(
        "UPDATE mdm_access.agent_bootstraps SET source=jsonb_set(source,'{device}',to_jsonb($3::text)) WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(bootstrap)
    .bind(n.device.into_uuid())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let (first, replay) = tokio::join!(
        service.native_grant(&peer, &input, &request),
        service.native_grant(&peer, &input, &request)
    );
    let first = first?;
    assert_eq!(
        serde_json::to_value(&first)?,
        serde_json::to_value(replay?)?
    );
    assert_eq!(support::counts(&c).await?, (1, 1));
    let bounded:bool=sqlx::query_scalar("SELECT g.expires_at<=to_timestamp(b.deadline) FROM mdm_access.certificate_grants g JOIN mdm_access.agent_bootstraps b ON b.tenant_id=g.tenant_id AND b.id=(g.native_authority->>'bootstrap')::uuid WHERE g.tenant_id=$1::uuid AND g.source='native'").bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
    assert!(bounded);
    let source:Value=sqlx::query_scalar("SELECT native_authority FROM mdm_access.certificate_grants WHERE tenant_id=$1::uuid AND source='native'").bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
    assert_eq!(source["installation"], json!(installation));
    assert_eq!(source["device"], json!(n.device.clone()));
    assert!(source.get("generation").is_none());
    assert!(source.get("registration").is_none());
    assert_eq!(source["bootstrap"], json!(bootstrap));
    // Registration projects its own state on the caller's real role/tenant snapshot.
    // Issuing a grant does not itself invent an authenticated Agent registration.
    use rss_mdm_registration_service::installation::queries as observations;
    let pool = c.inputs.pool("shared", "mdm_command_runtime").await?;
    let mut snapshot = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *snapshot)
        .await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(c.tenant.to_string())
        .execute(&mut *snapshot)
        .await?;
    let projected = observations::installations_on(&mut snapshot, c.tenant, &[installation])
        .await?
        .remove(&installation)
        .expect("requested installation");
    assert!(projected.registration.is_none());
    assert!(matches!(
        projected.bootstrap.expect("retained bootstrap").state,
        observations::BootstrapState::Consumed
    ));
    assert!(
        observations::cleanup_pending_on(&mut snapshot, &c.tenant.to_string(), &n.device).await?
    );
    assert!(
        !observations::cleanup_pending_on(&mut snapshot, &c.tenant.to_string(), &other.device)
            .await?
    );
    let contact =
        observations::native_contact_on(&mut snapshot, &c.tenant.to_string(), &n.device).await?;
    assert_eq!(
        (contact.active, contact.bindings, contact.last),
        (0, 0, None)
    );
    let foreign = rss_request_context::TenantId::parse(&Uuid::new_v4().to_string())?;
    let hidden = observations::installations_on(&mut snapshot, foreign, &[installation])
        .await?
        .remove(&installation)
        .expect("requested installation");
    assert!(hidden.bootstrap.is_none() && hidden.registration.is_none());
    snapshot.rollback().await?;
    pool.close().await;
    activation::prove(&c, &n, &service, &input).await?;
    resources.close().await?;
    c.close().await;
    Ok(())
}
