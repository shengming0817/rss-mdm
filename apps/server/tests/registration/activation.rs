//! Real activation consumes a legal issued candidate and owns first-registration time atomically.
use super::*;
#[expect(
    clippy::cognitive_complexity,
    reason = "The linear activation, rollback, replay and renewal proof retains original transaction coordinates"
)]
pub(super) async fn prove(
    c: &Context,
    n: &identity::Native,
    service: &agent::Service,
    input: &wire::NativeGrantRequest,
) -> Result<()> {
    let device = rss_mdm_agent_wire::DeviceId::new_v4();
    let grant = Uuid::new_v4();
    let (peer, certificate, csr) = crate::device_material_support::peer_material(
        c,
        &device,
        rss_mdm_agent_wire::pki::Purpose::Agent,
    )
    .await?;
    let metadata = peer.metadata();
    let issuance = Uuid::new_v4();
    let issuer = format!("{:x}", Sha256::digest(&n.root));
    let mut tx = command::seed_transaction(c).await?;
    use rss_mdm_inventory::builtin::{CLIENT_MODULES, MDM_ENROLLMENT};
    for field in rss_mdm_inventory::builtin::fields()
        .into_iter()
        .filter(|field| [MDM_ENROLLMENT, CLIENT_MODULES].contains(&field.key))
    {
        rss_mdm_inventory_postgres::publish_field_in(&mut tx, c.tenant, 0, &field).await?;
    }
    sqlx::query("INSERT INTO mdm_access.certificate_grants(tenant_id,id,operation_id,source,actor,instance,device,platform,secret_digest,request_digest,spki,state,expires_at) VALUES($1::uuid,$2,$2,'download','activation-time-proof',$3,$4,'windows',repeat('0',64),repeat('1',64),$5,'consumed',clock_timestamp()+interval '1 hour')")
        .bind(c.tenant.to_string()).bind(grant).bind(&c.inputs.installation.instance_id).bind(device.into_uuid()).bind(metadata.spki.iter().map(|v|format!("{v:02x}")).collect::<String>()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.certificate_issuances(tenant_id,id,grant_id,operation_id,request_digest,authority_digest,csr,spki,identity,profile,not_before,not_after,state,certificate_chain,metadata,fingerprint,signing_issuer) VALUES($1::uuid,$2,$3,$4,repeat('1',64),repeat('2',64),$5,$6,$7,$8,$9,$10,'issued',$11,$12,$13,$14)")
        .bind(c.tenant.to_string()).bind(issuance).bind(grant).bind(Uuid::new_v4()).bind(csr)
        .bind(metadata.spki.iter().map(|v|format!("{v:02x}")).collect::<String>()).bind(&metadata.identity).bind(serde_json::to_value(&input.runtime)?).bind(metadata.not_before).bind(metadata.not_after).bind(json!([STANDARD.encode(&certificate)])).bind(serde_json::to_value(metadata)?).bind(format!("{:x}",Sha256::digest(&certificate))).bind(&issuer).execute(&mut *tx).await?;
    tx.commit().await?;
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let _client = tokio::net::TcpStream::connect(socket.local_addr()?).await?;
    let (stream, _) = socket.accept().await?;
    let gateway =
        rss_mdm_certificate::GatewayConnection::from_stream(&stream, "127.0.0.1".parse()?)?;
    let origin = gateway.request_origin("https://localhost".into());
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        STANDARD.encode(&certificate)
    );
    let evidence = gateway.client_certificate(&pem)?;
    let request = wire::ActivationRequest {
        wire_version: 1,
        issuance_id: issuance,
        operation_id: Uuid::new_v4(),
    };
    let mut tx = command::seed_transaction(c).await?;
    let before: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    let receipt = service
        .activate(&evidence, &request, &audit(c), &origin)
        .await?;
    assert_eq!(receipt.runtime.device_id, device);
    let [definition] = receipt.runtime.collections.as_slice() else {
        anyhow::bail!("expected shared built-in definition")
    };
    assert_eq!(definition.dataset(), MDM_ENROLLMENT.as_str());
    assert!(
        definition
            .fields()
            .iter()
            .any(|field| field.key.as_str() == CLIENT_MODULES.as_str())
    );
    let registered: i64 = sqlx::query_scalar(
        "SELECT registered_at FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(device.into_uuid())
    .fetch_one(&c.operator)
    .await?;
    assert!(registered >= before);
    let audit_a = audit(c);
    let audit_b = audit(c);
    let (a, b) = tokio::join!(
        service.activate(&evidence, &request, &audit_a, &origin),
        service.activate(&evidence, &request, &audit_b, &origin)
    );
    assert_eq!(serde_json::to_value(a?)?, serde_json::to_value(&receipt)?);
    assert_eq!(serde_json::to_value(b?)?, serde_json::to_value(&receipt)?);
    let after: i64 = sqlx::query_scalar(
        "SELECT registered_at FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(device.into_uuid())
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(registered, after);
    // A renewed certificate replaces the credential while retaining the original device/time.
    let (peer, certificate, csr) = crate::device_material_support::peer_material(
        c,
        &device,
        rss_mdm_agent_wire::pki::Purpose::Agent,
    )
    .await?;
    let renewal: wire::GrantRequest = serde_json::from_value(
        json!({"tenantId":c.tenant.to_string(),"wireVersion":1,"operationId":Uuid::new_v4(),"secret":URL_SAFE_NO_PAD.encode([11;32]),"platform":"windows","csr":STANDARD.encode(&csr)}),
    )?;
    let renewal = service
        .renew(&evidence, &renewal, &audit(c), &origin)
        .await?;
    let metadata = peer.metadata();
    let issuance = Uuid::new_v4();
    let mut tx = command::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_access.certificate_issuances(tenant_id,id,grant_id,operation_id,request_digest,authority_digest,csr,spki,identity,profile,not_before,not_after,state,certificate_chain,metadata,fingerprint,signing_issuer) VALUES($1::uuid,$2,$3,$4,repeat('1',64),repeat('2',64),$5,$6,$7,$8,$9,$10,'issued',$11,$12,$13,$14)")
        .bind(c.tenant.to_string()).bind(issuance).bind(renewal.grant_id).bind(Uuid::new_v4()).bind(csr)
        .bind(metadata.spki.iter().map(|v|format!("{v:02x}")).collect::<String>()).bind(&metadata.identity).bind(serde_json::to_value(&input.runtime)?).bind(metadata.not_before).bind(metadata.not_after).bind(json!([STANDARD.encode(&certificate)])).bind(serde_json::to_value(metadata)?).bind(format!("{:x}",Sha256::digest(&certificate))).bind(&issuer).execute(&mut *tx).await?;
    tx.commit().await?;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        STANDARD.encode(&certificate)
    );
    let evidence = gateway.client_certificate(&pem)?;
    let request = wire::ActivationRequest {
        wire_version: 1,
        issuance_id: issuance,
        operation_id: Uuid::new_v4(),
    };
    let renewed = service
        .activate(&evidence, &request, &audit(c), &origin)
        .await?;
    assert_eq!(renewed.runtime.device_id, device);
    let after: i64 = sqlx::query_scalar(
        "SELECT registered_at FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(device.into_uuid())
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(registered, after);
    Ok(())
}
