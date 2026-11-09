//! One protected registration record per device; grants remain tenant scoped.
use crate::authority_t2_support::Context;
use anyhow::Result;
use rss_mdm_authorization_service::Permission;
use rss_mdm_install_support::StorageProfile;
use rss_mdm_registration_service::enrollment::registration::read;
use rss_request_context::TenantId;
use uuid::Uuid;

async fn seed(c: &Context, tenant: TenantId, device: &str) -> Result<Uuid> {
    let grant = Uuid::new_v4();
    let mut tx = c.operator.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO mdm_access.certificate_grants(tenant_id,id,operation_id,source,actor,instance,device,platform,secret_digest,request_digest,state,expires_at) VALUES($1::uuid,$2,$2,'download','directory-fixture',$3,$4,'windows',repeat('0',64),repeat('1',64),'consumed',clock_timestamp()+interval '1 hour')").bind(tenant.to_string()).bind(grant).bind(&c.inputs.installation.instance_id).bind(device).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.devices(tenant_id,id,channel,certificate_grant_id,state,purpose,epoch) VALUES($1::uuid,$2,'agent',$3,'active','primary',$4)").bind(tenant.to_string()).bind(device).bind(grant).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(grant)
}
#[tokio::test]
#[ignore = "T2: singular registration read preserves grant identity and current tenant authorization"]
async fn registration_read_preserves_grant_and_tenant_authority() -> Result<()> {
    let other = TenantId::parse(&Uuid::new_v4().to_string())?;
    let c = Context::open("shared", &[other]).await?;
    let result = async {
        let device = Uuid::new_v4().to_string();
        let grant = seed(&c, c.tenant, &device).await?;
        let foreign = seed(&c, other, &device).await?;
        assert_ne!(grant, foreign);
        let account = c.account(&[Permission::Credentials]).await?;
        let proof = c.read_auth(std::sync::Arc::new(c.authenticate(&account).await?));
        let store = c.database.registration();
        let row = read(StorageProfile::Mdm, &store, &proof, &device).await?;
        assert_eq!(row.device_id, device);
        assert_eq!(row.certificate_grant_id, Some(grant));
        let value = serde_json::to_value(row)?;
        assert!(value.get("registrationId").is_none());
        assert!(value.get("generation").is_none());
        let document = crate::http_contract_document().map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let endpoints = document["endpoints"].as_array().unwrap();
        assert!(
            !endpoints
                .iter()
                .any(|e| e["path"] == "/api/v1/devices/{device}/registrations")
        );
        let endpoint = endpoints
            .iter()
            .find(|e| e["method"] == "GET" && e["path"] == "/api/v1/devices/{device}/registration")
            .unwrap();
        let response = endpoint["responses"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["status"] == 200)
            .unwrap();
        let schema = response["body"]["schema"]["schemaId"].as_str().unwrap();
        assert!(jsonschema::validator_for(&document["schemas"][schema])?.is_valid(&value));
        assert!(matches!(
            read(
                StorageProfile::Mdm,
                &store,
                &proof,
                &Uuid::new_v4().to_string()
            )
            .await,
            Err(rss_mdm_registration_service::Error::NotFound)
        ));
        let reader = c.account(&[Permission::OperationRead]).await?;
        let denied = c.read_auth(std::sync::Arc::new(c.authenticate(&reader).await?));
        assert!(matches!(
            read(StorageProfile::Mdm, &store, &denied, &device).await,
            Err(rss_mdm_registration_service::Error::Forbidden)
        ));
        Ok(())
    }
    .await;
    c.close().await;
    result
}
