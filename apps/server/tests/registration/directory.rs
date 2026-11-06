//! The directory consumes real SQL, current authorization and typed field omission.
use crate::authority_t2_support::Context;
use anyhow::Result;
use rss_mdm_authorization_service::Permission;
use rss_mdm_install_support::StorageProfile;
use rss_mdm_query::cursor::CursorCodec;
use rss_mdm_registration_service::enrollment::registrations::{SCHEMA, list};
use rss_request_context::TenantId;
use serde_json::json;
use uuid::Uuid;

async fn seed(
    c: &Context,
    tenant: TenantId,
    device: &str,
    generation: i64,
) -> Result<(Uuid, Uuid)> {
    let registration = Uuid::new_v4();
    let grant = Uuid::new_v4();
    let mut tx = c.operator.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO mdm_access.devices(tenant_id,id) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING",
    )
    .bind(tenant.to_string())
    .bind(device)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO mdm_access.certificate_grants(tenant_id,id,operation_id,source,actor,instance,device,platform,secret_digest,request_digest,state,expires_at) VALUES($1::uuid,$2,$2,'download','directory-fixture',$3,$4,'windows',repeat('0',64),repeat('1',64),'consumed',clock_timestamp()+interval '1 hour')")
        .bind(tenant.to_string()).bind(grant).bind(&c.inputs.installation.instance_id).bind(device).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,certificate_grant_id,state,purpose,epoch) VALUES($1::uuid,$2,$3,'agent',$4,$5,$6,'primary',$7)")
        .bind(tenant.to_string()).bind(registration).bind(device).bind(generation).bind(grant)
        .bind(if generation == 1 { "superseded" } else { "active" }).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((registration, grant))
}

#[tokio::test]
#[ignore = "T2: real registration SQL preserves certificate grant identity through projection, paging and current authorization"]
async fn certificate_grants_survive_sql_projection_and_isolated_paging() -> Result<()> {
    let other = TenantId::parse(&Uuid::new_v4().to_string())?;
    let c = Context::open("shared", &[other]).await?;
    let result = async {
        let device = format!("directory-{}", Uuid::new_v4());
        let expected = std::collections::BTreeMap::from([
            seed(&c, c.tenant, &device, 1).await?,
            seed(&c, c.tenant, &device, 2).await?,
        ]);
        let other_device = format!("directory-{}", Uuid::new_v4());
        seed(&c, c.tenant, &other_device, 2).await?;
        seed(&c, other, &device, 2).await?;
        let account = c.account(&[Permission::Credentials]).await?;
        let proof = c.read_auth(std::sync::Arc::new(c.authenticate(&account).await?));
        let store = c.database.registration();
        let codec = CursorCodec::new(&[8; 32])?;
        let document = crate::http_contract_document().map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let endpoint = document["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["method"] == "GET" && e["path"] == "/api/v1/devices/{device}/registrations")
            .unwrap();
        let response = endpoint["responses"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["status"] == 200)
            .unwrap();
        let schema = response["body"]["schema"]["schemaId"].as_str().unwrap();
        let validator = jsonschema::validator_for(&document["schemas"][schema])?;

        let page = list(
            StorageProfile::Mdm,
            &store,
            &proof,
            &device,
            &SCHEMA.parse("")?,
            &codec,
        )
        .await?;
        assert_eq!(page.items.len(), 2);
        let value = serde_json::to_value(page)?;
        validator
            .validate(&value)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        for row in value["items"].as_array().unwrap() {
            let registration = Uuid::parse_str(row["registrationId"].as_str().unwrap())?;
            assert_eq!(row["certificateGrantId"], json!(expected[&registration]));
            assert!(row.get("agentGrantId").is_none());
        }

        let raw = "fields=registrationId,certificateGrantId&limit=1";
        let first = list(
            StorageProfile::Mdm,
            &store,
            &proof,
            &device,
            &SCHEMA.parse(raw)?,
            &codec,
        )
        .await?;
        assert_eq!(first.items.len(), 1);
        let cursor = first.next_cursor.clone().expect("second registration page");
        let mut parameters = url::form_urlencoded::Serializer::new(String::new());
        parameters
            .append_pair("fields", "registrationId,certificateGrantId")
            .append_pair("limit", "1")
            .append_pair("cursor", &cursor);
        let query = SCHEMA.parse(&parameters.finish())?;
        seed(&c, c.tenant, &format!("unrelated-{}", Uuid::new_v4()), 2).await?;
        let second = list(StorageProfile::Mdm, &store, &proof, &device, &query, &codec).await?;
        assert_eq!(second.items.len(), 1);
        assert!(second.next_cursor.is_none());
        let actual = first
            .items
            .into_iter()
            .chain(second.items)
            .map(|row| {
                let row = serde_json::to_value(row).unwrap();
                assert_eq!(row.as_object().unwrap().len(), 2);
                (
                    Uuid::parse_str(row["registrationId"].as_str().unwrap()).unwrap(),
                    Uuid::parse_str(row["certificateGrantId"].as_str().unwrap()).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected.into_iter().collect::<Vec<_>>());
        assert!(matches!(
            list(
                StorageProfile::Mdm,
                &store,
                &proof,
                &other_device,
                &query,
                &codec
            )
            .await,
            Err(rss_mdm_registration_service::Error::CursorInvalidated)
        ));

        let page = list(
            StorageProfile::Mdm,
            &store,
            &proof,
            &device,
            &SCHEMA.parse("fields=registrationId")?,
            &codec,
        )
        .await?;
        assert_eq!(page.items.len(), 2);
        for row in page.items {
            let row = serde_json::to_value(row)?;
            assert_eq!(row.as_object().unwrap().len(), 1);
            assert!(row.get("certificateGrantId").is_none());
        }
        let reader = c.account(&[Permission::OperationRead]).await?;
        let denied = c.read_auth(std::sync::Arc::new(c.authenticate(&reader).await?));
        assert!(matches!(
            list(
                StorageProfile::Mdm,
                &store,
                &denied,
                &device,
                &SCHEMA.parse("")?,
                &codec
            )
            .await,
            Err(rss_mdm_registration_service::Error::Forbidden)
        ));
        Ok(())
    }
    .await;
    c.close().await;
    result
}
