//! A real aggregate read retains native ownership through the production collection response.
use super::*;
use axum::response::IntoResponse;
use rss_mdm_authorization_service::Permission;
use rss_mdm_management_http::execution::operations::{Page, Reads, SCHEMA};
use rss_mdm_query::cursor::CursorCodec;

#[tokio::test]
#[ignore = "T2: real native directory reads preserve nested owners and match the mounted HTTP schema"]
async fn native_directory_serializes_the_actual_owner_and_respects_projection() -> Result<()> {
    let mut h = Harness::open().await?;
    let result = async {
        let native = super::retirement::native_controls(&mut h, 1).await?;
        let account = h.c.account(&[Permission::OperationRead]).await?;
        let proof = h.c.authenticate(&account).await?;
        let operations = crate::assembly::operation_reads::Operations {
            apple: Arc::new(rss_mdm_apple_channel::flow_store::Store {
                protection: h.a.resources.protection.clone(),
            }),
            tasks: h.a.task_reads.clone(),
            registration: h.a.registration.native.clone(),
            recovery: None,
            execution: h.a.service.clone(),
        };
        let codec = CursorCodec::new(&[7; 32])?;
        let document = crate::http_contract_document().map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let endpoint = document["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["method"] == "GET" && e["path"] == "/api/v1/operations")
            .unwrap();
        let response = endpoint["responses"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["status"] == 200)
            .unwrap();
        let schema = response["body"]["schema"]["schemaId"].as_str().unwrap();
        let validator = jsonschema::validator_for(&document["schemas"][schema])?;

        for fields in [None, Some("id,kind,device")] {
            let mut parameters = url::form_urlencoded::Serializer::new(String::new());
            parameters.append_pair("filter", &format!("device=={}", native.device));
            if let Some(fields) = fields {
                parameters.append_pair("fields", fields);
            }
            let query = SCHEMA.parse(&parameters.finish())?;
            let page = operations
                .directory(&proof, &query, &codec, &h.c.request(&proof)?)
                .await?;
            assert_eq!(page.items.len(), 1);
            let page = Page {
                items: page
                    .items
                    .into_iter()
                    .map(|row| query.project_typed(row))
                    .collect::<rss_mdm_query::Result<Vec<_>>>()?,
                next_cursor: page.next_cursor,
            };
            let response =
                rss_mdm_http_contract::CollectionResponse(axum::Json(page)).into_response();
            assert_eq!(response.status(), axum::http::StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 65536).await?;
            let value: Value = serde_json::from_slice(&bytes)?;
            validator
                .validate(&value)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let row = &value["items"][0];
            assert_eq!(row["id"], Uuid::from_u128(1).to_string());
            if fields.is_none() {
                assert_eq!(row["evidence"]["owner"], "native");
                assert_eq!(row["evidence"]["detail"]["owner"], "device");
                assert_eq!(row["evidence"]["detail"]["operationId"], row["id"]);
            } else {
                assert!(row.get("evidence").is_none());
            }
        }
        Ok(())
    }
    .await;
    h.close().await?;
    result
}
