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
            let request = h.c.read_auth(Arc::new(h.c.authenticate(&account).await?));
            let audit = h.c.request(&proof)?;
            let mut fence = h.c.operator.begin().await?;
            rss_mdm_authorization_service::lock_on(
                rss_mdm_install_support::StorageProfile::Mdm,
                &mut fence,
                proof.tenant_id(),
                proof.instance_id(),
            )
            .await?;
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *fence)
                .await?;
            let read = operations.directory(&request, &query, &codec, &audit);
            let write = async {
                h.c.wait_blocked(pid).await?;
                let mut tx = command::seed_transaction(&h.c).await?;
                sqlx::query("INSERT INTO mdm_access.devices(tenant_id,id) VALUES($1::uuid,$2)")
                    .bind(h.c.tenant.to_string())
                    .bind(format!("unrelated-{}", Uuid::new_v4()))
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
                fence.rollback().await?;
                Ok::<_, anyhow::Error>(())
            };
            let (page, ()) =
                tokio::try_join!(async { Ok::<_, anyhow::Error>(read.await?) }, write)?;
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

#[tokio::test]
#[ignore = "T2: production HTTP directory includes Script and both Collection channels with matching statistics and authorization"]
async fn recurring_owners_share_http_pagination_statistics_and_redacted_evidence() -> Result<()> {
    use tower::ServiceExt;
    let h = Harness::open().await?;
    let result=async {
        let (policy,version)=h.policy("directory-script").await?;
        let script=h.run(version,"directory-script",now()+300).await?;
        let (definition,frozen,_)=super::mixed::agent(&h)?;
        let collection_policy=Uuid::new_v4();
        let collection_version=super::mixed::publish(&h,collection_policy,1,definition,frozen).await?;
        let collection=super::mixed::run(&h,collection_version,now()).await?;
        let (native_policy,native,_)=super::retirement::native(&h,Some("timeout")).await?;
        let mut tx=command::seed_transaction(&h.c).await?;
        sqlx::query("UPDATE mdm_script.runs SET state=jsonb_set(jsonb_set(state,'{execution}','\"unknown\"'),'{startedAt}',to_jsonb($3::bigint)) WHERE tenant_id=$1::uuid AND id=$2").bind(h.c.tenant.to_string()).bind(script).bind(now()).execute(&mut *tx).await?;
        tx.commit().await?;
        let account=h.c.account(&[Permission::OperationRead,Permission::PolicyRead,Permission::InventoryRead]).await?;
        let proof=Arc::new(h.c.authenticate(&account).await?);
        let operations:Arc<dyn Reads>=Arc::new(crate::assembly::operation_reads::Operations {
            apple:Arc::new(rss_mdm_apple_channel::flow_store::Store{protection:h.a.resources.protection.clone()}),
            tasks:h.a.task_reads.clone(),registration:h.a.registration.native.clone(),recovery:None,execution:h.a.service.clone(),
        });
        let router=rss_mdm_management_http::execution::http::read_routes().with_state::<()>(operations.clone())
            .layer(axum::Extension(CursorCodec::new(&[8;32])?))
            .layer(axum::Extension(h.c.read_auth(proof.clone())))
            .layer(axum::Extension(h.c.request(&proof)?)).into_axum();
        // Exercise the real mounted handlers and HTTP encoders over loopback transport.
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address=listener.local_addr()?;
        let (stop,stopped)=tokio::sync::oneshot::channel::<()>();
        let server=tokio::spawn(async move {
            axum::serve(listener,router).with_graceful_shutdown(async{let _=stopped.await;}).await
        });
        let http=async {
            let client=reqwest::Client::builder().timeout(std::time::Duration::from_secs(6)).build()?;
            let base=format!("http://{address}");
            let mut cursor=None::<String>;
            let mut ids=std::collections::BTreeSet::new();
            loop {
                let mut query=vec![("limit".to_owned(),"1".into())];
                if let Some(c)=&cursor{query.push(("cursor".into(),c.clone()));}
                let response=client.get(format!("{base}/operations")).query(&query).send().await?;
                assert_eq!(response.status(),reqwest::StatusCode::OK);
                let value:Value=response.json().await?;
                let rows=value["items"].as_array().unwrap();
                assert_eq!(rows.len(),1);
                let row=&rows[0];
                let id=Uuid::parse_str(row["id"].as_str().unwrap())?;
                assert!(ids.insert(id));
                let owner=if id==script{"script"}else{"collection"};
                assert_eq!(row["evidence"]["owner"],owner);
                assert_eq!(row["kind"],"action_run");
                assert!(row["evidence"].get("native").is_none());
                if id==native{assert_eq!(row["status"],"expired");assert_eq!(row["evidence"]["report"]["reason"],"timeout");}
                let policy=if id==script{policy}else if id==collection{collection_policy}else{native_policy};
                assert_eq!(row["detailUrl"],format!("/api/v1/policies/{policy}/runs/{id}"));
                cursor=value["nextCursor"].as_str().map(str::to_owned);
                if cursor.is_none(){break;}
                assert!(ids.len()<4);
            }
            assert_eq!(ids,[script,collection,native].into());
            for (filter,count,unknown) in [
                (String::new(),3,1),
                (format!("device=={}",h.p.device()),2,1),
                (format!("policy=={policy}"),1,1),
                ("status==unknown".into(),1,1),
                ("status==expired".into(),1,0),
            ] {
                let query=if filter.is_empty(){vec![]}else{vec![("filter",filter.as_str())]};
                let page:Value=client.get(format!("{base}/operations")).query(&query).send().await?.error_for_status()?.json().await?;
                let stats:Value=client.get(format!("{base}/operations/statistics")).query(&query).send().await?.error_for_status()?.json().await?;
                assert_eq!(page["items"].as_array().unwrap().len(),count);
                assert_eq!(stats["statistics"]["total"],count);
                assert_eq!(stats["statistics"]["actionRuns"],count);
                assert_eq!(stats["statistics"]["unknown"],unknown);
            }
            // Raw Agent Collection detail still requires its separate sensitive permission.
            assert!(matches!(rss_mdm_management_http::execution::task_reads::Reads::run(h.a.task_reads.as_ref(),&h.c.read_auth(proof.clone()),&h.c.request(&proof)?,collection_policy,collection).await,Err(rss_mdm_management_http::Error::Forbidden)));
            assert!(rss_mdm_management_http::execution::task_reads::Reads::run(h.a.task_reads.as_ref(),&h.c.read_auth(proof.clone()),&h.c.request(&proof)?,native_policy,native).await.is_ok());
            let rule=rss_mdm_authorization_service::Rule{subject:rss_mdm_authorization_service::Subject::User{user:account.user.clone()},grants:vec![rss_mdm_authorization_service::Grant{operation:Permission::OperationRead,scope:rss_mdm_authorization_service::Scope::Device{id:h.p.device().into()}}]};
            sqlx::query("UPDATE mdm_access.authorization_rules SET document=$3,revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2").bind(h.c.tenant.to_string()).bind(account.rule).bind(serde_json::to_value(rule)?).execute(&h.c.operator).await?;
            let page:Value=client.get(format!("{base}/operations")).send().await?.error_for_status()?.json().await?;
            assert_eq!(page["items"].as_array().unwrap().len(),2);
            assert!(page["items"].as_array().unwrap().iter().all(|v|v["device"]==h.p.device()));
            let stats:Value=client.get(format!("{base}/operations/statistics")).send().await?.error_for_status()?.json().await?;
            assert_eq!(stats["statistics"]["total"],2);
            Ok::<(),anyhow::Error>(())
        }.await;
        let _=stop.send(());
        tokio::time::timeout(std::time::Duration::from_secs(10),server).await???;
        http?;
        // A verified identity lacking OperationRead is rejected by the same production handler.
        let denied=h.c.account(&[Permission::PolicyRead]).await?;
        let denied=Arc::new(h.c.authenticate(&denied).await?);
        let router=rss_mdm_management_http::execution::http::read_routes().with_state::<()>(operations)
            .layer(axum::Extension(CursorCodec::new(&[8;32])?))
            .layer(axum::Extension(h.c.read_auth(denied.clone())))
            .layer(axum::Extension(h.c.request(&denied)?)).into_axum();
        let response=router.oneshot(axum::http::Request::builder().uri("/operations").body(axum::body::Body::empty())?).await?;
        assert_eq!(response.status(),axum::http::StatusCode::FORBIDDEN);
        Ok(())
    }.await;
    h.close().await?;
    result
}

#[tokio::test]
#[ignore = "T2: PostgreSQL directory CASE and the native report owner share the exact terminal truth table"]
async fn native_report_sql_matches_the_owner_terminal_projection() -> Result<()> {
    let h = Harness::open().await?;
    let result=async {
        use rss_mdm_inventory_service::collection::execution::{model,queries};
        for (sealed,reason,result) in [(false,"timeout","failed"),(true,"complete","failed"),(true,"complete","snapshot"),(true,"complete","partial"),(true,"timeout","failed"),(true,"revoked","partial")] {
            let sql=format!("SELECT {} FROM (SELECT $1::bigint AS sealed_at,$2::text AS reason,$3::text AS result) report CROSS JOIN (SELECT 'sent'::text AS native_delivery) r",queries::NATIVE_STATUS_SQL);
            let actual:String=sqlx::QueryBuilder::<sqlx::Postgres>::new(sql).build_query_scalar().bind(sealed.then_some(1i64)).bind(reason).bind(result).fetch_one(&h.c.operator).await?;
            assert_eq!(actual,model::native_terminal_status(sealed,reason,result).unwrap_or("sent"));
        }
        Ok(())
    }.await;
    h.close().await?;
    result
}

#[tokio::test]
#[ignore = "T2: controlled concurrent writes cannot mix an execution snapshot; Identity revocation rejects delivery"]
async fn request_snapshot_is_stable_and_revalidates_identity() -> Result<()> {
    let h = Harness::open().await?;
    let result = async {
        let account = h.c.account(&[Permission::OperationRead]).await?;
        let request = h.c.read_auth(Arc::new(h.c.authenticate(&account).await?));
        let tenant = h.c.tenant.to_string();
        let (observed, wait_observed) = tokio::sync::oneshot::channel();
        let (committed, wait_committed) = tokio::sync::oneshot::channel();
        let writer = async {
            wait_observed.await?;
            let mut tx = command::seed_transaction(&h.c).await?;
            sqlx::query("INSERT INTO mdm_access.devices(tenant_id,id) VALUES($1::uuid,$2)")
                .bind(&tenant).bind(format!("unrelated-{}", Uuid::new_v4())).execute(&mut *tx).await?;
            tx.commit().await?;
            committed.send(()).unwrap();
            Ok::<_, anyhow::Error>(())
        };
        let reader = h.a.task_reads.snapshot(&request, (tenant.clone(), Some(observed), Some(wait_committed)), |state, c, _, _| Box::pin(async move {
            let before: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.devices WHERE tenant_id=$1::uuid").bind(&state.0).fetch_one(&mut *c).await.map_err(crate::assembly::task_reads::sql)?;
            state.1.take().unwrap().send(()).unwrap();
            state.2.take().unwrap().await.unwrap();
            let after: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.devices WHERE tenant_id=$1::uuid").bind(&state.0).fetch_one(&mut *c).await.map_err(crate::assembly::task_reads::sql)?;
            assert_eq!(before, after);
            Ok(before)
        }));
        let (before, ()) = tokio::try_join!(async { Ok::<_,anyhow::Error>(reader.await?) }, writer)?;
        let after: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.devices WHERE tenant_id=$1::uuid").bind(&tenant).fetch_one(&h.c.operator).await?;
        assert_eq!(after, before + 1);
        let rss_mdm_authorization_service::credential::RequestCredential::Cookie(secret) = account.credential()? else { unreachable!() };
        let session = h.c.authority.inspect_session(h.c.tenant, secret, request.remaining()?).await?;
        let rejected = h.a.task_reads.snapshot(&request, (&h.c.authority, Some(session)), |state, _, _, _| Box::pin(async move {
            state.0.revoke_current_session(state.1.take().unwrap(), rss_transactional_messaging::policy::OperationDeadline::from_remaining(std::time::Duration::from_secs(3))).await.map_err(|_|rss_mdm_management_http::Error::Unauthorized)?;
            Ok(())
        })).await;
        assert!(matches!(rejected, Err(rss_mdm_management_http::Error::Unauthorized)));
        Ok(())
    }.await;
    h.close().await?;
    result
}

#[tokio::test]
#[ignore = "T2: raw directory and detail consume actual access/command roles and the same Inventory snapshot"]
async fn raw_devices_use_authorized_presence_and_detail_connections() -> Result<()> {
    use rss_mdm_management_http::enrollment::directory as http;
    use tower::ServiceExt;
    let h = Harness::open().await?;
    let result = async {
        let endpoint = crate::planning_t2_support::endpoint(&h.c).await?;
        let device = endpoint.members[0].device.clone();
        let manual = crate::planning_t2_support::endpoint(&h.c).await?.members[0].device.clone();
        let empty = crate::planning_t2_support::endpoint(&h.c).await?.members[0].device.clone();
        let mut seed = command::seed_transaction(&h.c).await?;
        let field = rss_mdm_inventory::FieldKey::parse("device.name")?;
        let catalog = rss_mdm_inventory_postgres::catalog_in(&mut seed,h.c.tenant).await?;
        let definition = rss_mdm_inventory::CollectionDefinition::new("presence", "1", rss_mdm_inventory::Source::MdmWindows, vec![rss_mdm_inventory::CollectionField{definition:catalog.definition(field)?.clone(),scope:rss_mdm_inventory::CollectionScope::Device}])?;
        rss_mdm_inventory_postgres::register_collection_in(&mut seed,h.c.tenant,&definition).await?;
        let registration = endpoint.members[0].registration_id;
        let epoch:Uuid=sqlx::query_scalar("SELECT epoch FROM mdm_access.report_sources WHERE tenant_id=$1::uuid AND registration=$2 AND source='mdm.windows'").bind(h.c.tenant.to_string()).bind(registration).fetch_one(&mut *seed).await?;
        let scope=rss_mdm_registration_service::device::scope_dataset(rss_mdm_install_support::StorageProfile::Mdm,h.c.tenant,registration,"mdm.windows",epoch,"presence")?.encode()?;
        let projection=rss_mdm_inventory_postgres::projection_scope(h.c.tenant);
        sqlx::query("INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,registration,source,epoch,collection_sequence,field_scope) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,1,2,'known',$9,'mdm.windows',$10,1,'{\"kind\":\"device\"}')")
            .bind(h.c.tenant.to_string()).bind(projection.source().source()).bind(projection.generation()).bind(scope).bind(serde_json::to_string(&definition.coverage()?)?).bind(field.as_str()).bind(serde_json::to_string(&rss_mdm_inventory::Scalar::String("observed".into()))?).bind(Uuid::new_v4().to_string()).bind(registration.to_string()).bind(epoch.to_string()).execute(&mut *seed).await?;
        let evidence=rss_mdm_inventory::Evidence{scope:rss_mdm_inventory::CollectionScope::Device,source:rss_mdm_inventory::Source::Manual,dataset:None,registration:None,registration_generation:None,epoch:None,snapshot_id:Uuid::new_v4().to_string(),observed_at:1,received_at:2,actor:Some("presence-fixture".into())};
        assert_eq!(rss_mdm_inventory_postgres::assign_in(&mut seed,h.c.tenant,&manual,rss_mdm_inventory::builtin::ASSET_TAG,0,&rss_mdm_inventory::State::Known(rss_mdm_inventory::Scalar::String("manual".into())),&evidence).await?,Some(1));
        seed.commit().await?;
        let expected=std::collections::BTreeMap::from([(device.clone(),true),(manual.clone(),true),(empty.clone(),false)]);
        let devices = Arc::new(rss_mdm_registration_service::DeviceService::new(
            h.c.database.registration(),
            h.c.tenant.to_string(),
            h.c.audit.clone(),
        ));
        let reads = Arc::new(crate::assembly::device_reads::Devices {
            tasks: h.a.task_reads.clone(),
            devices: devices.clone(),
            windows: true,
            apple: false,
        });
        let account = h.c.account(&[Permission::InventoryRead]).await?;
        let proof = Arc::new(h.c.authenticate(&account).await?);
        let app = http::routes()
            .into_axum()
            .with_state(Arc::new(http::HttpState {
                cursor: CursorCodec::new(&[7; 32])?,
                devices,
                reads,
            }))
            .layer(axum::Extension(h.c.read_auth(proof.clone())))
            .layer(axum::Extension(h.c.request(&proof)?));
        for path in [
            "/devices?limit=100".to_owned(),
            format!("/devices/{device}"),
            format!("/devices/{manual}"),
            format!("/devices/{empty}"),
            "/devices/statistics".to_owned(),
        ] {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(&path)
                        .body(axum::body::Body::empty())?,
                )
                .await?;
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1_048_576).await?;
            let value: Value = serde_json::from_slice(&bytes)?;
            assert_eq!(status, axum::http::StatusCode::OK, "{path}: {value}");
            if let Some(id)=value["id"].as_str() {
                assert_eq!(value["inventoryAvailable"],expected[id]);
                assert!(
                    value["capabilities"]
                        .as_array()
                        .is_some_and(|v| !v.is_empty())
                );
            }
            if let Some(rows)=value["items"].as_array() {
                for (id,present) in &expected {
                    let row=rows.iter().find(|row|row["id"]==*id).expect("seeded endpoint in directory");
                    assert_eq!(row["inventoryAvailable"],*present);
                }
            }
        }
        let mut seed=command::seed_transaction(&h.c).await?;
        sqlx::query("UPDATE mdm_access.report_sources SET enabled=false WHERE tenant_id=$1::uuid AND registration=$2").bind(h.c.tenant.to_string()).bind(registration).execute(&mut *seed).await?;
        seed.commit().await?;
        let response=app.oneshot(axum::http::Request::builder().uri(format!("/devices/{device}")).body(axum::body::Body::empty())?).await?;
        assert_eq!(response.status(),axum::http::StatusCode::OK);
        let value:Value=serde_json::from_slice(&axum::body::to_bytes(response.into_body(),1_048_576).await?)?;
        assert_eq!(value["inventoryAvailable"],false,"revoked source must not count archived observations");
        let registration = h.c.database.registration();
        let mut tx = registration.snapshot(&h.c.tenant.to_string()).await?;
        let raw: bool =
            sqlx::query_scalar("SELECT has_table_privilege(current_user,'mdm.inventory','SELECT')")
                .fetch_one(&mut *tx)
                .await?;
        assert!(
            !raw,
            "presence must not grant the access role raw fact payloads"
        );
        tx.rollback().await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    h.close().await?;
    result
}
