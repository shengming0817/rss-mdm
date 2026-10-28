use super::*;
use crate::test_support::{http::*, runtime::*, *};
use anyhow::Context;
const DEFINITIONS: &str = "/api/v1/user-attribute-definitions";
const ME: &str = "/api/v1/user-profiles/me";
fn definition() -> Value {
    json!({"key":"employeeNumber","displayName":"Employee number","source":{"kind":"identity_local"},"pointer":"/extensions/employeeNumber","valueType":"string","maxLength":64,"maxItems":null,"minimum":null,"maximum":null,"enabled":true,"sensitive":false,"visibility":"both","displayUse":"profile","required":true,"useExistingObservation":false})
}
async fn ok(
    b: &mut Browser,
    r: &Router,
    method: Method,
    path: &str,
    value: Option<Value>,
) -> Result<Value> {
    let (status, value) = b.call(r, method, path, value).await?;
    ensure!(status == StatusCode::OK, "{path}: {status} {value}");
    Ok(value)
}
fn local_change(revision: i64, value: Option<&str>) -> Value {
    json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"value":value.map(|value|json!({"displayName":"Profile owner","username":null,"email":"profile@example.test","extensions":{"employeeNumber":value,"remote":false},"maxAgeSeconds":14400}))})
}
#[tokio::test]
#[ignore = "MODULE=settings.user_profiles: real identity observations, mappings, authorization, CAS and receipts"]
async fn login_bound_projection_and_definition_lifecycle() -> Result<()> {
    let mut f = authority::Authority::open().await?;
    let resources = std::mem::take(&mut f.resources);
    resources
        .finish(async {
            let backend = Arc::new(Backend {
                cursor: rss_mdm_query::cursor::CursorCodec::new(&[29;32]).unwrap(),
                identity: f.identity.authority.clone(),
                tenant: f.identity.tenant,
                instance: f.identity.instance,
                audit: f.audit.clone(),
            });
            let router = f.router(rss_mdm_http_contract::Router::new().nest(
                "/api/v1",
                rss_mdm_management_http::user_profiles::routes(backend),
            ))?;
            let mut admin = f.browser("admin")?;
            let local = format!(
                "/api/v1/identity/tenants/{}/accounts/{}/profile",
                case_tenant(),
                case::admin()
            );
            ok(
                &mut admin,
                &router,
                Method::PUT,
                &local,
                Some(local_change(0, Some("E1001"))),
            )
            .await?;
            admin = Browser::default();
            ensure!(
                admin
                    .login_password(&router, "admin", identity::PASSWORD)
                    .await?
                    == StatusCode::OK
            );
            let accounts=format!("/api/v1/identity/tenants/{}/accounts?source=local&fields=principalId,displayName,email,profileStatus&filter=email=='profile@example.test'",case_tenant());
            let directory=ok(&mut admin,&router,Method::GET,&accounts,None).await?;
            ensure!(directory["accounts"].as_array().context("account directory")?.iter().any(|row|row["principalId"]==case::admin() && row["email"]=="profile@example.test" && row["profileStatus"]=="available"));
            let mut old = admin.clone();
            let field = Uuid::new_v4();
            let path = format!("{DEFINITIONS}/{field}");
            let operation = Uuid::new_v4();
            let input = json!({"operationId":operation,"expectedRevision":0,"value":definition()});
            let receipt = ok(&mut admin, &router, Method::PUT, &path, Some(input.clone())).await?;
            ensure!(receipt["definition"]["revision"] == 1);
            ensure!(
                admin
                    .call(
                        &router,
                        Method::PUT,
                        &path,
                        Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1}))
                    )
                    .await?
                    .0
                    == StatusCode::BAD_REQUEST
            );
            ensure!(ok(&mut admin, &router, Method::GET, &path, None).await?["revision"] == 1);

            let initial = ok(&mut admin, &router, Method::GET, ME, None).await?;
            ensure!(
                initial["fields"][0]["status"] == "pending_login"
                    && initial["completeness"]["missing"] == 1
            );
            ensure!(
                ok(&mut admin, &router, Method::PUT, &path, Some(input.clone())).await? == receipt
            );
            ensure!(
                ok(
                    &mut admin,
                    &router,
                    Method::GET,
                    &format!("/api/v1/user-attribute-operations/{operation}"),
                    None
                )
                .await?
                    == receipt
            );
            let mut different = input.clone();
            different["value"]["displayName"] = json!("Different");
            ensure!(
                admin
                    .call(&router, Method::PUT, &path, Some(different))
                    .await?
                    .0
                    == StatusCode::CONFLICT
            );
            admin = Browser::default();
            ensure!(
                admin
                    .login_password(&router, "admin", identity::PASSWORD)
                    .await?
                    == StatusCode::OK
            );
            let fresh = ok(&mut admin, &router, Method::GET, ME, None).await?;
            ensure!(fresh["profiles"][0]["providerConfigVersion"].is_null());
            ensure!(fresh["profiles"][0]["sourceRevision"]==1);
            ensure!(
                fresh["fields"][0]["value"] == "E1001" && fresh["completeness"]["missing"] == 0
            );
            ensure!(
                ok(&mut old, &router, Method::GET, ME, None).await?["fields"][0]["status"]
                    == "unavailable"
            );
            ok(
                &mut admin,
                &router,
                Method::PUT,
                &local,
                Some(local_change(1, Some("E1002"))),
            )
            .await?;
            ensure!(
                ok(&mut admin, &router, Method::GET, ME, None).await?["fields"][0]["value"]
                    == "E1001"
            );
            ensure!(ok(&mut admin,&router,Method::GET,ME,None).await?["profiles"][0]["sourceRevision"]==1);
            admin = Browser::default();
            ensure!(
                admin
                    .login_password(&router, "admin", identity::PASSWORD)
                    .await?
                    == StatusCode::OK
            );
            ensure!(
                ok(&mut admin, &router, Method::GET, ME, None).await?["fields"][0]["value"]
                    == "E1002"
            );
            ensure!(ok(&mut admin,&router,Method::GET,ME,None).await?["profiles"][0]["sourceRevision"]==2);
            let mut changed = definition();
            changed["displayName"] = json!("Employee");
            changed["sensitive"] = json!(true);
            let update = json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"value":changed});
            let saved = ok(&mut admin, &router, Method::PUT, &path, Some(update)).await?;
            ensure!(
                saved["definition"]["collectedAfterMicros"]
                    == receipt["definition"]["collectedAfterMicros"]
            );
            let preview = ok(
                &mut admin,
                &router,
                Method::GET,
                &format!("{ME}?preview=true"),
                None,
            )
            .await?;
            ensure!(
                preview["fields"][0]["status"] == "redacted"
                    && preview["fields"][0]["value"].is_null()
            );
            ensure!(
                preview["profiles"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|v| v["fixed"].is_null())
            );
            let email_id = Uuid::new_v4();
            let mut email = definition();
            email["key"] = json!("privateEmail");
            email["pointer"] = json!("/email");
            email["sensitive"] = json!(true);
            email["useExistingObservation"] = json!(true);
            email["maxLength"] = json!(320);
            ok(
                &mut admin,
                &router,
                Method::PUT,
                &format!("{DEFINITIONS}/{email_id}"),
                Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":email})),
            )
            .await?;
            let masked = ok(
                &mut admin,
                &router,
                Method::GET,
                &format!("{ME}?preview=true"),
                None,
            )
            .await?;
            ensure!(!masked.to_string().contains("profile@example.test"));
            ensure!(
                masked["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|v| v["fieldId"] == email_id.to_string())
                    .unwrap()["status"]
                    == "redacted"
            );
            ok(
                &mut admin,
                &router,
                Method::PUT,
                &format!("{DEFINITIONS}/{email_id}"),
                Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"value":null})),
            )
            .await?;

            let mut value=definition();value["key"]=json!("secondNumber");value["displayName"]=json!("Employee number");
            let second_id=Uuid::new_v4();
            ok(&mut admin,&router,Method::PUT,&format!("{DEFINITIONS}/{second_id}"),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":value}))).await?;
            let query=format!("{DEFINITIONS}?sort=displayName&fields=fieldId&limit=1");
            let first=ok(&mut admin,&router,Method::GET,&query,None).await?;
            ensure!(first["sources"].is_array()&&first["items"].as_array().unwrap().len()==1);
            let cursor=first["nextCursor"].as_str().unwrap();
            let last=ok(&mut admin,&router,Method::GET,&format!("{query}&cursor={cursor}"),None).await?;
            ensure!(last["items"].as_array().unwrap().len()==1&&last["nextCursor"].is_null()&&first["items"][0]!=last["items"][0]);
            ok(&mut admin,&router,Method::PUT,&format!("{DEFINITIONS}/{second_id}"),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"value":null}))).await?;
            let mut other = f.browser("other")?;
            let principal = f
                .identity
                .authority
                .inspect_session(
                    f.identity.tenant,
                    identity::credential(&f.identity, "other")?,
                    crate::identity::deadline(),
                )
                .await?
                .account()
                .principal
                .as_uuid()
                .to_string();
            identity::seed_grants(
                case_tenant(),
                &principal,
                vec![
                    Permission::UserAttributeDefinitionsRead,
                    Permission::UserAttributeDefinitionsWrite,
                ]
                .into_iter()
                .map(|operation| rss_mdm_authorization_service::Grant {
                    operation,
                    scope: rss_mdm_authorization_service::Scope::Tenant,
                })
                .collect(),
            )
            .await?;
            ensure!(
                ok(&mut other, &router, Method::GET, DEFINITIONS, None).await?["items"]
                    .as_array()
                    .unwrap()
                    .len()
                    == 1
            );
            ensure!(
                other
                    .call(
                        &router,
                        Method::GET,
                        &format!("/api/v1/user-profiles/{}", case::admin()),
                        None
                    )
                    .await?
                    .0
                    == StatusCode::FORBIDDEN
            );
            ensure!(
                other
                    .call(&router, Method::GET, &format!("{ME}?preview=true"), None)
                    .await?
                    .0
                    == StatusCode::FORBIDDEN
            );
            ensure!(
                other
                    .call(&router, Method::PUT, &local, Some(local_change(2, None)))
                    .await?
                    .0
                    == StatusCode::FORBIDDEN
            );
            // Even a valid person's bound observation cannot bypass product field visibility.
            let other_local=format!("/api/v1/identity/tenants/{}/accounts/{principal}/profile",case_tenant());
            ok(&mut admin,&router,Method::PUT,&other_local,Some(local_change(0,Some("PRIVATE-OTHER")))).await?;
            other=Browser::default();
            ensure!(other.login_password(&router,"other",identity::PASSWORD).await?==StatusCode::OK);
            let restricted_id=Uuid::new_v4();
            let restricted_path=format!("{DEFINITIONS}/{restricted_id}");
            let mut restricted=definition();
            restricted["key"]=json!("restrictedNumber");
            restricted["visibility"]=json!("profiles_read");
            restricted["useExistingObservation"]=json!(true);
            ok(&mut admin,&router,Method::PUT,&restricted_path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":restricted}))).await?;
            let visible=ok(&mut other,&router,Method::GET,ME,None).await?;
            ensure!(visible["fields"].as_array().unwrap().iter().all(|v|v["fieldId"]!=restricted_id.to_string()));
            let raw=format!("/api/v1/identity/tenants/{}/profile",case_tenant());
            for revision in 1..=3 {
                ensure!(other.call(&router,Method::GET,&raw,None).await?.0==StatusCode::NOT_FOUND);
                ensure!(other.call(&router,Method::GET,&format!("{raw}?source=identity_local"),None).await?.0==StatusCode::NOT_FOUND);
                if revision<3 {
                    restricted["enabled"]=json!(false);
                    let value=if revision==1 {restricted.clone()}else{Value::Null};
                    ok(&mut admin,&router,Method::PUT,&restricted_path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"value":value}))).await?;
                }
            }
            // A mapping source/path/type change defaults to the next locally collected observation.
            changed["pointer"] = json!("/extensions/remote");
            changed["valueType"] = json!("boolean");
            changed["maxLength"] = Value::Null;
            ok(
                &mut admin,
                &router,
                Method::PUT,
                &path,
                Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":2,"value":changed})),
            )
            .await?;
            ensure!(
                ok(&mut admin, &router, Method::GET, ME, None).await?["fields"][0]["status"]
                    == "pending_login"
            );
            changed["useExistingObservation"] = json!(true);
            ok(
                &mut admin,
                &router,
                Method::PUT,
                &path,
                Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":3,"value":changed})),
            )
            .await?;
            ensure!(
                ok(&mut admin, &router, Method::GET, ME, None).await?["fields"][0]["value"]
                    == false
            );
            changed["enabled"] = json!(false);
            ok(
                &mut admin,
                &router,
                Method::PUT,
                &path,
                Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":4,"value":changed})),
            )
            .await?;
            ensure!(
                ok(&mut admin, &router, Method::GET, ME, None).await?["fields"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            ok(
                &mut admin,
                &router,
                Method::PUT,
                &path,
                Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":5,"value":null})),
            )
            .await?;
            ensure!(
                ok(&mut admin, &router, Method::GET, DEFINITIONS, None).await?["items"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            Ok(())
        })
        .await
}

#[tokio::test]
#[ignore = "MODULE=settings.user_profiles: exact unknown-commit receipt and audit rollback"]
async fn definition_receipts_and_audit_are_atomic() -> Result<()> {
    let mut f = authority::Authority::open().await?;
    let resources = std::mem::take(&mut f.resources);
    resources
        .finish(async {
            let session = f
                .identity
                .authority
                .inspect_session(
                    f.identity.tenant,
                    identity::credential(&f.identity, "other")?,
                    crate::identity::deadline(),
                )
                .await?;
            identity::seed_grants(
                case_tenant(),
                &session.account().principal.as_uuid().to_string(),
                vec![
                    Permission::UserAttributeDefinitionsRead,
                    Permission::UserAttributeDefinitionsWrite,
                ]
                .into_iter()
                .map(|operation| rss_mdm_authorization_service::Grant {
                    operation,
                    scope: rss_mdm_authorization_service::Scope::Tenant,
                })
                .collect(),
            )
            .await?;
            let p = AuthorizedPrincipal::new(session)?
                .load_authorization(&f.authorization.clone())
                .await?;
            let id = Uuid::new_v4();
            let input: Change = serde_json::from_value(
                json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":definition()}),
            )?;
            let audit = RequestAudit::new(
                case_tenant().into(),
                "user_attribute_definition_change",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            p.bind_audit(&audit)?;
            audit.operation(
                input.operation_id,
                "user_attribute_definition_change",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            f.audit.inject_next_fault(
                rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
            );
            ensure!(matches!(
                store::change(&f.audit, &p, &audit, id, &input).await,
                Err(Error::CommitUnknown)
            ));
            let receipt = store::one(&f.audit, &p, &audit, input.operation_id, true)
                .await?
                .receipt()?;
            ensure!(receipt.definition.revision == 1);
            ensure!(
                serde_json::to_value(store::change(&f.audit, &p, &audit, id, &input).await?)?
                    == serde_json::to_value(receipt)?
            );
            let mut a = input.clone();
            a.operation_id = Uuid::new_v4();
            a.expected_revision = 1;
            let mut b = a.clone();
            b.operation_id = Uuid::new_v4();
            let first = RequestAudit::new(
                case_tenant().into(),
                "user_attribute_definition_change",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            p.bind_audit(&first)?;
            first.operation(
                a.operation_id,
                "user_attribute_definition_change",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            let second = RequestAudit::new(
                case_tenant().into(),
                "user_attribute_definition_change",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            p.bind_audit(&second)?;
            second.operation(
                b.operation_id,
                "user_attribute_definition_change",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            let (a, b) = tokio::join!(
                store::change(&f.audit, &p, &first, id, &a),
                store::change(&f.audit, &p, &second, id, &b)
            );
            ensure!(a.is_ok() != b.is_ok());
            let failed = Change {
                operation_id: Uuid::new_v4(),
                expected_revision: 2,
                value: None,
            };
            let conflict = RequestAudit::new(
                case_tenant().into(),
                "user_attribute_definition_change",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            p.bind_audit(&conflict)?;
            conflict.operation(
                failed.operation_id,
                "user_attribute_definition_change",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            let fact = rss_mdm_audit_integration::Fact::business(
                &conflict,
                &format!(
                    "user-attribute:{}:{}:{}",
                    p.instance_id(),
                    p.principal_id(),
                    failed.operation_id
                ),
                200,
                "success",
                None,
            )?;
            let budget =
                rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(6));
            let staged = f
                .audit
                .write(
                    f.identity.tenant,
                    &budget.source_control(),
                    (&f.audit, &fact),
                    |(store, fact), tx| Box::pin(async move { store.append(tx, fact).await }),
                )
                .await;
            ensure!(staged.fold(
                |_| true,
                |_| false,
                |_| false,
                |_| false,
                |_| false,
                |_| false
            ));
            ensure!(
                store::change(&f.audit, &p, &conflict, id, &failed)
                    .await
                    .is_err()
            );
            ensure!(
                store::one(&f.audit, &p, &conflict, id, false)
                    .await?
                    .definition()?
                    .revision
                    == 2
            );
            ensure!(matches!(
                store::one(&f.audit, &p, &conflict, failed.operation_id, true).await,
                Err(Error::NotFound)
            ));
            // A current role withdrawal applies even to retained proof and durable receipt reads.
            identity::change_grants(case_tenant(), p.principal_id(), vec![]).await?;
            ensure!(matches!(
                store::one(&f.audit, &p, &audit, input.operation_id, true).await,
                Err(Error::Forbidden)
            ));
            first.finalize(None);
            second.finalize(None);
            conflict.finalize(None);
            audit.finalize(None);
            Ok(())
        })
        .await
}

#[test]
fn mapping_types_and_pointers_reject_coercion_and_invalid_paths() {
    let mut d: DefinitionValue = serde_json::from_value(definition()).unwrap();
    for path in [
        "relative",
        "/extensions/~2bad",
        "/extensions/trailing~",
        "/extensions/\0",
    ] {
        d.pointer = path.into();
        assert!(model::validate(&d).is_err());
    }
    for path in ["", "/extensions/a~1b/~0key", "/extensions/"] {
        d.pointer = path.into();
        assert!(model::validate(&d).is_ok());
    }
    assert!(!model::conforms(&json!(42), &d));
    d.value_type = ValueType::Integer;
    d.max_length = None;
    assert!(model::conforms(&json!(9007199254740991_i64), &d));
    for value in [
        json!(9007199254740992_u64),
        json!(1.5),
        json!("42"),
        json!(true),
    ] {
        assert!(!model::conforms(&value, &d));
    }
    d.value_type = ValueType::Boolean;
    assert!(model::conforms(&json!(false), &d));
    assert!(!model::conforms(&json!(0), &d));
}

#[tokio::test]
#[ignore = "MODULE=settings.user_profiles: active definition capacity and real tenant RLS"]
async fn enabled_capacity_and_cross_tenant_storage_are_enforced() -> Result<()> {
    let mut f = authority::Authority::open().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let seed=definition().to_string().replace('\'',"''");
        process::pg(&format!("INSERT INTO mdm_user_profiles.definitions(tenant_id,field_id,revision,collected_after_micros,value) SELECT '{}'::uuid,gen_random_uuid(),1,0,jsonb_set('{}'::jsonb,'{{key}}',to_jsonb('field'||i::text)) FROM generate_series(1,128) i",case_tenant(),seed))?;
        let session=f.identity.authority.inspect_session(f.identity.tenant,identity::credential(&f.identity,"admin")?,crate::identity::deadline()).await?;
        let p=AuthorizedPrincipal::new(session)?.load_authorization(&f.authorization.clone()).await?;
        let audit=RequestAudit::new(case_tenant().into(),"user_attribute_definition_change", rss_mdm_audit_integration::AuditIntent::Management);p.bind_audit(&audit)?;
        let input:Change=serde_json::from_value(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":definition()}))?;
        audit.operation(input.operation_id,"user_attribute_definition_change", rss_mdm_audit_integration::AuditIntent::Management);
        ensure!(matches!(store::change(&f.audit,&p,&audit,Uuid::new_v4(),&input).await,Err(Error::Conflict)));
        let (existing,_)=store::definitions(&f.audit,&p,&audit,Some(Permission::UserAttributeDefinitionsRead),true,None).await?;
        ensure!(existing.len()==128);
        let mut first=existing[0].value.clone().unwrap();first.enabled=false;
        let stopped=Change{operation_id:Uuid::new_v4(),expected_revision:1,value:Some(first)};
        let stop_audit=RequestAudit::new(case_tenant().into(),"user_attribute_definition_change", rss_mdm_audit_integration::AuditIntent::Management);p.bind_audit(&stop_audit)?;
        stop_audit.operation(stopped.operation_id,"user_attribute_definition_change", rss_mdm_audit_integration::AuditIntent::Management);
        store::change(&f.audit,&p,&stop_audit,existing[0].field_id,&stopped).await?;
        stop_audit.finalize(None);
        let create_audit=RequestAudit::new(case_tenant().into(),"user_attribute_definition_change", rss_mdm_audit_integration::AuditIntent::Management);p.bind_audit(&create_audit)?;
        create_audit.operation(input.operation_id,"user_attribute_definition_change", rss_mdm_audit_integration::AuditIntent::Management);
        store::change(&f.audit,&p,&create_audit,Uuid::new_v4(),&input).await?;
        create_audit.finalize(None);
        use sqlx::Connection;
        let config:Config=serde_json::from_value(f.base.clone())?;
        let mut c=sqlx::PgConnection::connect_with(&config.access_options()?).await?;
        let mut tx=c.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case::peer()).execute(&mut *tx).await?;
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_user_profiles.definitions WHERE tenant_id=$1::uuid").bind(case_tenant()).fetch_one(&mut *tx).await?;
        ensure!(count==0);
        let denied=sqlx::query("INSERT INTO mdm_user_profiles.definitions(tenant_id,field_id,revision,collected_after_micros,value) VALUES($1::uuid,$2,1,0,NULL)").bind(case_tenant()).bind(Uuid::new_v4()).execute(&mut *tx).await;
        ensure!(denied.err().and_then(|e|e.as_database_error().and_then(|e|e.code()).map(|c|c.into_owned()))==Some("42501".into()));
        tx.rollback().await?;c.close().await?;audit.finalize(None);
        Ok(())
    }).await
}
