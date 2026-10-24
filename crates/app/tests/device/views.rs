use super::associations::{member, parameters, query, seed, setup, window};
use super::*;
use rss_mdm_device_service::{Confirm, ViewRef};
use serde_json::json;
#[path = "personnel.rs"]
mod personnel;
use crate::test_support::query_reads::QueryReadCounts;
// Hold the same publication fence as an association writer and observe the real
// reader/mutation waiting there. Its authorization lock must remain available.
pub(super) async fn publication_first<T>(
    c: &mut PgConnection,
    proof: &AuthorizedPrincipal,
    operation: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    let mut hold = c.begin().await?;
    rss_mdm_inventory_postgres::lock_watermark_in(&mut hold, TenantId::parse(proof.tenant_id())?)
        .await?;
    let release = async {
        let observed = tokio::time::timeout(Duration::from_secs(3),async {
            loop {
                let waiting: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pg_backend_pid()=ANY(pg_blocking_pids(pid)) AND query LIKE '%mdm.lock_asset_watermark%')").fetch_one(&mut *hold).await?;
                if waiting { break; }
                sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut *hold).await?;
                tokio::task::yield_now().await;
            }
            let free: bool=sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,2363))")
                .bind(format!("{}:{}",proof.tenant_id(),proof.instance_id())).fetch_one(&mut *hold).await?;
            anyhow::ensure!(free,"device consumer acquired authorization before publication watermark");
            Ok::<_,anyhow::Error>(())
        }).await;
        hold.rollback().await?;
        observed.context("device consumer must actually wait at publication fence")??;
        Ok::<_, anyhow::Error>(())
    };
    let (result, released) = tokio::join!(operation, release);
    released?;
    result
}

#[tokio::test]
#[ignore = "MODULE=device.views: real tenant transaction and authority"]
async fn permission_projection_deduplication_and_cursor_invalidation() -> anyhow::Result<()> {
    let mut authority = crate::test_support::authority::Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources
        .finish(async {
            let (access, s, admin, mut c) = setup().await?;
            let mdm = crate::test_support::case::name("view-mdm");
            let agent = crate::test_support::case::name("view-agent");
            let other = crate::test_support::case::name("view-other");
            seed(mdm, "mdm", "view-serial")?;
            seed(agent, "agent", "VIEW-SERIAL")?;
            seed(other, "mdm", "different")?;
            s.reconcile().await?;
            let page = publication_first(&mut c, &admin, async {
                Ok(s.views(&admin, &query(1), &people(&authority)?).await?)
            })
            .await?;
            assert_eq!(
                s.statistics(&admin, &query(1), &people(&authority)?)
                    .await?["statistics"],
                json!({"endpointCount":3,"deviceViewCount":2})
            );
            let reference: ViewRef = serde_json::from_value(page["items"][0]["reference"].clone())?;
            let token = page["nextCursor"]
                .as_str()
                .context("page token")?
                .to_owned();
            let next = parameters(1, None, Some(&token));
            let last = s.views(&admin, &next, &people(&authority)?).await?;
            assert_eq!(last["items"].as_array().unwrap().len(), 1);
            let view = publication_first(&mut c, &admin, async {
                Ok(s.view(&admin, &reference, &people(&authority)?).await?)
            })
            .await?;
            assert_eq!(
                view["fields"]["device.model"]["sources"]
                    .as_array()
                    .unwrap()
                    .len(),
                2
            );
            let id = match reference {
                ViewRef::Association(id) => id,
                _ => anyhow::bail!("association sorts first"),
            };
            let a = s.get(&admin, id).await?;
            let confirm = Confirm {
                operation_id: Uuid::new_v4(),
                association_id: Some(id),
                expected_version: a.version,
                mdm: member(&mut c, mdm, Channel::Mdm).await?,
                agent: member(&mut c, agent, Channel::Agent).await?,
                evidence: "physical verification".into(),
            };
            s.confirm(
                &admin,
                &confirm,
                &RequestAudit::new(case_a().into(), "device_association_confirm"),
            )
            .await?;
            assert!(matches!(
                s.views(&admin, &next, &people(&authority)?).await,
                Err(rss_mdm_device_service::Error::CursorInvalidated)
            ));
            let fresh = s.views(&admin, &query(1), &people(&authority)?).await?;
            let next = parameters(
                1,
                None,
                Some(fresh["nextCursor"].as_str().context("fresh cursor")?),
            );
            let next_page = s.views(&admin, &next, &people(&authority)?).await?;
            assert_ne!(
                fresh["items"][0]["reference"],
                next_page["items"][0]["reference"]
            );
            crate::test_support::identity::set_grants(
                case_a(),
                admin.principal_id(),
                crate::test_support::identity::device_grants(
                    Some(mdm),
                    &["inventory_read", "device_association_write"],
                )?,
            )
            .await?;
            let hidden = s.views(&admin, &query(64), &people(&authority)?).await?;
            assert_eq!(
                s.statistics(&admin, &query(64), &people(&authority)?)
                    .await?["statistics"],
                json!({"endpointCount":1,"deviceViewCount":1})
            );
            let serialized = serde_json::to_string(&hidden)?;
            assert!(!serialized.contains(agent));
            assert!(!serialized.contains(&id.to_string()));
            assert!(hidden["items"][0]["association"].is_null());
            assert!(matches!(
                s.get(&admin, id).await,
                Err(rss_mdm_device_service::Error::NotFound)
            ));
            assert!(matches!(
                s.confirm(
                    &admin,
                    &confirm,
                    &RequestAudit::new(case_a().into(), "device_association_confirm")
                )
                .await,
                Err(rss_mdm_device_service::Error::Forbidden)
            ));
            assert!(matches!(
                s.views(&admin, &next, &people(&authority)?).await,
                Err(rss_mdm_device_service::Error::CursorInvalidated)
            ));
            assert!(
                s.changes(&admin, &window(None)).await?["items"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            access.close().await;
            Ok(())
        })
        .await
}

#[tokio::test]
#[ignore = "MODULE=device.views: authenticated HTTP preserves Manual and list sources"]
async fn http_lists_manual_conflicts_and_signed_source_pagination() -> anyhow::Result<()> {
    use crate::test_support::{authority::Authority, http::Browser};
    use axum::{
        Router,
        http::{Method, StatusCode},
    };
    use rss_mdm_inventory::{
        Evidence, FieldDefinition, FieldKey, Scalar, Source, SourceFact, State,
    };
    let (access, s, admin, mut c) = setup().await?;
    let mdm = crate::test_support::case::name("http-mdm");
    let agent = crate::test_support::case::name("http-agent");
    seed(mdm, "mdm", "HTTP-SERIAL")?;
    seed(agent, "agent", "http-serial")?;
    s.reconcile().await?;
    let key = "custom.association_list";
    let definition: FieldDefinition = serde_json::from_value(
        json!({"key":key,"version":1,"valueType":{"kind":"array","items":{"kind":"integer"},"maxItems":1000},"nullable":true,"manual":true,"sources":{"manual":0},"platforms":["macos","windows"],"sensitivity":"standard","unit":null,"searchable":true,"itemKey":null}),
    )?;
    assert!(
        rss_mdm_inventory_postgres::publish_field_in(
            &mut c,
            TenantId::parse(case_a())?,
            0,
            &definition
        )
        .await?
    );
    let fact = |value: Scalar| SourceFact {
        state: State::Known(value),
        last_known: None,
        evidence: Evidence {
            scope: rss_mdm_inventory::CollectionScope::Device,
            source: Source::Manual,
            dataset: None,
            registration: None,
            registration_generation: None,
            epoch: None,
            snapshot_id: Uuid::new_v4().to_string(),
            observed_at: 1,
            received_at: 2,
            actor: Some(admin.principal_id().into()),
        },
    };
    for (device, tag, values) in [
        (mdm, "mdm-tag", vec![1, 2, 3]),
        (agent, "agent-tag", vec![9]),
    ] {
        for (field, value) in [
            ("custom.asset_tag", Scalar::String(tag.into())),
            (
                key,
                Scalar::Array(values.into_iter().map(Scalar::Integer).collect()),
            ),
        ] {
            let fact = fact(value);
            sqlx::query("BEGIN").execute(&mut c).await?;
            assert_eq!(
                rss_mdm_inventory_postgres::assign_in(
                    &mut c,
                    TenantId::parse(case_a())?,
                    device,
                    FieldKey::parse(field)?,
                    0,
                    &fact.state,
                    &fact.evidence
                )
                .await?,
                Some(1)
            );
            sqlx::query("COMMIT").execute(&mut c).await?;
        }
    }
    let mut authority = Authority::open().await?;
    let authority_resources = std::mem::take(&mut authority.resources);
    authority_resources.finish(async {
    let routes = Router::new().nest(
        "/api/v1",
        rss_mdm_management_http::device_views::routes(Arc::new(rss_mdm_authorization_service::session::SessionAuthority::new(authority.identity.authority.clone(),authority.identity.tenant)),authority.identity.authority.clone(),None).with_state(Arc::new(s)).into_axum(),
    );
    let router = authority.router(routes)?;
    let mut browser = authority.browser("admin")?;
    let (status, page) = browser
        .call(&router, Method::GET, "/api/v1/device-views", None)
        .await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    let id = page["items"][0]["reference"]["id"]
        .as_str()
        .context("association id")?;
    let path = format!("/api/v1/device-views/association/{id}");
    let (status, detail) = browser.call(&router, Method::GET, &path, None).await?;
    assert_eq!(status, StatusCode::OK, "{detail}");
    assert_eq!(
        detail["fields"]["custom.asset_tag"]["state"]["kind"],
        "conflict"
    );
    assert_eq!(
        detail["fields"]["custom.asset_tag"]["sources"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(detail["lists"][key]["state"]["kind"], "conflict");
    let source = detail["lists"][key]["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["endpoint"] == mdm)
        .unwrap();
    let cursor = source["cursor"].as_str().unwrap();
    let list_path = format!("{path}/inventory-lists/{key}?limit=2&cursor={cursor}");
    let (status, first) = browser.call(&router, Method::GET, &list_path, None).await?;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert!(first.get("endpoints").is_none(), "list pages must not gain detail projection fields");
    assert_eq!(first["total"], 3);
    assert_eq!(first["items"], json!([{"kind":"integer","value":1},{"kind":"integer","value":2}]));
    let second_path = format!(
        "{path}/inventory-lists/{key}?limit=2&cursor={}",
        first["nextCursor"].as_str().unwrap()
    );
    let (status, second) = browser
        .call(&router, Method::GET, &second_path, None)
        .await?;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(second["items"], json!([{"kind":"integer","value":3}]));
    assert!(second["nextCursor"].is_null());
    assert!(second.get("endpoints").is_none());
    let mut anonymous = Browser::default();
    assert_eq!(
        anonymous.call(&router, Method::GET, &path, None).await?.0,
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("UPDATE mdm.manual_assignments SET revision=revision+1,fact=$3 WHERE tenant_id=$1::uuid AND device=$2 AND field='custom.asset_tag'").bind(case_a()).bind(mdm).bind(serde_json::to_value(fact(Scalar::String("updated".into())))?).execute(&mut c).await?;
    let (status, error) = browser
        .call(&router, Method::GET, &second_path, None)
        .await?;
    assert_eq!(status, StatusCode::CONFLICT, "{error}");
    assert!(serde_json::to_string(&error)?.contains("device_view_cursor_invalidated"));
    assert!(FieldKey::parse(key).is_ok());
    access.close().await;
    Ok(())

    }).await
}

#[tokio::test]
#[ignore = "MODULE=device.views: pending targets and higher-generation child registrations"]
async fn pending_targets_filter_by_source_and_child_never_replaces_primary() -> anyhow::Result<()> {
    let mut authority = crate::test_support::authority::Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
    let (access, s, admin, mut c) = setup().await?;
    let device = crate::test_support::case::name("pending-view");
    let registration = DeviceService::new(
        access.registration(),
        case_a().into(),
        access
            .audit_store_fixture(&crate::config::AuditConfig::Plain)
            .await?,
    );
    let request = registration
        .fixture_request(&admin, device, Channel::Mdm)
        .await?;
    let mut filter=parameters(64,Some("status==pending;channel==mdm;source==mdm.windows"),None);
    let page = s.views(&admin, &filter, &people(&authority)?).await?;
    assert_eq!(
        s.statistics(&admin,&filter,&people(&authority)?).await?["statistics"],
        json!({"endpointCount":1,"deviceViewCount":1})
    );
    assert_eq!(page["items"][0]["endpoints"][0]["id"], device);
    filter=parameters(64,Some("status==pending;channel==mdm;source==mdm.apple"),None);
    assert_eq!(
        s.statistics(&admin, &filter, &people(&authority)?).await?["statistics"]["deviceViewCount"],
        0
    );
    let _ = request;
    let registered = crate::test_support::case::name("primary-view");
    let parent = seed(registered, "mdm", "primary-serial")?;
    let child = Uuid::new_v4();
    let child_request = Uuid::new_v4();
    let child_grant = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,created_at,expires_at) SELECT g.tenant_id,$3,g.actor,g.instance,g.device,g.purpose,g.state,g.created_at,g.expires_at FROM mdm_access.grants g JOIN mdm_access.requests q ON (q.tenant_id,q.grant_id)=(g.tenant_id,g.id) JOIN mdm_access.registrations r ON (r.tenant_id,r.request_id)=(q.tenant_id,q.id) WHERE r.tenant_id=$1::uuid AND r.id=$2").bind(case_a()).bind(parent).bind(child_grant).execute(&mut c).await?;
    sqlx::query("INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source,windows_profile) SELECT tenant_id,$3,$4,source,windows_profile FROM mdm_access.requests WHERE tenant_id=$1::uuid AND id=(SELECT request_id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2)").bind(case_a()).bind(parent).bind(child_request).bind(child_grant).execute(&mut c).await?;
    sqlx::query("INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,request_id,state,purpose,epoch,parent_id,parent_generation) SELECT tenant_id,$3,device,channel,99,$4,'active','windows_declared',$5,id,generation FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2").bind(case_a()).bind(parent).bind(child).bind(child_request).bind(Uuid::new_v4()).execute(&mut c).await?;
    assert_eq!(
        member(&mut c, registered, Channel::Mdm)
            .await?
            .registration_id,
        parent
    );
    let detail = s
        .view(&admin, &ViewRef::Endpoint(registered.into()), &people(&authority)?)
        .await?;
    assert_eq!(
        detail["endpoints"][0]["primaryMdmRegistration"]["registrationId"],
        parent.to_string()
    );
    assert_eq!(
        detail["endpoints"][0]["channels"][0]["registrationId"],
        parent.to_string()
    );
    assert!(detail["endpoints"][0]["channels"][0]["lastCommunicationReceivedAt"].is_null());
    let locator = [31_u8; 32];
    sqlx::query("INSERT INTO mdm_access.credentials(tenant_id,id,registration,channel,locator,state) VALUES($1::uuid,$2,$3,'mdm',$4,'active')")
        .bind(case_a()).bind(Uuid::new_v4()).bind(child).bind("1f".repeat(32)).execute(&mut c).await?;
    let channel_credential = rss_mdm_registration_service::ChannelMount::new(TenantId::parse(case_a())?, rss_mdm_inventory::ReportSource::MdmWindows, rss_mdm_registration_service::Purpose::WindowsDeclared).credential(locator)?;
    let principal = registration.management_principal(&channel_credential).await?;
    let mut tx = c.begin().await?;
    rss_mdm_registration_service::device::store::record_communication_in(&mut tx, &principal).await?;
    tx.commit().await?;
    let contacted = s.view(&admin, &ViewRef::Endpoint(registered.into()), &people(&authority)?).await?;
    assert!(contacted["endpoints"][0]["channels"][0]["lastCommunicationReceivedAt"].as_i64().is_some_and(|v| v > 0));
    let child_has_contact: bool = sqlx::query_scalar("SELECT last_communication_received_at IS NOT NULL FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_a()).bind(child).fetch_one(&mut c).await?;
    assert!(!child_has_contact, "child communication belongs to its primary registration");
    let child_state = &detail["endpoints"][0]["channels"][0]["children"][0];
    assert_eq!(child_state["registrationId"], child.to_string());
    assert_eq!(child_state["generation"], 99);
    assert_eq!(child_state["parentRegistrationId"], parent.to_string());
    assert_eq!(child_state["parentGeneration"], 1);
    assert_eq!(child_state["status"], "active");
    assert!(detail["endpoints"][0]["channels"][0]["userContext"].is_null());
    sqlx::query(
        "UPDATE mdm_access.registrations SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_a())
    .bind(child)
    .execute(&mut c)
    .await?;
    sqlx::query("UPDATE mdm_access.requests SET windows_profile='Full' WHERE tenant_id=$1::uuid AND id=(SELECT request_id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2)").bind(case_a()).bind(parent).execute(&mut c).await?;
    let updated = s
        .view(&admin, &ViewRef::Endpoint(registered.into()), &people(&authority)?)
        .await?;
    let channel = &updated["endpoints"][0]["channels"][0];
    assert_eq!(channel["registrationId"], parent.to_string());
    assert_eq!(channel["status"], "active");
    assert_eq!(channel["children"][0]["status"], "revoked");
    assert_eq!(channel["userContext"]["id"], parent.to_string());
    assert_eq!(channel["userContext"]["parentGeneration"], 1);
    assert_eq!(channel["userContext"]["registrationStatus"], "active");
    // The original endpoint directory consumes the same projection.
    let endpoint = registration.directory_device(&admin, registered).await?;
    assert_eq!(endpoint["channels"], updated["endpoints"][0]["channels"]);
    access.close().await;
    Ok(())

    }).await
}

#[tokio::test]
#[ignore = "MODULE=device.views: authorized full-set search, batched projection and visibility-bound cursors"]
async fn directory_search_authorization_and_generation_invalidation() -> anyhow::Result<()> {
    let mut authority = crate::test_support::authority::Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
        let (access,s,admin,mut c)=setup().await?;
        let needle=crate::test_support::case::name("zzz-directory-needle");
        let peer=crate::test_support::case::name("zzz-directory-peer");
        let hidden=crate::test_support::case::name("zzz-directory-hidden");
        let first=seed(needle,"mdm","Search-Needle-Serial")?;
        let name_key=rss_mdm_inventory::FieldKey::parse("device.name")?;
        let definition=crate::test_support::inventory::definition("directory_name","mdm.windows",&[name_key]);
        crate::test_support::inventory::register_definition(&definition)?;
        let source_epoch:Uuid=sqlx::query_scalar("SELECT epoch FROM mdm_access.report_sources WHERE tenant_id=$1::uuid AND registration=$2 AND source='mdm.windows'").bind(case_a()).bind(first).fetch_one(&mut c).await?;
        let name_scope=rss_mdm_registration_service::device::scope_dataset(TenantId::parse(case_a())?,first,"mdm.windows",source_epoch,"directory_name")?.encode()?;
        sqlx::query("INSERT INTO mdm.inventory(field_scope,tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,last_known,last_known_batch,last_known_observed,last_known_received,registration,source,epoch,collection_sequence) SELECT field_scope,tenant_id,journal,generation,$3,$4,'device.name',$5,'name-fixture',observed_at,received_at,state,$5,'name-fixture',last_known_observed,last_known_received,registration,source,epoch,collection_sequence FROM mdm.inventory WHERE tenant_id=$1::uuid AND registration=$2 AND field='device.serial_number'").bind(case_a()).bind(first.to_string()).bind(name_scope).bind(serde_json::to_string(&definition.coverage()?)?).bind(serde_json::to_string(&json!({"kind":"string","value":"Directory Workstation"}))?).execute(&mut c).await?;

        let second=seed(peer,"mdm","Peer-Serial")?;
        let secret=seed(hidden,"mdm","Hidden-Serial")?;
        let prefix=crate::test_support::case::name("aaa-directory-filler");
        sqlx::query("INSERT INTO mdm_access.devices(tenant_id,id) SELECT $1::uuid,$2||'-'||lpad(n::text,4,'0') FROM generate_series(1,1000) n").bind(case_a()).bind(prefix).execute(&mut c).await?;
        let registration=DeviceService::new(access.registration(),case_a().into(),authority.audit.clone());
        let owned=registration.assign_registration_user(&admin,needle,&rss_mdm_registration_service::device::registration_user::RegistrationUserChange{expected_revision:0,user:Some(admin.user()?)},Uuid::new_v4(),&RequestAudit::new(case_a().into(),"registration_user_change")).await?;
        let mut filter=parameters(1,Some("search=icontains=search-NEEDLE;platform==windows"),None);
        use tracing::instrument::WithSubscriber;
        use tracing_subscriber::layer::SubscriberExt;
        use std::sync::atomic::Ordering::Relaxed;
        let counts=QueryReadCounts::new("device.identity");
        let observer=tracing_subscriber::registry().with(counts.clone());
        let found=s.views(&admin,&filter,&people(&authority)?).with_subscriber(observer).await?;
        assert_eq!(counts.calls.load(Relaxed),1,"one batch hydrates the selected endpoint");
        assert_eq!(counts.rows.load(Relaxed),1,"off-page filler endpoints were decoded");
        let bytes=counts.bytes.load(Relaxed);assert!(bytes>0&&bytes<65536,"real cell payload budget: {bytes}");
        let identity_query=rss_mdm_registration_service::device::directory::SCHEMA.parse(&format!("limit=1&filter=id=={needle}"))?;
        let plan=registration.directory_plan(&admin,&identity_query).await?;
        println!("QUERY-05 identity rows={} payload_bytes={} plan={}",counts.rows.load(Relaxed),bytes,plan);
        assert!(plan[0]["Plan"]["Actual Rows"].as_u64().is_some_and(|n|n<=2));
        // Explain the production device candidate relation and page selection.
        // Identity boundaries are covered above; this plan isolates product SQL
        // with no upstream personnel/session rows.
        let plan_sql=concat!("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) WITH platform_configuration AS (SELECT $7::jsonb AS config), platform_sessions AS (SELECT NULL::uuid AS instance_id,NULL::uuid AS tenant_id,NULL::uuid AS principal_id,NULL::uuid AS session_id,NULL::text AS credential_kind,NULL::bigint AS platform_valid_until WHERE false), people AS (SELECT NULL::uuid AS principal_id,false AS active,NULL::text AS login,NULL::text AS status,NULL::text AS display_name WHERE false),",
            include_str!("../../../device-service/src/directory_relation.sql"),
            include_str!("../../../device-service/src/directory.sql"));
        sqlx::query("SELECT set_config('rss.tenant_id',$1,false)").bind(case_a()).execute(&mut c).await?;
        let predicate=r#"($.search[*] like_regex "search-NEEDLE" flag "i") && ($.platform[*] == "windows")"#;
        let plan:serde_json::Value=sqlx::query_scalar(plan_sql).bind(case_a()).bind(None::<Vec<String>>).bind(None::<Vec<String>>).bind(None::<Vec<String>>).bind(predicate).bind(admin.instance_id()).bind(json!(null)).bind(true).bind(4096_i64).bind(None::<String>).bind(false).bind(2_i64).fetch_one(&mut c).await?;

        fn work(node:&serde_json::Value)->u64 {
            node["Actual Rows"].as_u64().unwrap_or(0)*node["Actual Loops"].as_u64().unwrap_or(0)
                +node["Plans"].as_array().map_or(0,|p|p.iter().map(work).sum::<u64>())
        }
        let processed=work(&plan[0]["Plan"]);
        let buffers=plan[0]["Plan"]["Shared Hit Blocks"].as_u64().unwrap_or(0)+plan[0]["Plan"]["Shared Read Blocks"].as_u64().unwrap_or(0);
        println!("QUERY-05 device candidates processed={processed} buffers={buffers} plan={plan}");
        assert!(processed<500000 && buffers<250000,"candidate processing grew beyond the fixture work budget");
        // The same source guard at a reduced test threshold must stop its raw
        // append before the metadata UNION and per-candidate searches run.
        let over:serde_json::Value=sqlx::query_scalar(plan_sql).bind(case_a()).bind(None::<Vec<String>>).bind(None::<Vec<String>>).bind(None::<Vec<String>>).bind(predicate).bind(admin.instance_id()).bind(json!(null)).bind(true).bind(1_i64).bind(None::<String>).bind(false).bind(2_i64).fetch_one(&mut c).await?;
        println!("QUERY-05 source overflow plan={over}");
        assert!(work(&over[0]["Plan"])<5000,"raw overflow performed expensive candidate work");
        fn scanned(node:&serde_json::Value,table:&str)->u64 {
            let own=if node["Relation Name"]==table {node["Actual Rows"].as_u64().unwrap_or(0)*node["Actual Loops"].as_u64().unwrap_or(0)}else{0};
            own+node["Plans"].as_array().map_or(0,|p|p.iter().map(|n|scanned(n,table)).sum::<u64>())
        }
        assert!(scanned(&over[0]["Plan"],"devices")<=257,"source guard scanned the complete device relation");

        assert_eq!(s.statistics(&admin,&filter,&people(&authority)?).await?["statistics"],json!({"endpointCount":1,"deviceViewCount":1}));
        assert_eq!(found["items"][0]["endpoints"][0]["id"],needle);
        assert_eq!(found["items"][0]["endpoints"][0]["registrationUser"]["user"]["principalId"],admin.principal_id());
        assert!(found["nextCursor"].is_null());
        assert_eq!(found["items"][0]["endpoints"][0]["displayName"]["state"]["value"]["value"],"Directory Workstation");
        filter=parameters(1,Some("search=icontains='workSTATION';platform==windows"),None);
        assert_eq!(s.statistics(&admin,&filter,&people(&authority)?).await?["statistics"]["deviceViewCount"],1);

        let detail=s.view(&admin,&ViewRef::Endpoint(needle.into()),&people(&authority)?).await?;
        assert_eq!(detail["endpoints"],found["items"][0]["endpoints"]);
        // The existing field owner allows unused, unprotected names to gain a manual source.
        use rss_mdm_inventory_service::assets;
        use rss_mdm_inventory_service::operation::Operation;
        let planning = crate::planning::test_support::planning(TenantId::parse(case_a())?).await;
        let assets = crate::planning::test_support::assets(&planning).await;
        async fn write(service: &assets::AssetService, principal: &AuthorizedPrincipal, command: &assets::Command) -> anyhow::Result<serde_json::Value> {
            let audit = RequestAudit::new(case_a().into(), "management_write");
            audit.set_principal(principal.principal_id(), crate::test_support::INSTANCE);
            let result = service.execute(command, &audit, &|| Ok(())).await;
            audit.finalize(None);
            Ok(result?)
        }
        let catalog = rss_mdm_inventory_postgres::catalog_in(&mut c, TenantId::parse(case_a())?).await?;
        let mut definition = catalog.definition(name_key)?.clone();
        let revision = definition.version;
        definition.version += 1;
        definition.manual = true;
        for priority in definition.sources.values_mut() { *priority += 1; }
        definition.sources.insert(rss_mdm_inventory::Source::Manual, 0);
        write(&assets, &admin, &assets::Command::FieldWrite { field: name_key, change: Operation {
            operation_id: Uuid::new_v4(), expected_revision: revision,
            input: assets::FieldChange::Put { definition: Box::new(definition) },
        }}).await?;
        let manual = |revision, input| assets::Command::Manual {
            device: needle.into(), field: name_key,
            change: Operation { operation_id: Uuid::new_v4(), expected_revision: revision, input },
            owner: assets::Owner { instance: crate::test_support::INSTANCE.into(), principal: admin.principal_id().into() },
        };
        write(&assets, &admin, &manual(0, assets::ManualChange::Set { value: assets::Scalar::String("Assigned Notebook".into()) })).await?;
        filter=parameters(1,Some("search=icontains='assigned noteBOOK';platform==windows"),None);
        let assigned=s.views(&admin,&filter,&people(&authority)?).await?;
        assert_eq!(s.statistics(&admin,&filter,&people(&authority)?).await?["statistics"]["deviceViewCount"],1);
        assert_eq!(assigned["items"][0]["endpoints"][0]["displayName"]["state"]["value"]["value"],"Assigned Notebook");
        filter=parameters(1,Some("search=icontains='workstation';platform==windows"),None);
        assert_eq!(s.statistics(&admin,&filter,&people(&authority)?).await?["statistics"]["deviceViewCount"],0);
        write(&assets, &admin, &manual(1, assets::ManualChange::Delete {})).await?;
        assert_eq!(s.statistics(&admin,&filter,&people(&authority)?).await?["statistics"]["deviceViewCount"],1);
        planning.runtime.close().await;
        filter=parameters(1,Some("search=icontains=workstation;platform==macos"),None);
        assert_eq!(s.statistics(&admin,&filter,&people(&authority)?).await?["statistics"]["deviceViewCount"],0);
        filter=parameters(1,Some(&format!("search=icontains={}",admin.principal_id())),None);
        assert_eq!(s.statistics(&admin,&filter,&people(&authority)?).await?["statistics"]["deviceViewCount"],1);
        let mut grants=crate::test_support::identity::device_grants(Some(needle),&["inventory_read"])?;
        grants.extend(crate::test_support::identity::device_grants(Some(peer),&["inventory_read"])?);
        crate::test_support::identity::set_grants(case_a(),admin.principal_id(),grants).await?;
        assert_eq!(s.statistics(&admin,&filter,&people(&authority)?).await?["statistics"]["deviceViewCount"],0,"unreadable ownership participated in search");
        let first_page=s.views(&admin,&query(1),&people(&authority)?).await?;
        assert_eq!(s.statistics(&admin,&query(1),&people(&authority)?).await?["statistics"],json!({"endpointCount":2,"deviceViewCount":2}));
        let token=first_page["nextCursor"].as_str().context("two visible endpoints")?;
        use base64::Engine;
        let payload=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token)?;
        let text=String::from_utf8_lossy(&payload[..payload.len()-32]);
        assert!(!text.contains(hidden)&&!text.contains(admin.principal_id()));
        let mut next =parameters(1,None,Some(token));
        sqlx::query("UPDATE mdm.inventory SET value=$3,last_known=$3 WHERE tenant_id=$1::uuid AND registration=$2 AND field='device.serial_number'").bind(case_a()).bind(secret.to_string()).bind(serde_json::to_string(&json!({"kind":"string","value":"hidden-changed"}))?).execute(&mut c).await?;
        assert!(matches!(s.views(&admin,&next,&people(&authority)?).await,Err(rss_mdm_device_service::Error::CursorInvalidated)));
        let refreshed=s.views(&admin,&query(1),&people(&authority)?).await?;
        next=parameters(1,None,Some(refreshed["nextCursor"].as_str().context("refreshed cursor")?));
        let tail=s.views(&admin,&next,&people(&authority)?).await?;
        assert_eq!(tail["items"].as_array().unwrap().len(),1);assert!(tail["nextCursor"].is_null());
        // Even a real manual assignment is unobservable without its read permission.
        registration.assign_registration_user(&admin,needle,&rss_mdm_registration_service::device::registration_user::RegistrationUserChange{expected_revision:owned.revision,user:None},Uuid::new_v4(),&RequestAudit::new(case_a().into(),"registration_user_change")).await.err().context("stale authority must not write after grant removal")?;
        sqlx::query("UPDATE mdm_access.registration_users SET revision=revision+1,instance=NULL,principal=NULL WHERE tenant_id=$1::uuid AND device=$2").bind(case_a()).bind(needle).execute(&mut c).await?;
        assert!(matches!(s.views(&admin,&next,&people(&authority)?).await,Err(rss_mdm_device_service::Error::CursorInvalidated)));
        let refreshed=s.views(&admin,&query(1),&people(&authority)?).await?;
        next=parameters(1,None,Some(refreshed["nextCursor"].as_str().context("refreshed cursor")?));
        sqlx::query("UPDATE mdm.inventory SET value=$3,last_known=$3 WHERE tenant_id=$1::uuid AND registration=$2 AND field='device.serial_number'").bind(case_a()).bind(second.to_string()).bind(serde_json::to_string(&json!({"kind":"string","value":"visible-changed"}))?).execute(&mut c).await?;
        assert!(matches!(s.views(&admin,&next,&people(&authority)?).await,Err(rss_mdm_device_service::Error::CursorInvalidated)));
        let malformed=parameters(1,Some("search=icontains=' '"),None);
        assert!(matches!(s.views(&admin,&malformed,&people(&authority)?).await,Err(rss_mdm_device_service::Error::Malformed)));
        crate::test_support::identity::set_grants(case_a(),admin.principal_id(),crate::test_support::identity::device_grants(None,&["inventory_read"])?).await?;
        sqlx::query("INSERT INTO mdm_access.devices(tenant_id,id) SELECT $1::uuid,$2||'-budget-'||n FROM generate_series(1,4096) n").bind(case_a()).bind(prefix).execute(&mut c).await?;
        assert!(matches!(s.views(&admin,&query(1),&people(&authority)?).await,Err(rss_mdm_device_service::Error::Capacity)),"candidate overflow returned a truncated page");
        let _=first;
        access.close().await;Ok(())
    }).await
}

pub(super) fn people<'a>(
    authority: &'a crate::test_support::authority::Authority,
) -> anyhow::Result<rss_mdm_device_service::personnel::Reader<'a>> {
    Ok(rss_mdm_device_service::personnel::Reader::new(
        &authority.identity.authority,
        rss_request_context::Clock::now(&rss_mdm_audit_integration::budget::RuntimeTimer)
            + std::time::Duration::from_secs(15),
        &rss_mdm_audit_integration::budget::RuntimeTimer,
        None,
    ))
}
