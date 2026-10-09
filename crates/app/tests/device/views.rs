use super::associations::{member, query, seed, setup};
use super::*;
use rss_mdm_device_service::{Confirm, ViewRef};
use serde_json::json;
#[tokio::test]
#[ignore = "MODULE=device.views: real tenant transaction and authority"]
async fn permission_projection_deduplication_and_cursor_invalidation() -> anyhow::Result<()> {
    let (access, s, admin, mut c) = setup().await?;
    let mdm = crate::test_support::case::name("view-mdm");
    let agent = crate::test_support::case::name("view-agent");
    let other = crate::test_support::case::name("view-other");
    seed(mdm, "mdm", "view-serial")?;
    seed(agent, "agent", "VIEW-SERIAL")?;
    seed(other, "mdm", "different")?;
    s.reconcile().await?;
    let page = s.views(&admin, &query(1)).await?;
    assert_eq!(
        page["statistics"],
        json!({"endpointCount":3,"deviceViewCount":2})
    );
    let reference: ViewRef = serde_json::from_value(page["items"][0]["reference"].clone())?;
    let token = page["nextCursor"]
        .as_str()
        .context("page token")?
        .to_owned();
    let mut next = query(1);
    next.cursor = Some(token.clone());
    let last = s.views(&admin, &next).await?;
    assert_eq!(last["items"].as_array().unwrap().len(), 1);
    let view = s.view(&admin, &reference).await?;
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
        s.views(&admin, &next).await,
        Err(rss_mdm_device_service::Error::CursorInvalidated)
    ));
    crate::test_support::identity::set_grants(
        case_a(),
        admin.principal_id(),
        crate::test_support::identity::device_grants(
            Some(mdm),
            &["inventory_read", "device_association_write"],
        )?,
    )
    .await?;
    let hidden = s.views(&admin, &query(64)).await?;
    assert_eq!(
        hidden["statistics"],
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
    let mut changed = query(64);
    changed.cursor = Some(token);
    assert!(matches!(
        s.views(&admin, &changed).await,
        Err(rss_mdm_device_service::Error::CursorInvalidated)
    ));
    assert!(
        s.changes(&admin, None).await?["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    access.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=device.views: authenticated HTTP preserves Manual and list sources"]
async fn http_lists_manual_conflicts_and_signed_source_pagination() -> anyhow::Result<()> {
    use crate::test_support::{Browser, authority::Authority};
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
            sqlx::query("INSERT INTO mdm.manual_assignments(tenant_id,device,field,revision,fact) VALUES($1::uuid,$2,$3,1,$4)").bind(case_a()).bind(device).bind(field).bind(serde_json::to_value(fact(value))?).execute(&mut c).await?;
        }
    }
    let authority = Authority::open().await?;
    let routes = Router::new().nest(
        "/api/v1",
        rss_mdm_management_http::device_views::routes().with_state(Arc::new(s)),
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
    assert_eq!(first["total"], 3);
    assert_eq!(first["items"].as_array().unwrap().len(), 2);
    let second_path = format!(
        "{path}/inventory-lists/{key}?limit=2&cursor={}",
        first["nextCursor"].as_str().unwrap()
    );
    let (status, second) = browser
        .call(&router, Method::GET, &second_path, None)
        .await?;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(second["items"], json!([{"kind":"integer","value":3}]));
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
}

#[tokio::test]
#[ignore = "MODULE=device.views: pending targets and higher-generation child registrations"]
async fn pending_targets_filter_by_source_and_child_never_replaces_primary() -> anyhow::Result<()> {
    let (access, s, admin, mut c) = setup().await?;
    let device = crate::test_support::case::name("pending-view");
    let registration = DeviceService::new(
        access.registration(),
        case_a().into(),
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    );
    let request = registration
        .fixture_request(&admin, device, Channel::Mdm)
        .await?;
    let mut filter = query(64);
    filter.status = Some("pending".into());
    filter.channel = Some("mdm".into());
    filter.source = Some("mdm.windows".into());
    let page = s.views(&admin, &filter).await?;
    assert_eq!(
        page["statistics"],
        json!({"endpointCount":1,"deviceViewCount":1})
    );
    assert_eq!(page["items"][0]["endpoints"][0]["id"], device);
    filter.channel = Some("agent".into());
    assert_eq!(
        s.views(&admin, &filter).await?["statistics"]["deviceViewCount"],
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
        .view(&admin, &ViewRef::Endpoint(registered.into()))
        .await?;
    assert_eq!(
        detail["endpoints"][0]["primaryMdmRegistration"]["registrationId"],
        parent.to_string()
    );
    assert_eq!(
        detail["endpoints"][0]["channels"][0]["registrationId"],
        parent.to_string()
    );
    access.close().await;
    Ok(())
}
