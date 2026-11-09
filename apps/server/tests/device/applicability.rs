//! Real device-detail consumption and control admission; reads never manufacture commands.
use super::*;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_device_service::control::{
    Error as ControlError,
    device_control::{Action, Input},
};
use rss_mdm_management_http::enrollment::directory;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;

struct Http {
    state: Arc<directory::HttpState>,
}
impl Http {
    fn open(a: &Fixture) -> Result<Self> {
        let reads = Arc::new(crate::assembly::device_reads::Devices {
            tasks: a.task_reads.clone(),
            devices: a.devices.clone(),
            windows: true,
            apple: true,
        });
        Ok(Self {
            state: Arc::new(directory::HttpState {
                cursor: rss_mdm_query::cursor::CursorCodec::new(&[7; 32])?,
                devices: a.devices.clone(),
                reads,
            }),
        })
    }
    async fn get(
        &self,
        c: &Context,
        proof: Arc<AuthorizedPrincipal>,
        device: &str,
    ) -> Result<(u16, Value)> {
        let router = directory::routes()
            .with_state::<()>(self.state.clone())
            .layer(axum::Extension(c.request(&proof)?))
            .layer(axum::Extension(c.read_auth(proof)))
            .into_axum();
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            router.oneshot(
                axum::http::Request::builder()
                    .uri(format!("/devices/{device}"))
                    .body(axum::body::Body::empty())?,
            ),
        )
        .await??;
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 262144).await?;
        Ok((status, serde_json::from_slice(&bytes)?))
    }
}
async fn open() -> Result<(Context, Fixture, Http)> {
    let c = Context::open("shared", &[]).await?;
    let a = match Fixture::open(&c, false).await {
        Ok(a) => a,
        Err(e) => {
            c.close().await;
            return Err(e);
        }
    };
    match Http::open(&a) {
        Ok(http) => Ok((c, a, http)),
        Err(e) => {
            let closed = Fixture::close(a).await;
            c.close().await;
            closed?;
            Err(e)
        }
    }
}
fn capability<'a>(body: &'a Value, action: &str) -> &'a Value {
    body["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["action"] == action && v["channel"] == "mdm")
        .unwrap()
}
fn wipe() -> Input {
    Input {
        operation_id: Uuid::new_v4(),
        deadline: time::OffsetDateTime::now_utc().unix_timestamp() + 300,
        action: Action::Wipe { confirmed: true },
    }
}
async fn windows(c: &Context, n: &native::Native, version: &str) -> Result<()> {
    let mut tx = command::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_windows.capabilities (tenant_id, device, protocol_epoch, os_version, edition, session, observed_at) VALUES (CAST($1 AS uuid), $2, $4, $3, 4, 1, CAST(EXTRACT(EPOCH FROM clock_timestamp()) AS bigint)) ON CONFLICT (tenant_id, device, protocol_epoch) DO UPDATE SET os_version = excluded.os_version")
        .bind(c.tenant.to_string()).bind(n.device.clone()).bind(version).bind(n.epoch).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
async fn change(c: &Context, query: &'static str, id: String) -> Result<(), sqlx::Error> {
    let mut tx = c.operator.begin().await?;
    sqlx::query(
        "SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','6000',true)",
    )
    .bind(c.tenant.to_string())
    .execute(&mut *tx)
    .await?;
    sqlx::query(query)
        .bind(c.tenant.to_string())
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}
async fn effects(c: &Context) -> Result<Vec<i64>> {
    // Count exactly this tenant's durable business effects, including PIN custody and probes.
    let mut counts = Vec::new();
    for query in [
        "SELECT count(*) FROM mdm_devices.control_operations WHERE tenant_id=$1::uuid",
        "SELECT count(*) FROM mdm_devices.control_requests WHERE tenant_id=$1::uuid",
        "SELECT count(*) FROM rss_device_command.commands WHERE tenant_id=$1::uuid",
        "SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid",
        "SELECT count(*) FROM mdm_recovery.native_actions WHERE tenant_id=$1::uuid",
        "SELECT count(*) FROM mdm_apple.attempts WHERE tenant_id=$1::uuid",
    ] {
        counts.push(
            sqlx::query_scalar::<_, i64>(query)
                .bind(c.tenant.to_string())
                .fetch_one(&c.operator)
                .await?,
        );
    }
    Ok(counts)
}
async fn read(
    c: &Context,
    http: &Http,
    p: &Arc<AuthorizedPrincipal>,
    n: &native::Native,
) -> Result<Value> {
    let (status, body) = http.get(c, p.clone(), &n.device).await?;
    assert_eq!(status, 200, "{body}");
    Ok(body)
}

#[tokio::test]
#[ignore = "T2 #3136: production device-detail HTTP reads truthful capabilities and separated permissions without effects"]
async fn detail_capabilities_are_authorized_read_only_facts() -> Result<()> {
    let (c, a, http) = open().await?;
    let result = async {
        let n = native::seed(&c, "windows").await?;
        let account = c.account(&[Permission::InventoryRead, Permission::DeviceControl]).await?;
        let p = Arc::new(c.authenticate(&account).await?);
        let before = effects(&c).await?;
        let missing = read(&c, &http, &p, &n).await?;
        assert_eq!(capability(&missing,"restart")["devicePrerequisite"], json!({"state":"unknown","reason":"capability_unknown"}));
        assert_eq!(capability(&missing,"lock")["devicePrerequisite"]["state"], "unsupported");
        windows(&c, &n, "10.0.22631.0").await?;
        let body = read(&c, &http, &p, &n).await?;
        assert_eq!(body["id"], n.device.clone().to_string());
        for action in ["restart","wipe"] { assert_eq!(capability(&body,action)["devicePrerequisite"]["state"], "supported"); }
        assert_eq!(capability(&body,"restart")["permission"]["allowed"], true);
        assert_eq!(capability(&body,"wipe")["permission"], json!({"allowed":false,"reason":"permission_denied"}));
        let document = crate::http_contract_document().map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let endpoint = document["endpoints"].as_array().unwrap().iter().find(|e| e["method"]=="GET" && e["path"]=="/api/v1/devices/{device}").unwrap();
        let response = endpoint["responses"].as_array().unwrap().iter().find(|r|r["status"]==200).unwrap();
        let schema = response["body"]["schema"]["schemaId"].as_str().unwrap();
        jsonschema::validator_for(&document["schemas"][schema])?.validate(&body).map_err(|e|anyhow::anyhow!(e.to_string()))?;
        assert_eq!(read(&c,&http,&p,&n).await?, body);
        assert_eq!(effects(&c).await?, before);
        assert!(!serde_json::to_string(&body)?.contains("PIN"));
        let denied = c.account(&[Permission::DeviceControl]).await?;
        assert_eq!(http.get(&c,Arc::new(c.authenticate(&denied).await?),&n.device).await?.0,403);
        let other = native::seed(&c,"windows").await?;
        sqlx::query("UPDATE mdm_access.authorization_rules SET revision=revision+1,document=jsonb_set(document,'{grants}', $3) WHERE tenant_id=$1::uuid AND id=$2")
            .bind(c.tenant.to_string()).bind(account.rule).bind(json!([{"operation":"inventory_read","scope":{"kind":"device","id":other.device}}])).execute(&c.operator).await?;
        // Scope change is reflected by the real current authorization snapshot.
        assert_eq!(http.get(&c,p,&n.device).await?.0,403);
        Ok(())
    }.await;
    drop(http);
    let drained = Fixture::close(a).await;
    c.close().await;
    drained?;
    result
}

#[tokio::test]
#[ignore = "T2 #3136: supported reads do not authorize stale, revoked or unsupported writes"]
async fn supported_snapshot_never_authorizes_a_later_write() -> Result<()> {
    let (c, a, http) = open().await?;
    let result = async {
        let n = native::seed(&c,"windows").await?;
        windows(&c,&n,"10.0.22631.0").await?;
        let account = c.account(&[Permission::InventoryRead,Permission::DeviceWipe]).await?;
        let p = Arc::new(c.authenticate(&account).await?);
        assert_eq!(capability(&read(&c,&http,&p,&n).await?,"wipe")["devicePrerequisite"]["state"],"supported");
        let before = effects(&c).await?;
        let mut input = wipe();
        input.action = Action::Wipe { confirmed:false, };
        assert!(matches!(a.service.create_control(&p,&n.device,&input,&c.request(&p)?).await,Err(ControlError::Malformed)));
        let input = wipe();
        change(&c, "DELETE FROM mdm_windows.capabilities WHERE tenant_id = CAST($1 AS uuid) AND device = $2", n.device.clone()).await?;
        assert!(matches!(a.service.create_control(&p,&n.device,&input,&c.request(&p)?).await,Err(ControlError::Unsupported)));
        windows(&c,&n,"10.0.22631.0").await?;
        let input = wipe();
        change(&c, "UPDATE mdm_access.devices SET state = 'revoked' WHERE tenant_id = CAST($1 AS uuid) AND id = $2", n.device.clone()).await?;
        assert!(matches!(a.service.create_control(&p,&n.device,&input,&c.request(&p)?).await,Err(ControlError::Conflict)));
        change(&c, "UPDATE mdm_access.devices SET state = 'active' WHERE tenant_id = CAST($1 AS uuid) AND id = $2", n.device.clone()).await?;
        let input = wipe();
        change(&c, "DELETE FROM mdm_access.authorization_rules WHERE tenant_id=$1::uuid AND id=$2::uuid", account.rule.to_string()).await?;
        assert!(matches!(a.service.create_control(&p,&n.device,&input,&c.request(&p)?).await,Err(ControlError::Forbidden)));
        assert_eq!(effects(&c).await?,before);
        Ok(())
    }.await;
    drop(http);
    let drained = Fixture::close(a).await;
    c.close().await;
    drained?;
    result
}

async fn apple_facts(
    c: &Context,
    a: &Fixture,
    n: &native::Native,
    proof: &AuthorizedPrincipal,
    silicon: Option<bool>,
    version: Option<&str>,
) -> Result<()> {
    use rss_mdm_device_service::control::{
        Create, NativeTarget, authority::Authority, device_control::Kind,
    };
    use rss_mdm_native_protection::ProtectionContext;
    use sha2::{Digest, Sha256};
    let operation = Uuid::new_v4();
    let input = Create {
        operation_id: operation,
        deadline: time::OffsetDateTime::now_utc().unix_timestamp() + 300,
        input_version: "device-control-v1".into(),
        target: NativeTarget::Device,
        task: Kind::Restart.native_shape(rss_mdm_inventory::ReportSource::MdmApple)?,
    };
    let authority = Authority::DeviceControl {
        action: Kind::Restart,
        confirmation: false,
        required: vec![Permission::DeviceControl],
        actor: proof.actor(),
    };
    crate::apple_t2::support::operation(c, n, &a.resources.protection, &input, authority, None)
        .await?;
    let mut tx = command::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_apple.devices (tenant_id, device, udid, state, access_rights) VALUES (CAST($1 AS uuid), $2, $3, 'active', 8191) ON CONFLICT (tenant_id, device) DO NOTHING").bind(c.tenant.to_string()).bind(n.device.clone()).bind(&n.device).execute(&mut *tx).await?;
    // This fixture starts at the accepted, authenticated evidence boundary being read.
    sqlx::query(
        "DELETE FROM mdm_apple.attempts WHERE tenant_id = CAST($1 AS uuid) AND device = $2",
    )
    .bind(c.tenant.to_string())
    .bind(n.device.clone())
    .execute(&mut *tx)
    .await?;
    let mut facts = plist::Dictionary::new();
    if let Some(v) = version {
        facts.insert("OSVersion".into(), plist::Value::String(v.into()));
    }
    if let Some(v) = silicon {
        facts.insert("IsAppleSilicon".into(), plist::Value::Boolean(v));
    }
    for (phase, key, facts) in [
        ("resolve_device", "QueryResponses", facts),
        ("resolve_security", "SecurityInfo", plist::Dictionary::new()),
    ] {
        let id = Uuid::new_v4();
        let body = plist::Value::Dictionary(plist::Dictionary::from_iter([(
            key.to_owned(),
            plist::Value::Dictionary(facts),
        )]));
        let mut bytes = Vec::new();
        body.to_writer_xml(&mut bytes)?;
        let owner = serde_json::to_string(&(n.device.clone(), id))?;
        let response = a.resources.protection.seal_bytes(
            &bytes,
            &ProtectionContext::new(c.tenant, &owner, "apple.attempt.response", 1)?.derive(),
        )?;
        let request = a.resources.protection.seal_bytes(
            &bytes,
            &ProtectionContext::new(c.tenant, &owner, "apple.attempt.request", 1)?.derive(),
        )?;
        sqlx::query("INSERT INTO mdm_apple.attempts (tenant_id, id, device, operation, phase, request, state, response, response_digest, received_at, accepted, deadline) VALUES (CAST($1 AS uuid), $2, $3, $4, $5, $6, 'acknowledged', $7, $8, CAST(EXTRACT(EPOCH FROM clock_timestamp()) AS bigint), TRUE, clock_timestamp() + CAST('5 minutes' AS interval))")
            .bind(c.tenant.to_string()).bind(id).bind(n.device.clone()).bind(operation).bind(phase).bind(request).bind(response).bind(Sha256::digest(&bytes).to_vec()).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "T2 #3136: authenticated Apple facts distinguish hardware unknown, unsupported, native rights and product PIN custody"]
async fn apple_reads_distinguish_platform_evidence_and_product_configuration() -> Result<()> {
    let (c, a, http) = open().await?;
    let result=async {
        let n=native::seed(&c,"apple").await?;
        let account=c.account(&[Permission::InventoryRead,Permission::DeviceControl,Permission::DeviceWipe]).await?;
        let p=Arc::new(c.authenticate(&account).await?);
        apple_facts(&c,&a,&n,&p,Some(true),Some("15.0.1")).await?;
        let before=effects(&c).await?;
        let body=read(&c,&http,&p,&n).await?;
        for kind in ["restart","lock","wipe"] { assert_eq!(capability(&body,kind)["devicePrerequisite"]["state"],"supported"); }
        assert_eq!(capability(&body,"lock")["productSupport"],json!({"state":"unsupported","reason":"product_not_configured"}));
        assert_eq!(effects(&c).await?,before);
        let pin="692704";
        let lock=Input { operation_id:Uuid::new_v4(),deadline:time::OffsetDateTime::now_utc().unix_timestamp()+300,action:Action::Lock{confirmed:true,pin:pin.into()} };
        assert!(matches!(a.service.create_control(&p,&n.device,&lock,&c.request(&p)?).await,Err(ControlError::Unsupported)));
        assert!(!format!("{:?}",lock.action).contains(pin));
        assert_eq!(effects(&c).await?,before);
        apple_facts(&c,&a,&n,&p,None,Some("15.0.1")).await?;
        let body=read(&c,&http,&p,&n).await?;
        for kind in ["lock","wipe"] { assert_eq!(capability(&body,kind)["devicePrerequisite"]["state"],"unknown"); }
        assert_eq!(capability(&body,"restart")["devicePrerequisite"]["state"],"supported");
        apple_facts(&c,&a,&n,&p,Some(false),Some("15.0.1")).await?;
        assert_eq!(capability(&read(&c,&http,&p,&n).await?,"wipe")["devicePrerequisite"]["state"],"unsupported");
        apple_facts(&c,&a,&n,&p,Some(true),None).await?;
        assert_eq!(capability(&read(&c,&http,&p,&n).await?,"restart")["devicePrerequisite"]["state"],"unknown");
        apple_facts(&c,&a,&n,&p,Some(true),Some("15.0.1")).await?;
        change(&c, "UPDATE mdm_apple.devices SET access_rights = 1 WHERE tenant_id = CAST($1 AS uuid) AND device = $2", n.device.clone()).await?;
        let body=read(&c,&http,&p,&n).await?;
        assert_eq!(capability(&body,"wipe")["devicePrerequisite"]["state"],"unsupported");
        assert_eq!(capability(&body,"wipe")["permission"]["allowed"],true);
        assert!(matches!(a.service.create_control(&p,&n.device,&wipe(),&c.request(&p)?).await,Err(ControlError::Unsupported)));
        apple_facts(&c,&a,&n,&p,Some(true),Some("corrupt")).await?;
        assert_eq!(http.get(&c,p.clone(),&n.device).await?.0,503);
        Ok(())
    }.await;
    drop(http);
    let drained = Fixture::close(a).await;
    c.close().await;
    drained?;
    result
}

#[tokio::test]
#[ignore = "T2 #3136: missing primary, stale protocol contexts, source conflicts and corrupt facts are not conflated"]
async fn lifecycle_and_dependency_failures_are_not_platform_unsupported() -> Result<()> {
    let (c, a, http) = open().await?;
    let foreign = Context::open("shared", &[]).await?;
    let result=async {
        let n=native::seed(&c,"windows").await?;
        let other=native::seed(&foreign,"windows").await?;
        let account=c.account(&[Permission::InventoryRead]).await?;
        let p=Arc::new(c.authenticate(&account).await?);
        assert_eq!(http.get(&c,p.clone(),&other.device).await?.0,404);
        let outsider=foreign.account(&[Permission::InventoryRead]).await?;
        assert_eq!(http.get(&foreign,Arc::new(foreign.authenticate(&outsider).await?),&n.device).await?.0,403);
        windows(&c,&n,"10.0.22631.0").await?;
        change(&c, "UPDATE mdm_windows.capabilities SET protocol_epoch = gen_random_uuid() WHERE tenant_id = CAST($1 AS uuid) AND device = $2", n.device.clone()).await?;
        assert_eq!(capability(&read(&c,&http,&p,&n).await?,"wipe")["devicePrerequisite"]["state"],"unknown");
        windows(&c,&n,"10.0.22631.0").await?;
        change(&c, "UPDATE mdm_windows.capabilities SET os_version = 'corrupt' WHERE tenant_id = CAST($1 AS uuid) AND device = $2", n.device.clone()).await?;
        assert_eq!(http.get(&c,p.clone(),&n.device).await?.0,503);
        windows(&c,&n,"10.0.22631.0").await?;
        change(&c, "UPDATE mdm_access.report_sources SET enabled = FALSE WHERE tenant_id = CAST($1 AS uuid) AND device = $2", n.device.clone()).await?;
        let body=read(&c,&http,&p,&n).await?;
        for kind in ["restart","lock","wipe"] { assert_eq!(capability(&body,kind)["devicePrerequisite"],json!({"state":"blocked","reason":"capability_unknown"})); }
        change(&c, "UPDATE mdm_access.devices SET state = 'revoked' WHERE tenant_id = CAST($1 AS uuid) AND id = $2", n.device.clone()).await?;
        let body=read(&c,&http,&p,&n).await?;
        for kind in ["restart","lock","wipe"] { assert_eq!(capability(&body,kind)["devicePrerequisite"],json!({"state":"blocked","reason":"not_registered"})); }
        Ok(())
    }.await;
    foreign.close().await;
    drop(http);
    let drained = Fixture::close(a).await;
    c.close().await;
    drained?;
    result
}

#[tokio::test]
#[ignore = "T2 #3136: the registered snapshot rejects committed authority and registration changes before delivery"]
async fn snapshot_revalidates_authority_and_registration_before_return() -> Result<()> {
    use rss_mdm_registration_service::device::endpoints;
    let c = Context::open("shared", &[]).await?;
    let a = Fixture::open(&c, false).await?;
    let result=async {
        let n=native::seed(&c,"windows").await?;
        let account=c.account(&[Permission::InventoryRead]).await?;
        let p=Arc::new(c.authenticate(&account).await?);
        for change_registration in [true,false] {
            let request=c.read_auth(p.clone());
            let result=a.task_reads.snapshot_registered(&request,(&c,&n,&account),move |args,connection,_,_,registration| Box::pin(async move {
                let (c,n,account)=*args;
                *registration=Some((n.device.clone(),endpoints::current_in(rss_mdm_install_support::StorageProfile::Mdm,connection,&c.tenant.to_string(),&n.device,rss_mdm_inventory::Channel::Mdm).await?));
                // A second real connection commits while the first retains its RR snapshot.
                if change_registration {
                    change(c, "UPDATE mdm_access.credentials SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2::uuid", n.credential.to_string()).await.map_err(crate::assembly::task_reads::sql)?;
                } else {
                    change(c, "DELETE FROM mdm_access.authorization_rules WHERE tenant_id=$1::uuid AND id=$2::uuid", account.rule.to_string()).await.map_err(crate::assembly::task_reads::sql)?;
                }
                Ok(())
            })).await;
            assert!(matches!(result,Err(rss_mdm_management_http::Error::QueryReadConflict)), "{result:?}");
        }
        Ok(())
    }.await;
    let drained = Fixture::close(a).await;
    c.close().await;
    drained?;
    result
}
