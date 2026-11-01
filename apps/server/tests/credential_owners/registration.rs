use super::*;
use rss_mdm_agent_wire::runtime as w;
use rss_mdm_registration_service::device_access as da;
use serde_json::json;
#[tokio::test]
#[ignore = "T2: Registration access delivery rejects stale generation without state or audit effects"]
async fn access_offer_requires_current_registration_generation() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let owner = Owners::open(&c, "shared", protection(&c, "old")?).await?;
    let (registration, grant, device) = material::seed_registration(&c).await?;
    let caps = vec![
        w::Capability::InventoryCollectionV1,
        w::Capability::DeviceAccessV1,
        w::Capability::DeviceAccessWhfbV1,
    ];
    let p = material::authenticated_agent(&c, registration, grant, &device, caps.clone()).await?;
    let mut tx = seed(&c).await?;
    sqlx::query("INSERT INTO mdm_agent.bindings(tenant_id,registration,wire_version,capabilities,platform,architecture,execution_context) VALUES($1::uuid,$2,1,$3,'windows','x86_64',$4)").bind(c.tenant.to_string()).bind(registration).bind(serde_json::to_string(&caps)?).bind(json!({"revision":1,"msixSideload":false,"msixUnsigned":false,"osVersion":[10,0,26100,0],"systemBroker":true,"userHelper":false,"interactiveUser":null,"sourceCredentials":[]})).execute(&mut *tx).await?;
    tx.commit().await?;
    let object = serde_json::from_value(
        json!({"object":{"kind":"endpoint","id":device},"associationVersion":null,"verified":true,"members":[{"device":device,"channel":"agent","registrationId":registration,"generation":2}]}),
    )?;
    let scope = crate::planning_t2_support::published(&c, &object)
        .await?
        .scope;
    let policy = Uuid::new_v4();
    let version = Uuid::new_v4();
    let id = Uuid::new_v4();
    let account = w::AccessAccount::Windows {
        sid: "S-1-12-1-1-2-3-4".into(),
        authority: w::AccessWindowsAuthority::Entra {
            tenant_id: Uuid::new_v4(),
            object_id: Uuid::new_v4(),
        },
    };
    let configuration = w::AccessConfiguration {
        mac: None,
        windows: w::AccessWindowsConfiguration::Whfb,
        self_enrollment: false,
        enabled: true,
        role: None,
    };
    let mut binding = da::Binding {
        operation_id: Uuid::new_v4(),
        account_disposition: w::AccessAccountDisposition::Keep,
        id: Uuid::new_v4(),
        tenant: Uuid::parse_str(&c.tenant.to_string())?,
        device: device.clone(),
        registration,
        registration_generation: 1,
        person: da::Person {
            instance: Uuid::parse_str(&c.inputs.installation.instance_id)?,
            principal: Uuid::new_v4(),
        },
        origin: da::Origin::SelfEnrollment,
        generation: 1,
        factor_generation: 1,
        revision: 1,
        state: da::State::Pending,
        intent: da::AccountIntent::Existing {
            account: account.clone(),
        },
        account: Some(account),
        policy,
        policy_version: version,
        configuration: configuration.clone(),
        received_revision: None,
        applied_revision: None,
        effect: None,
        applied_windows: None,
        created_by_rss: false,
    };
    binding.validate()?;
    let mut tx = seed(&c).await?;
    let definition: rss_mdm_policy::Definition = serde_json::from_value(
        json!({"scope":scope,"action":{"kind":"device_access","mac":null,"windows":{"kind":"whfb"},"selfEnrollment":false,"role":null}}),
    )?;
    definition.validate()?;
    let frozen = serde_json::to_value(da::publication::Frozen::DeviceAccess { configuration })?;
    let author = rss_mdm_authorization_service::Actor::Account {
        user: c.user(binding.person.principal),
    };
    sqlx::query("INSERT INTO mdm_policy.policies(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at) VALUES($1::uuid,$2,1,$3,1,'enabled',$4,$5,$6)").bind(c.tenant.to_string()).bind(policy).bind(version).bind(serde_json::to_value(definition)?).bind(serde_json::to_value(author)?).bind(now()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,action_kind,frozen,fingerprint) VALUES($1::uuid,$2,$3,1,'device_access',$4,$5)").bind(c.tenant.to_string()).bind(version).bind(policy).bind(frozen).bind(vec![4u8;32]).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.device_access_bindings(tenant_id,id,device,registration,registration_generation,instance,principal,generation,revision,state,account,document) VALUES($1,$2,$3,$4,1,$5,$6,1,1,'pending',$7,$8)").bind(binding.tenant).bind(binding.id).bind(&device).bind(registration).bind(binding.person.instance).bind(binding.person.principal).bind(serde_json::to_value(&binding.account)?).bind(serde_json::to_value(&binding)?).execute(&mut *tx).await?;
    let state = serde_json::to_value(rss_mdm_task_state::RunState::new(now() + 300, now())?)?;
    sqlx::query("INSERT INTO mdm_access_tasks.runs(tenant_id,id,policy_version,origin,access_binding,device,registration,generation,occurrence,created_at,available_at,deadline,state,dispatch_fingerprint,gateway_accepted) VALUES($1,$2,$3,'\"policy\"',$4,$5,$6,1,$7,$8,$8,$9,$10,$11,true)").bind(binding.tenant).bind(id).bind(version).bind(serde_json::to_value(&binding)?).bind(&device).bind(registration).bind(id.to_string()).bind(now()).bind(now()+300).bind(&state).bind(vec![5u8;32]).execute(&mut *tx).await?;
    tx.commit().await?;
    let input = w::TaskClaimRequest::new(
        Uuid::new_v4(),
        vec![],
        serde_json::from_value(
            json!({"revision":1,"msixSideload":false,"msixUnsigned":false,"osVersion":[10,0,26100,0],"systemBroker":true,"userHelper":false,"interactiveUser":null,"sourceCredentials":[]}),
        )?,
    )?;
    let offer = || async {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            c.tenant.to_string(),
            "access-offer",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("registration-test");
        access::transaction::run(
            &owner.audit,
            &owner.runtime,
            c.tenant,
            &audit,
            (&owner.access, &p, &input, &audit),
            |ctx, tx| {
                Box::pin(async move {
                    ctx.0
                        .agent_offer_one_in(tx, ctx.1, ctx.2, id, Uuid::new_v4(), ctx.3)
                        .await
                })
            },
        )
        .await
    };
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1")
            .bind(binding.tenant)
            .fetch_one(&c.operator)
            .await?;
    assert!(matches!(offer().await, Err(access::Error::Unauthorized)));
    let persisted: serde_json::Value =
        sqlx::query_scalar("SELECT state FROM mdm_access_tasks.runs WHERE tenant_id=$1 AND id=$2")
            .bind(binding.tenant)
            .bind(id)
            .fetch_one(&c.operator)
            .await?;
    assert_eq!(persisted, state);
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1")
            .bind(binding.tenant)
            .fetch_one(&c.operator)
            .await?;
    assert_eq!(after, before);

    binding.registration_generation = 2;
    sqlx::query("UPDATE mdm_access.device_access_bindings SET registration_generation=2,document=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(binding.tenant).bind(binding.id).bind(serde_json::to_value(&binding)?).execute(&c.operator).await?;
    sqlx::query("UPDATE mdm_access_tasks.runs SET generation=2,access_binding=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(binding.tenant)
        .bind(id)
        .bind(serde_json::to_value(&binding)?)
        .execute(&c.operator)
        .await?;
    assert!(offer().await?.is_some());
    owner.close().await;
    c.close().await;
    Ok(())
}
