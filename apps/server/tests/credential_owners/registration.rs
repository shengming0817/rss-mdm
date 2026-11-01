use super::*;
use rss_mdm_agent_wire::runtime as w;
use rss_mdm_registration_service::device_access as da;
use serde_json::json;
#[tokio::test]
#[ignore = "T2: Registration consumes only a current-generation access binding without rejection side effects"]
async fn access_binding_requires_current_registration_generation() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let owner = Owners::open(&c, "shared", protection(&c, "old")?).await?;
    let (registration, grant, device) = material::seed_registration(&c).await?;
    let caps = vec![
        w::Capability::InventoryCollectionV1,
        w::Capability::DeviceAccessV1,
        w::Capability::DeviceAccessWhfbV1,
    ];
    let p = material::authenticated_agent(&c, registration, grant, &device, caps.clone()).await?;
    let object = serde_json::from_value(
        json!({"object":{"kind":"endpoint","id":device},"associationVersion":null,"verified":true,"members":[{"device":device,"channel":"agent","registrationId":registration,"generation":2}]}),
    )?;
    let scope = crate::planning_t2_support::published(&c, &object)
        .await?
        .scope;
    let policy = Uuid::new_v4();
    let version = Uuid::new_v4();
    let account = w::AccessAccount::Windows {
        sid: "S-1-12-1-1-2-3-4".into(),
        authority: w::AccessWindowsAuthority::Entra {
            tenant_id: Uuid::new_v4(),
            object_id: Uuid::new_v4(),
        },
    };
    let mut tx = seed(&c).await?;
    sqlx::query("INSERT INTO mdm_agent.bindings(tenant_id,registration,wire_version,capabilities,platform,architecture,execution_context) VALUES($1::uuid,$2,1,$3,'windows','x86_64',$4)").bind(c.tenant.to_string()).bind(registration).bind(serde_json::to_string(&caps)?).bind(json!({"revision":1,"msixSideload":false,"msixUnsigned":false,"osVersion":[10,0,26100,0],"systemBroker":true,"userHelper":true,"interactiveUser":{"identity":"S-1-12-1-1-2-3-4","windowsAuthority":match &account { w::AccessAccount::Windows { authority, .. } => Some(authority), _=>None },"generatedUid":null,"sessionId":Uuid::new_v4(),"administrator":false},"sourceCredentials":[]})).execute(&mut *tx).await?;
    tx.commit().await?;
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
    tx.commit().await?;
    let binding_id = binding.id;
    let consume = || async {
        access::transaction::inspect(&owner.runtime, c.tenant, (&owner.access, &p), |ctx, tx| {
            Box::pin(async move {
                let value = tx
                    .with_connection_context(ctx, |(service, principal), c| {
                        Box::pin(async move {
                            Ok(service
                                .registration_access_binding_on(c, principal, binding_id, 1)
                                .await)
                        })
                    })
                    .await??;
                Ok(value)
            })
        })
        .await
    };
    let before_document = serde_json::to_value(&binding)?;
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1")
            .bind(binding.tenant)
            .fetch_one(&c.operator)
            .await?;
    assert!(matches!(consume().await, Err(access::Error::Conflict)));
    let persisted: serde_json::Value = sqlx::query_scalar(
        "SELECT document FROM mdm_access.device_access_bindings WHERE tenant_id=$1 AND id=$2",
    )
    .bind(binding.tenant)
    .bind(binding.id)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(persisted, before_document);
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1")
            .bind(binding.tenant)
            .fetch_one(&c.operator)
            .await?;
    assert_eq!(after, before);

    binding.registration_generation = 2;
    sqlx::query("UPDATE mdm_access.device_access_bindings SET registration_generation=2,document=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(binding.tenant).bind(binding.id).bind(serde_json::to_value(&binding)?).execute(&c.operator).await?;
    assert_eq!(consume().await?.registration_generation, 2);
    owner.close().await;
    c.close().await;
    Ok(())
}
