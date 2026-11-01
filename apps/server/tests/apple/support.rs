//! Apple-owned legal material, dispatch and publication rows for real protocol consumers.
use crate::{
    authority_t2_support::Context,
    native_identity_t2_support::{self as identity, Native},
};
use anyhow::Result;
use rss_mdm_device_service::control::{Create, authority::Authority};
use rss_mdm_native_protection::{ProtectionContext, Protector};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;
pub fn context(user: bool) -> rss_mdm_apple_mdm::applicability::Context {
    use rss_mdm_apple_mdm::applicability::*;
    Context {
        version: Some(Version::parse("26.0").unwrap()),
        channel: if user { Channel::User } else { Channel::Device },
        enrollment: Enrollment::Device,
        supervised: Some(true),
        automated_enrollment: Some(true),
        user_approved: Some(true),
        apple_silicon: Some(true),
    }
}
pub async fn apple(
    c: &Context,
    n: &Native,
    key: Arc<Protector>,
    users: &[String],
) -> Result<(
    Arc<rss_mdm_apple_channel::Apple>,
    rss_mdm_registration_service::DevicePrincipal,
)> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let cert = std::fs::read_to_string(n.directory.join("runtime.pem"))?;
    let private = std::fs::read(n.directory.join("runtime.pk8"))?;
    let der = identity::der("x509", &n.directory.join("runtime.pem")).await?;
    let public = openssl::pkey::PKey::private_key_from_pkcs8(&private)?.public_key_to_der()?;
    use x509_cert::der::{Decode, EncodePem};
    let expires = i64::try_from(
        x509_cert::Certificate::from_der(&der)?
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs(),
    )?;
    let mut hash = Sha256::new();
    hash.update((der.len() as u64).to_be_bytes());
    hash.update(&der);
    let digest = format!("{:x}", hash.finalize());
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    for purpose in ["apns", "profile"] {
        let id = Uuid::new_v4();
        let aad = ProtectionContext::new(
            c.tenant,
            &format!("{purpose}:1:{id}"),
            "apple.runtime.private-key",
            1,
        )?
        .derive();
        let sealed = key.seal_bytes(&private, &aad)?;
        sqlx::query("INSERT INTO mdm_apple_runtime.heads(tenant_id,purpose,revision,desired_revision) VALUES($1::uuid,$2,1,1)").bind(c.tenant.to_string()).bind(purpose).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_apple_runtime.versions(tenant_id,purpose,revision,key_id,public_digest,private_key,csr,certificate,certificate_digest,expires_at,selected,topic) VALUES($1::uuid,$2,1,$3,$4,$5,$6,$7,$8,$9,true,$10)").bind(c.tenant.to_string()).bind(purpose).bind(id).bind(format!("{:x}",Sha256::digest(&public))).bind(sealed).bind(std::fs::read_to_string(n.directory.join("runtime.csr"))?).bind(&cert).bind(&digest).bind(expires).bind(if purpose=="apns"{Some("com.apple.mgmt.rss-t2")}else{None}).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    let root_pem = x509_cert::Certificate::from_der(&n.root)?
        .to_pem(x509_cert::der::pem::LineEnding::LF)?
        .into_bytes();
    let loaded = rss_mdm_apple_channel::runtime_materials::runtime::load(
        &c.database.apple_store(),
        c.tenant,
        &key,
        std::slice::from_ref(&root_pem),
        &rss_mdm_apple_channel::runtime_materials::runtime::Selection {
            apns: Some(1),
            profile: Some(1),
            accounts: Default::default(),
        },
        now,
    )
    .await?;
    let authority = rss_mdm_device_trust::apple::AppleDeviceTrust::from_trust(
        rss_mdm_device_trust::DeviceTrust::new(
            n.trust.clone(),
            rss_mdm_agent_wire::pki::Purpose::Apple,
            now,
        )?,
    )?;
    let checked = authority.verify(
        &[tokio_rustls::rustls::pki_types::CertificateDer::from(
            n.certificate.clone(),
        )],
        now,
    )?;
    let credential = rss_mdm_registration_service::device::ChannelMount::new(
        c.tenant,
        rss_mdm_inventory::ReportSource::MdmApple,
        rss_mdm_registration_service::Purpose::Primary,
    )
    .credential(checked.fingerprint())?;
    let p = crate::device::DeviceService::new(
        c.database.registration(),
        c.tenant.to_string(),
        c.audit.clone(),
    )
    .management_principal(&credential)
    .await?;
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_apple.devices(tenant_id,registration,udid,state,access_rights) VALUES($1::uuid,$2,$3,'active',8191)").bind(c.tenant.to_string()).bind(n.registration).bind(&n.device).execute(&mut *tx).await?;
    for user in std::iter::once("").chain(users.iter().map(String::as_str)) {
        let aad = ProtectionContext::new(
            c.tenant,
            &serde_json::to_string(&(n.registration, 1i64, user, 1i64))?,
            "apple.push.material",
            1,
        )?
        .derive();
        let compare = ProtectionContext::new(
            c.tenant,
            &serde_json::to_string(&(n.registration, 1i64, user, 0i64))?,
            "apple.push.compare",
            1,
        )?
        .derive();
        let bytes = serde_json::to_vec(&json!({"token":[1,2,3],"magic":"native-t2"}))?;
        sqlx::query("INSERT INTO mdm_apple.channels(tenant_id,registration,generation,user_key,state,material,material_digest,token_revision) VALUES($1::uuid,$2,1,$3,'active',$4,$5,1)").bind(c.tenant.to_string()).bind(n.registration).bind(user).bind(key.seal_bytes(&bytes,&aad)?).bind(key.mac(&bytes,&compare)?.to_vec()).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    let push = rss_mdm_apple_channel::push::Push::from_bytes(
        loaded.apns_topic.clone(),
        &loaded.apns_certificate,
        &loaded.apns_private_key,
        Arc::new(identity::Clock),
    )?;
    let webhook =
        rss_mdm_pki_service::scep::Verifier::new(vec![rss_mdm_pki_service::scep::Credentials {
            issuer: format!("{:x}", Sha256::digest(&n.root)),
            challenge_id: "challenge".into(),
            notify_id: "notify".into(),
            challenge_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[7; 32]),
            notify_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[8; 32]),
        }])?;
    let apple = Arc::new(rss_mdm_apple_channel::Apple::new(
        key,
        rss_mdm_apple_channel::Config {
            management: rss_mdm_apple_channel::Origin {
                origin: "https://localhost".into(),
            },
            apns_topic: loaded.apns_topic,
            identity_seed: rss_mdm_apple_channel::IdentitySeed {
                challenge_id: "challenge".into(),
                notify_id: "notify".into(),
            },
        },
        authority,
        loaded.profile,
        push,
        loaded.binding,
        webhook,
        Arc::new(rss_mdm_pki_service::providers::Providers::new(vec![])?),
    ));
    Ok((apple, p))
}
/// Seed a genuinely published command with its immutable protected input and exact authority.
pub async fn operation(
    c: &Context,
    n: &Native,
    key: &Protector,
    input: &Create,
    authority: Authority,
    policy: Option<Uuid>,
) -> Result<()> {
    seed_operation(
        c,
        n,
        key,
        OperationSeed {
            id: input.operation_id,
            input: serde_json::to_value(input)?,
            digest: input.digest(key, c.tenant, &n.device)?.as_bytes().to_vec(),
            authority: serde_json::to_value(authority)?,
            policy,
            configuration: false,
        },
    )
    .await
}
struct OperationSeed {
    id: Uuid,
    input: serde_json::Value,
    digest: Vec<u8>,
    authority: serde_json::Value,
    policy: Option<Uuid>,
    configuration: bool,
}
async fn seed_operation(
    c: &Context,
    n: &Native,
    key: &Protector,
    seed: OperationSeed,
) -> Result<()> {
    let OperationSeed {
        id,
        input,
        digest,
        authority,
        policy,
        configuration,
    } = seed;
    #[derive(serde::Serialize)]
    struct Identity<'a> {
        operation: Uuid,
        device: &'a str,
        registration: Uuid,
        generation: i64,
    }
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Metadata<'a> {
        platform: &'a str,
        deadline: i64,
        input_version: &'a str,
        target: &'a serde_json::Value,
    }
    let meta = Metadata {
        platform: "macos",
        deadline: input["deadline"].as_i64().unwrap(),
        input_version: input["inputVersion"].as_str().unwrap(),
        target: &input["target"],
    };
    let owner = serde_json::to_string(&Identity {
        operation: id,
        device: &n.device,
        registration: n.registration,
        generation: 1,
    })?;
    let field = serde_json::to_string(&("native.operation.input/v1", &meta))?;
    let sealed = key.seal_bytes(
        &serde_json::to_vec(&input)?,
        &ProtectionContext::new(c.tenant, &owner, &field, 1)?.derive(),
    )?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let command_device = Uuid::new_v4();
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    let device:Uuid=sqlx::query_scalar("INSERT INTO mdm_access.command_authorities(tenant_id,device,command_device,generation,epoch,registration,registration_generation) VALUES($1::uuid,$2,$3,1,1,$4,1) ON CONFLICT(tenant_id,device) DO UPDATE SET device=excluded.device RETURNING command_device").bind(c.tenant.to_string()).bind(&n.device).bind(command_device).bind(n.registration).fetch_one(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_device_command.authorities(tenant_id,device_id,generation,authority_epoch) VALUES($1::uuid,$2,1,1) ON CONFLICT DO NOTHING").bind(c.tenant.to_string()).bind(device).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_device_command.commands(tenant_id,command_id,device_id,generation,authority_epoch,expected_digest,deadline,queued_at,outbox_domain,outbox_message_id,outbox_fingerprint,status,published_at,version) VALUES($1::uuid,$2,$3,1,1,$4,$5,$6,'mdm.commands.v1',$2,$4,'published',$6,2)").bind(c.tenant.to_string()).bind(id.to_string()).bind(device).bind(digest).bind(input["deadline"].as_i64().unwrap()*1_000_000).bind(now*1_000_000).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_apple.native_commands(tenant_id,id,registration,registration_generation) VALUES($1::uuid,$2,$3,1)").bind(c.tenant.to_string()).bind(id).bind(n.registration).execute(&mut *tx).await?;
    if configuration {
        sqlx::query("INSERT INTO mdm_planning.configuration_operations(tenant_id,id,device,request,input_context,fingerprint,registration,registration_generation,generation,epoch,authority,dispatch_fingerprint,gateway_accepted,policy_version) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,1,1,1,$8,$6,true,$9)").bind(c.tenant.to_string()).bind(id).bind(&n.device).bind(sealed).bind(serde_json::to_value(meta)?).bind(vec![1u8;32]).bind(n.registration).bind(authority).bind(policy).execute(&mut *tx).await?;
    } else {
        sqlx::query("INSERT INTO mdm_devices.control_operations(tenant_id,id,device,request,input_context,fingerprint,registration,registration_generation,generation,epoch,authority,dispatch_fingerprint,gateway_accepted,source_kind,policy_version) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,1,1,1,$8,$6,true,$9,$10)").bind(c.tenant.to_string()).bind(id).bind(&n.device).bind(sealed).bind(serde_json::to_value(meta)?).bind(vec![1u8;32]).bind(n.registration).bind(authority).bind(if policy.is_some(){"policy"}else{"direct"}).bind(policy).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}
pub async fn dispatched(c: &Context, n: &Native, key: &Protector, operation: Uuid) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let request = rss_mdm_apple_mdm::native::Command::new(
        "RestartDevice",
        plist::Dictionary::new(),
        &rss_mdm_apple_mdm::native::Target {
            context: &context(false),
            access_rights: &["AllowPasscodeRemovalAndLock"],
        },
    )?
    .encode(id)?;
    let aad = ProtectionContext::new(
        c.tenant,
        &serde_json::to_string(&(n.registration, 1i64, id))?,
        "apple.attempt.request",
        1,
    )?
    .derive();
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_apple.attempts(tenant_id,id,registration,generation,operation,phase,ordinal,request,state,deadline,context,user_key) VALUES($1::uuid,$2,$3,1,$4,'execute',0,$5,'sent',clock_timestamp()+interval '5 minutes',$6,'')").bind(c.tenant.to_string()).bind(id).bind(n.registration).bind(operation).bind(key.seal_bytes(&request,&aad)?).bind(serde_json::to_value(context(false))?).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(id)
}
pub async fn publication(
    c: &Context,
    n: &Native,
    key: &Protector,
    user: &str,
) -> Result<(Uuid, String, String)> {
    use rss_mdm_apple_mdm::native::{
        ddm::DeclarationInput,
        input::{FieldValue as F, Fields},
    };
    use rss_mdm_policy_service::configuration::{
        Configuration, NativeTarget, Owner, Protected, Task, frozen::Frozen,
    };
    use std::collections::BTreeMap;
    let id = Uuid::new_v4();
    let policy = Uuid::new_v4();
    let version = Uuid::new_v4();
    let declaration = DeclarationInput {
        identifier: "subscriptions".into(),
        declaration_type: "com.apple.configuration.management.status-subscriptions".into(),
        payload: Fields(BTreeMap::from([(
            "StatusItems".into(),
            F::Array(vec![F::Dictionary(Fields(BTreeMap::from([(
                "Name".into(),
                F::String("management.declarations".into()),
            )])))]),
        )])),
    };
    let native = Configuration {
        target: NativeTarget::User {
            user_id: user.into(),
        },
        apply: Task::Macos {
            request: rss_mdm_apple_mdm::native::request::Request::Declarations {
                declarations: vec![declaration.clone()],
                assets: vec![],
            },
        },
        remove: None,
    };
    native.validate()?;
    let unit = native.unit_key(key, c.tenant, &n.device)?;
    let owner = format!("configuration:{unit}");
    let frozen = Frozen::Configuration {
        native: Protected::seal(key, c.tenant, Owner::Policy { policy, version }, &native)?,
        platform: rss_mdm_policy::Platform::Macos,
        exit: rss_mdm_policy::Exit::Retain,
        resource_digest: [1; 32],
    };
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let definition: rss_mdm_policy::Definition = serde_json::from_value(
        json!({"scope":Uuid::new_v4(),"action":{"resource":{"id":"ddm-native-fixture","version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"kind":"configuration"}}),
    )?;
    definition.validate()?;
    let actor = rss_mdm_authorization_service::Actor::Account {
        user: c.user(Uuid::new_v4()),
    };
    let frozen = serde_json::to_value(frozen)?;
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_policy.policies(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at) VALUES($1::uuid,$2,1,$3,1,'enabled',$4,$5,$6)").bind(c.tenant.to_string()).bind(policy).bind(version).bind(serde_json::to_value(definition)?).bind(serde_json::to_value(actor)?).bind(now).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,action_kind,resource,resource_version,frozen,fingerprint) VALUES($1::uuid,$2,$3,1,'configuration','ddm-native-fixture','v1',$4,$5)").bind(c.tenant.to_string()).bind(version).bind(policy).bind(&frozen).bind(Sha256::digest(serde_json::to_vec(&frozen)?).to_vec()).execute(&mut *tx).await?;
    tx.commit().await?;
    let input = native.request(id, version.to_string(), now + 300, false)?;
    let authority = json!({"kind":"policy","origin":"policy","source_objects":[],"unit":unit,"required":input.task.permissions()?,"tenant":c.tenant.to_string(),"policy":policy,"version":version,"device":n.device,"remove":false});
    seed_operation(
        c,
        n,
        key,
        OperationSeed {
            id,
            input: serde_json::to_value(&input)?,
            digest: input.digest(key, c.tenant, &n.device)?.as_bytes().to_vec(),
            authority,
            policy: Some(version),
            configuration: true,
        },
    )
    .await?;
    let publication = json!({"input_version":version.to_string(),"version":id.to_string(),"owner":owner,"inputs":[declaration],"assets":[],"context":context(true),"legacy":[]});
    let aad = ProtectionContext::new(
        c.tenant,
        &serde_json::to_string(&(n.registration, 1i64, user, id))?,
        "apple.ddm.publication",
        1,
    )?
    .derive();
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_apple.declarations(tenant_id,operation,registration,generation,user_key,owner,snapshot) VALUES($1::uuid,$2,$3,1,$4,$5,$6)").bind(c.tenant.to_string()).bind(id).bind(n.registration).bind(user).bind(owner).bind(key.seal_bytes(&serde_json::to_vec(&publication)?,&aad)?).execute(&mut *tx).await?;
    tx.commit().await?;
    let token = declaration
        .compile(
            &id.to_string(),
            &rss_mdm_apple_mdm::native::Target {
                context: &context(true),
                access_rights: &[],
            },
        )?
        .server_token()
        .to_string();
    Ok((id, version.to_string(), token))
}
