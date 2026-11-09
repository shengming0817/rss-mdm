//! Legal published work for the protocol identity and historical recovery seams.
use super::*;
use rss_mdm_native_protection::{ProtectionContext, Protector};
use rss_mdm_policy_service::configuration::{
    self as cfg, Configuration, Owner, Protected, frozen::Frozen,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;
const DOCUMENT: &str = "27fea311-68b9-4320-9fc4-296f6fdfafe2";
fn document() -> String {
    format!(
        r#"<DeclaredConfiguration schema="1.0" context="Device" id="{DOCUMENT}" checksum="version-1" osdefinedscenario="MSFTExtensibilityMIProviderConfig"><DSC namespace="root/Microsoft/Windows/DesiredStateConfiguration" className="MSFT_FileDirectoryConfiguration"><Key name="DestinationPath">c:\data\file</Key><Value name="Contents">fixture contents</Value></DSC></DeclaredConfiguration>"#
    )
}
fn request(linked: bool, user: bool) -> Result<Configuration> {
    let request = if linked {
        json!({"kind":"node","node":"./Device/Vendor/MSFT/DeclaredConfiguration/Host/Complete/Documents/*/Document","instance":[DOCUMENT],"operation":"replace","value":{"type":"xml","value":document()}})
    } else {
        json!({"kind":"node","node":if user {"./User/Vendor/MSFT/Policy/Config/*/*"} else {"./Device/Vendor/MSFT/Policy/Config/Experience/AllowCortana"},"instance":if user {vec!["Experience", "AllowCortana"]} else {vec![]},"operation":"delete","value":null})
    };
    Ok(serde_json::from_value(
        json!({"target":{"kind":if user {"enrolled_user"}else{"device"}},"apply":{"platform":"windows","request":{"kind":"sync_ml","request":request}},"remove":null}),
    )?)
}
#[derive(serde::Serialize)]
struct Identity<'a> {
    operation: Uuid,
    device: &'a str,
}
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Metadata<'a> {
    platform: &'a str,
    purpose: rss_mdm_registration_service::Purpose,
    deadline: i64,
    input_version: &'a str,
    target: &'a cfg::NativeTarget,
}
async fn seed_group(
    c: &Context,
    n: &identity::Native,
    key: &Protector,
    native: &Configuration,
    ids: &[Uuid],
) -> Result<()> {
    native.validate()?;
    let policy = Uuid::new_v4();
    let version = Uuid::new_v4();
    let unit = native.unit_key(key, c.tenant, &n.device)?;
    let frozen = serde_json::to_value(Frozen::Configuration {
        native: Protected::seal(key, c.tenant, Owner::Policy { policy, version }, native)?,
        platform: rss_mdm_policy::Platform::Windows,
        exit: rss_mdm_policy::Exit::Retain,
        resource_digest: [1; 32],
    })?;
    let definition: rss_mdm_policy::Definition = serde_json::from_value(
        json!({"scope":Uuid::new_v4(),"action":{"kind":"configuration","resource":{"id":"native-identity","version":"v1","platform":"windows","architecture":"x86_64","variant":"default"}}}),
    )?;
    definition.validate()?;
    let actor = rss_mdm_authorization_service::Actor::Account {
        user: c.user(Uuid::new_v4()),
    };
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut tx = command::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_policy.policies(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at) VALUES($1::uuid,$2,1,$3,1,'enabled',$4,$5,$6)").bind(c.tenant.to_string()).bind(policy).bind(version).bind(serde_json::to_value(definition)?).bind(serde_json::to_value(actor)?).bind(now).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,action_kind,resource,resource_version,frozen,fingerprint) VALUES($1::uuid,$2,$3,1,'configuration','native-identity','v1',$4,$5)").bind(c.tenant.to_string()).bind(version).bind(policy).bind(&frozen).bind(Sha256::digest(serde_json::to_vec(&frozen)?).to_vec()).execute(&mut *tx).await?;
    let command_device:Uuid=sqlx::query_scalar("INSERT INTO mdm_access.command_authorities(tenant_id,device,command_device,generation,epoch) VALUES($1::uuid,$2,$3,1,1) ON CONFLICT(tenant_id,device) DO UPDATE SET device=excluded.device RETURNING command_device").bind(c.tenant.to_string()).bind(&n.device).bind(Uuid::new_v4()).fetch_one(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_device_command.authorities(tenant_id,device_id,generation,authority_epoch) VALUES($1::uuid,$2,1,1) ON CONFLICT DO NOTHING").bind(c.tenant.to_string()).bind(command_device).execute(&mut *tx).await?;
    for &id in ids {
        let input = native.request(id, version.to_string(), now + 1800, false)?;
        input.validate(now)?;
        let metadata = Metadata {
            platform: "windows",
            purpose: input.task.purpose()?,
            deadline: input.deadline,
            input_version: &input.input_version,
            target: &input.target,
        };
        let aad = ProtectionContext::new(
            c.tenant,
            &serde_json::to_string(&Identity {
                operation: id,
                device: &n.device,
            })?,
            &serde_json::to_string(&("native.operation.input/v1", &metadata))?,
            1,
        )?
        .derive();
        let sealed = key.seal_bytes(&serde_json::to_vec(&input)?, &aad)?;
        let digest = input.digest(key, c.tenant, &n.device)?.as_bytes().to_vec();
        let authority = json!({"kind":"policy","origin":"policy","source_objects":[{"object":{"kind":"endpoint","id":n.device},"associationVersion":null,"verified":true,"members":[{"device":n.device,"channel":"mdm"}]}],"unit":unit,"required":input.task.permissions()?,"tenant":c.tenant.to_string(),"policy":policy,"version":version,"device":n.device,"remove":false});
        sqlx::query("INSERT INTO rss_device_command.commands(tenant_id,command_id,device_id,generation,authority_epoch,expected_digest,deadline,queued_at,outbox_domain,outbox_message_id,outbox_fingerprint,status,published_at,version) VALUES($1::uuid,$2,$3,1,1,$4,$5,$6,'mdm.commands.v1',$2,$4,'published',$6,2)").bind(c.tenant.to_string()).bind(id.to_string()).bind(command_device).bind(&digest).bind(input.deadline*1_000_000).bind(now*1_000_000).execute(&mut *tx).await?;
        sqlx::query(
            "INSERT INTO mdm_windows.native_commands(tenant_id,id,device) VALUES($1::uuid,$2,$3)",
        )
        .bind(c.tenant.to_string())
        .bind(id)
        .bind(&n.device)
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO mdm_planning.configuration_operations(tenant_id,id,device,request,input_context,fingerprint,generation,epoch,authority,dispatch_fingerprint,gateway_accepted,policy_version) VALUES($1::uuid,$2,$3,$4,$5,$6,1,1,$7,$6,true,$8)").bind(c.tenant.to_string()).bind(id).bind(&n.device).bind(sealed).bind(serde_json::to_value(metadata)?).bind(digest).bind(authority).bind(version).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}
pub(super) async fn prepare(
    c: &Context,
    n: &identity::Native,
    child: &identity::Native,
    old: &identity::Native,
    a: &Fixture,
) -> Result<()> {
    let key = &a.resources.protection;
    seed_group(
        c,
        n,
        key,
        &request(true, false)?,
        &(1..=65).map(Uuid::from_u128).collect::<Vec<_>>(),
    )
    .await?;
    seed_group(
        c,
        n,
        key,
        &request(false, false)?,
        &(66..=130).map(Uuid::from_u128).collect::<Vec<_>>(),
    )
    .await?;
    seed_group(c, n, key, &request(false, true)?, &[Uuid::from_u128(131)]).await?;
    let mut tx = command::seed_transaction(c).await?;
    verify_routes(&mut tx, c, n, child, a).await?;
    history(&mut tx, c, old, key).await?;
    // Keep one real operation per context for the actual wire proof; the batch boundary was proved above.
    sqlx::query("UPDATE rss_device_command.commands SET status='cancelled',version=version+1,terminal_at=queued_at+1 WHERE tenant_id=$1::uuid AND command_id<>$2 AND command_id<>$3").bind(c.tenant.to_string()).bind(Uuid::from_u128(1).to_string()).bind(Uuid::from_u128(66).to_string()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
async fn verify_routes(
    tx: &mut sqlx::PgConnection,
    c: &Context,
    n: &identity::Native,
    child: &identity::Native,
    a: &Fixture,
) -> Result<()> {
    use rss_mdm_install_support::StorageProfile::Mdm;
    use rss_mdm_inventory::ReportSource::MdmWindows;
    use rss_mdm_registration_service::{
        Purpose,
        device::{self, store},
    };
    for (peer, purpose, first) in [
        (n, Purpose::Primary, 66u128),
        (child, Purpose::WindowsDeclared, 1),
    ] {
        let evidence = device::ChannelMount::new(Mdm, c.tenant, MdmWindows, purpose)
            .credential(Sha256::digest(&peer.certificate).into())?;
        let principal = store::management_in(Mdm, &mut *tx, &evidence).await?;
        let candidates = a
            .configuration
            .windows_candidates_on(&mut *tx, &principal)
            .await?;
        assert_eq!(
            candidates.iter().map(|op| op.id).collect::<Vec<_>>(),
            (first..first + 64).map(Uuid::from_u128).collect::<Vec<_>>()
        );
        sqlx::query("INSERT INTO mdm_windows.capabilities(tenant_id,device,protocol_epoch,os_version,edition,session,observed_at) VALUES($1::uuid,$2,$3,'10.0.22631.0',48,17,1)").bind(c.tenant.to_string()).bind(&n.device).bind(peer.epoch).execute(&mut *tx).await?;
    }
    let evidence = device::ChannelMount::new(Mdm, c.tenant, MdmWindows, Purpose::Primary)
        .credential(Sha256::digest(&n.certificate).into())?;
    let parent = store::management_in(Mdm, &mut *tx, &evidence).await?;
    let user = a
        .configuration
        .windows_operation_on(&mut *tx, &parent, Uuid::from_u128(131))
        .await?;
    assert!(
        user.user && user.dispatch,
        "Full user target must reach the session user gate"
    );
    Ok(())
}
pub(super) async fn routed(
    c: &Context,
    n: &identity::Native,
    child: &identity::Native,
    old: &identity::Native,
) -> Result<()> {
    let rows:Vec<(Uuid,Uuid)>=sqlx::query_as("SELECT operation,protocol_epoch FROM mdm_windows.attempts WHERE tenant_id=$1::uuid AND device=$2 ORDER BY operation,ordinal").bind(c.tenant.to_string()).bind(&n.device).fetch_all(&c.operator).await?;
    assert_eq!(
        rows,
        vec![
            (Uuid::from_u128(1), old.epoch),
            (Uuid::from_u128(1), child.epoch),
            (Uuid::from_u128(66), n.epoch)
        ]
    );
    let failed:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_planning.configuration_operations WHERE tenant_id=$1::uuid AND dispatch_failure IS NOT NULL").bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
    assert_eq!(failed, 0);
    let recovered: (i64, String, i64) = sqlx::query_as("SELECT ordinal,phase,session FROM mdm_windows.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND protocol_epoch=$3")
        .bind(c.tenant.to_string()).bind(Uuid::from_u128(1)).bind(child.epoch).fetch_one(&c.operator).await?;
    assert_eq!(recovered, (2, "observe".into(), 17));
    let state: String = sqlx::query_scalar(
        "SELECT status FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(Uuid::from_u128(1).to_string())
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(
        state, "published",
        "an InProgress result cannot complete the command"
    );
    Ok(())
}

async fn history(
    tx: &mut sqlx::PgConnection,
    c: &Context,
    old: &identity::Native,
    key: &Protector,
) -> Result<()> {
    use rss_mdm_windows_mdm::native::{
        Context as Platform, Enrollment, Execution, Scope,
        verification::{EffectFact, EffectState},
    };
    let native = request(true, false)?;
    let cfg::Task::Windows {
        request: Execution::SyncMl { request },
    } = native.apply
    else {
        unreachable!()
    };
    let platform = Platform {
        build: Some([10, 0, 22631, 3958]),
        edition: Some(48),
        scope: Scope::Device,
        enrollment: Enrollment::LinkedCertificate,
    };
    let effect = request.effect_plan(platform)?;
    let plan = effect.readback().unwrap();
    let uri = plan.expected.keys().next().unwrap();
    let value = document()
        .replace("DeclaredConfiguration", "DeclaredConfigurationResult")
        .replace(
            " checksum=",
            " result_checksum=\"result-1\" operation=\"Set\" state=\"20\" checksum=",
        )
        .replace("className=", "status=\"200\" state=\"20\" className=");
    assert_eq!(
        effect
            .assess(&[EffectFact {
                uri: uri.clone(),
                status: Some(200),
                value: Some(value.clone()),
                receipt_accepted: true,
                result_accepted: true
            }])
            .state,
        EffectState::Waiting
    );
    let attempt = Uuid::new_v4();
    let command = 2048i64;
    let aad = ProtectionContext::new(
        c.tenant,
        &serde_json::to_string(&(&old.device, old.epoch, attempt, command, 0i32))?,
        "windows.attempt.result",
        1,
    )?
    .derive();
    let sealed = key.seal_bytes(value.as_bytes(), &aad)?;
    let mut wire = s::decode(
        &first_package(old, "/ManagementServer/Declared.svc", "declared-secret", 17)?,
        &CodecLimits::default(),
    )?;
    std::mem::swap(&mut wire.header.source, &mut wire.header.target);
    wire.header.credential = None;
    wire.commands = vec![plan.request.compile(platform, command as u32)?.command];
    let aad = ProtectionContext::new(
        c.tenant,
        &serde_json::to_string(&(&old.device, old.epoch, attempt))?,
        "windows.attempt.request",
        1,
    )?
    .derive();
    let wire = key.seal_bytes(&s::encode_request(&wire, &CodecLimits::default())?.0, &aad)?;
    sqlx::query("INSERT INTO mdm_windows.attempts(tenant_id,id,operation,ordinal,credential,session,message,phase,request,platform,declared_versions,device,protocol_epoch) VALUES($1::uuid,$2,$3,1,$4,17,1,'observe',$5,$6,'{}',$7,$8)")
        .bind(c.tenant.to_string()).bind(attempt).bind(Uuid::from_u128(1)).bind(old.credential).bind(wire).bind(serde_json::to_value(platform)?).bind(&old.device).bind(old.epoch).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_windows.attempt_items(tenant_id,attempt,command,item_ordinal,kind,uri,status,receipt_accepted,value,result_accepted) VALUES($1::uuid,$2,$3,0,'get',$4,200,true,$5,true)")
        .bind(c.tenant.to_string()).bind(attempt).bind(command).bind(uri).bind(sealed).execute(&mut *tx).await?;
    Ok(())
}
