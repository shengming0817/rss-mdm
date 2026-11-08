//! Minimal registered endpoints and immutable Scope inputs for publication consumers.
use crate::{authority_t2_support::Context, command_runtime_t2_support::seed_transaction};
use anyhow::Result;
use rss_mdm_inventory_service::objects::{DeviceObject, ObjectRef};
use rss_mdm_registration_service::device::endpoints::PrimaryRegistration;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;
pub async fn owner(c: &Context, role: &str) -> Result<crate::owner_storage::OwnerRuntime> {
    if role == "mdm_policy_runtime" {
        return Ok(crate::owner_storage::OwnerRuntime::open(
            crate::owner_storage::Messaging::Runtime(&c.inputs.database("shared", role)),
            &crate::owner_storage::StorageBinding {
                target: c.inputs.installation.target,
                lineage: c.inputs.installation.lineage,
                epoch: 1,
            },
            c.tenant,
            4,
            c.audit.clone(),
            "policy-runtime-t2",
            |_| {},
        )
        .await?);
    }
    let runtime = crate::identity::open_runtime(
        &c.inputs.database("shared", role),
        &c.inputs.installation.target,
        &c.inputs.installation.lineage,
        &[(c.tenant, 1)],
        4,
    )
    .await?;
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(10));
    let audit = Arc::new(
        c.audit
            .on_runtime(runtime.clone(), c.tenant, &budget.control())
            .await?,
    );
    Ok(crate::owner_storage::OwnerRuntime { runtime, audit })
}
pub async fn endpoint(c: &Context) -> Result<DeviceObject> {
    let request = Uuid::new_v4();
    let grant = Uuid::new_v4();
    let credential = Uuid::new_v4();
    let epoch = Uuid::new_v4();
    let device = Uuid::new_v4().to_string();
    let mut tx = seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES($1::uuid,$2,'planning-fixture',$3,$4,'enrollment','consumed',clock_timestamp()+interval '4 minutes')").bind(c.tenant.to_string()).bind(grant).bind(&c.inputs.installation.instance_id).bind(&device).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.requests(tenant_id,id,source,state,grant_id,device,expires_at,issuance_operation,password_digest,password_version,credential_ref,windows_profile) VALUES($1::uuid,$2,'mdm.windows','bound',$3,$6,clock_timestamp()+interval '4 minutes',$4,repeat('a',64),1,$5,'Device')").bind(c.tenant.to_string()).bind(request).bind(grant).bind(Uuid::new_v4()).bind(credential).bind(&device).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.devices (tenant_id, id, channel, request_id, state, purpose, epoch) VALUES (CAST($1 AS uuid), $2, 'mdm', $3, 'active', 'primary', $4)").bind(c.tenant.to_string()).bind(&device).bind(request).bind(epoch).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.credentials (tenant_id, id, device, channel, locator, state, purpose) VALUES (CAST($1 AS uuid), $2, $3, 'mdm', $4, 'active', 'primary')").bind(c.tenant.to_string()).bind(credential).bind(&device).bind(format!("{:x}",Sha256::digest(credential.as_bytes()))).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.report_sources (tenant_id, device, source, epoch, next_sequence, enabled) VALUES (CAST($1 AS uuid), $2, 'mdm.windows', $3, 0, TRUE)").bind(c.tenant.to_string()).bind(&device).bind(epoch).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(DeviceObject {
        object: ObjectRef::Endpoint(device.clone()),
        association_version: None,
        verified: true,
        members: vec![PrimaryRegistration {
            device,
            channel: rss_mdm_inventory::Channel::Mdm,
        }],
    })
}
pub struct Published {
    pub policy: Uuid,
    pub scope: Uuid,
    pub run: Uuid,
    pub cut: rss_mdm_inventory::AssetCut,
    pub input: rss_mdm_scope_service::sources::ScopeInput,
}
pub async fn published(c: &Context, object: &DeviceObject) -> Result<Published> {
    let scope = Uuid::new_v4();
    let policy = Uuid::new_v4();
    let run = Uuid::new_v4();
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(6));
    let cut = rss_mdm_inventory_service::assets::cut::capture(&c.audit, c.tenant, &budget).await?;
    let mut tx = seed_transaction(c).await?;
    let device = &object.members[0].device;
    let authority = rss_mdm_registration_service::device::coordinates::authority_at_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        &mut tx,
        c.tenant,
        device,
        &cut,
    )
    .await?;
    let definition = serde_json::from_value(
        json!({"targets":[{"kind":"device","id":device}],"limitations":null,"exclusions":[]}),
    )?;
    let input = rss_mdm_scope_service::sources::ScopeInput {
        definition,
        sources: vec![rss_mdm_scope_service::sources::SourceSet {
            reference: rss_mdm_scope::Reference::Device(device.clone()),
            coordinates: rss_mdm_group::SourceCoordinates {
                member_set: None,
                member_version: 0,
                definition_version: 0,
                authority_version: authority,
                asset_context: rss_mdm_group::AssetContext::Endpoint,
            },
            snapshot: None,
        }],
        as_of: time::OffsetDateTime::now_utc().unix_timestamp(),
    };
    sqlx::query("INSERT INTO mdm_scope.scopes(tenant_id,id,policy_id,revision,calculation_revision,resolution_revision) VALUES($1::uuid,$2,$3,1,1,1)").bind(c.tenant.to_string()).bind(scope).bind(policy).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_scope.scope_versions(tenant_id,id,revision,definition) VALUES($1::uuid,$2,1,$3)").bind(c.tenant.to_string()).bind(scope).bind(serde_json::to_value(&input.definition)?).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_scope.scope_sources(tenant_id,scope,kind,target) VALUES($1::uuid,$2,'device',$3)").bind(c.tenant.to_string()).bind(scope).bind(device).execute(&mut *tx).await?;
    seed_run(
        &mut tx,
        c,
        RunSeed {
            scope,
            run,
            previous: None,
            object,
            cut: &cut,
            input: &input,
            phase: "published",
        },
    )
    .await?;
    sqlx::query("UPDATE mdm_scope.scopes SET resolution=$3 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string())
        .bind(scope)
        .bind(run)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Published {
        policy,
        scope,
        run,
        cut,
        input,
    })
}
pub async fn staged(c: &Context, old: &Published, object: &DeviceObject) -> Result<Uuid> {
    let run = Uuid::new_v4();
    let mut tx = seed_transaction(c).await?;
    seed_run(
        &mut tx,
        c,
        RunSeed {
            scope: old.scope,
            run,
            previous: Some(old.run),
            object,
            cut: &old.cut,
            input: &old.input,
            phase: "ready",
        },
    )
    .await?;
    sqlx::query("INSERT INTO mdm_scope.tasks(tenant_id,id,scope) VALUES($1::uuid,$2,$3)")
        .bind(c.tenant.to_string())
        .bind(run)
        .bind(old.scope)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(run)
}
struct RunSeed<'a> {
    scope: Uuid,
    run: Uuid,
    previous: Option<Uuid>,
    object: &'a DeviceObject,
    cut: &'a rss_mdm_inventory::AssetCut,
    input: &'a rss_mdm_scope_service::sources::ScopeInput,
    phase: &'a str,
}
async fn seed_run(tx: &mut sqlx::PgConnection, c: &Context, seed: RunSeed<'_>) -> Result<()> {
    let RunSeed {
        scope,
        run,
        previous,
        object,
        cut,
        input,
        phase,
    } = seed;
    let device = &object.members[0].device;
    let fingerprint = Sha256::digest(serde_json::to_vec(&(
        1u64,
        &input.definition,
        &input.sources,
    ))?)
    .to_vec();
    sqlx::query("INSERT INTO mdm_scope.scope_runs(tenant_id,id,scope,definition_revision,asset_cut,input,fingerprint,phase,object_count,member_count) VALUES($1::uuid,$2,$3,1,$4,$5,$6,$7,1,1)").bind(c.tenant.to_string()).bind(run).bind(scope).bind(cut.to_json()).bind(serde_json::to_value(input)?).bind(fingerprint).bind(phase).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_scope.scope_source_members(tenant_id,run,source,device,input,unknown) VALUES($1::uuid,$2,0,$3,$4,false)").bind(c.tenant.to_string()).bind(run).bind(object.object.key()).bind(serde_json::to_value(object)?).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_scope.scope_results(tenant_id,run,device,matched,explanation) VALUES($1::uuid,$2,$3,true,$4)").bind(c.tenant.to_string()).bind(run).bind(object.object.key()).bind(json!({"device":device,"targets":input.definition.targets,"limitations":[],"exclusions":[],"reasons":[]})).execute(&mut *tx).await?;
    let channel = match object.members[0].channel {
        rss_mdm_inventory::Channel::Agent => "agent",
        rss_mdm_inventory::Channel::Mdm => "mdm",
    };
    let mut hashes = json!({"agent":"0".repeat(64),"mdm":"0".repeat(64)});
    hashes[channel] = json!(format!("{:x}", Sha256::digest(serde_json::to_vec(object)?)));
    sqlx::query("INSERT INTO mdm_scope.scope_projection_runs(tenant_id,id,scope,previous_resolution,next_entry,phase,agent_revision,mdm_revision,channel_hashes) VALUES($1::uuid,$2,$3,$4,1,'project',1,1,$5)").bind(c.tenant.to_string()).bind(run).bind(scope).bind(previous).bind(hashes).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_scope.scope_channel_results(tenant_id,run,channel,device,matched,pending,target,entry_revision) VALUES($1::uuid,$2,$5,$3,true,false,$4,1)").bind(c.tenant.to_string()).bind(run).bind(device).bind(serde_json::to_value(&object.members[0])?).bind(channel).execute(&mut *tx).await?;
    sqlx::query(
        "UPDATE mdm_scope.scope_projection_runs SET phase=$3 WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(run)
    .bind(phase)
    .execute(tx)
    .await?;
    Ok(())
}
