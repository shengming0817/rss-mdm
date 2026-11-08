use super::*;
use rss_mdm_inventory_service::objects::DeviceObject;
use sha2::{Digest, Sha256};
async fn seed_transaction(c: &Context) -> Result<sqlx::Transaction<'_, sqlx::Postgres>> {
    c.seed().await
}
pub struct Published {
    pub scope: Uuid,
}
pub async fn published(c: &Context, policy: Uuid, object: &DeviceObject) -> Result<Published> {
    let scope = Uuid::new_v4();
    let run = Uuid::new_v4();
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(6));
    let cut = rss_mdm_inventory_service::assets::cut::capture(&c.audit, c.tenant, &budget).await?;
    let mut tx = seed_transaction(c).await?;
    let device = &object.members[0].device;
    let authority = rss_mdm_registration_service::device::coordinates::authority_at_on(
        DA, &mut tx, c.tenant, device, &cut,
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
    sqlx::query("INSERT INTO rss_da.scopes(tenant_id,id,policy_id,revision,calculation_revision,resolution_revision) VALUES($1::uuid,$2,$3,1,1,1)").bind(c.tenant.to_string()).bind(scope).bind(policy).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_da.scope_versions(tenant_id,id,revision,definition) VALUES($1::uuid,$2,1,$3)").bind(c.tenant.to_string()).bind(scope).bind(serde_json::to_value(&input.definition)?).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_da.scope_sources(tenant_id,scope,kind,target) VALUES($1::uuid,$2,'device',$3)").bind(c.tenant.to_string()).bind(scope).bind(device).execute(&mut *tx).await?;
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
    sqlx::query("UPDATE rss_da.scopes SET resolution=$3 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string())
        .bind(scope)
        .bind(run)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Published { scope })
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
    sqlx::query("INSERT INTO rss_da.scope_runs(tenant_id,id,scope,definition_revision,asset_cut,input,fingerprint,phase,object_count,member_count) VALUES($1::uuid,$2,$3,1,$4,$5,$6,$7,1,1)").bind(c.tenant.to_string()).bind(run).bind(scope).bind(cut.to_json()).bind(serde_json::to_value(input)?).bind(fingerprint).bind(phase).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_da.scope_source_members(tenant_id,run,source,device,input,unknown) VALUES($1::uuid,$2,0,$3,$4,false)").bind(c.tenant.to_string()).bind(run).bind(object.object.key()).bind(serde_json::to_value(object)?).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_da.scope_results(tenant_id,run,device,matched,explanation) VALUES($1::uuid,$2,$3,true,$4)").bind(c.tenant.to_string()).bind(run).bind(object.object.key()).bind(json!({"device":device,"targets":input.definition.targets,"limitations":[],"exclusions":[],"reasons":[]})).execute(&mut *tx).await?;
    let channel = match object.members[0].channel {
        rss_mdm_inventory::Channel::Agent => "agent",
        rss_mdm_inventory::Channel::Mdm => "mdm",
    };
    let mut hashes = json!({"agent":"0".repeat(64),"mdm":"0".repeat(64)});
    hashes[channel] = json!(format!("{:x}", Sha256::digest(serde_json::to_vec(object)?)));
    sqlx::query("INSERT INTO rss_da.scope_projection_runs(tenant_id,id,scope,previous_resolution,next_entry,phase,agent_revision,mdm_revision,channel_hashes) VALUES($1::uuid,$2,$3,$4,1,'project',1,1,$5)").bind(c.tenant.to_string()).bind(run).bind(scope).bind(previous).bind(hashes).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_da.scope_channel_results(tenant_id,run,channel,device,matched,pending,target,entry_revision) VALUES($1::uuid,$2,$5,$3,true,false,$4,1)").bind(c.tenant.to_string()).bind(run).bind(device).bind(serde_json::to_value(&object.members[0])?).bind(channel).execute(&mut *tx).await?;
    sqlx::query(
        "UPDATE rss_da.scope_projection_runs SET phase=$3 WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(run)
    .bind(phase)
    .execute(tx)
    .await?;
    Ok(())
}
