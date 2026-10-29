//! One affected device per claimed owner step; matching semantics remain domain-owned.
use crate::*;
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_inventory::Channel;
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use std::collections::BTreeSet;
use uuid::Uuid;
pub(crate) struct Prepared {
    input: identity::PreparedWorld,
    changes: Vec<Change>,
}
enum Change {
    Refresh(Association),
    Write(
        Confirm,
        std::collections::BTreeMap<String, identity::Hardware>,
        State,
    ),
}
pub(crate) async fn prepare(
    c: &mut PgConnection,
    tenant: TenantId,
    device: &str,
) -> Result<Prepared> {
    let input = identity::affected_world(c, tenant, device).await?;
    let world = &input.world;
    let mut occupied = BTreeSet::new();
    let mut changes = Vec::new();
    for old in &world.associations {
        if old.state == State::Revoked {
            continue;
        }
        occupied.extend(old.members.iter().map(|m| m.device.clone()));
        if !old.members.iter().any(|m| m.device == device) {
            continue;
        }
        let effective = world.effective(old.clone());
        let members = if effective.state == State::Confirmed {
            old.members
                .iter()
                .map(|m| {
                    world
                        .current(m)
                        .map(|e| e.member.clone())
                        .ok_or(Error::Conflict)
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            old.members.clone()
        };
        if effective.state == old.state && members == old.members {
            changes.push(Change::Refresh(effective));
            continue;
        }
        let hardware = if effective.state == State::Confirmed {
            identity::evidence(world, &members)
        } else {
            old.hardware.clone()
        };
        let request = command(Some(old), &members, "automatic registration continuity");
        changes.push(Change::Write(request, hardware, effective.state));
    }
    for mdm in world
        .endpoints
        .iter()
        .filter(|e| e.member.channel == Channel::Mdm)
    {
        if occupied.contains(&mdm.member.device) {
            continue;
        }
        let Some(agent) = world.peer(mdm) else {
            continue;
        };
        let members = vec![mdm.member.clone(), agent.member.clone()];
        if !members.iter().any(|m| m.device == device)
            || occupied.contains(&agent.member.device)
            || !world.unique(&members, &mdm.hardware)
            || !world.unique(&members, &agent.hardware)
            || world.revoked(&members)
        {
            continue;
        }
        let request = command(None, &members, "automatic unique hardware match");
        changes.push(Change::Write(
            request,
            identity::evidence(world, &members),
            State::Confirmed,
        ));
        occupied.extend(members.iter().map(|m| m.device.clone()));
    }
    Ok(Prepared { input, changes })
}
/// Only relevant-input revalidation and publication hold the nonblocking tenant fence.
pub(crate) async fn publish(
    c: &mut PgConnection,
    tenant: TenantId,
    prepared: Prepared,
) -> Result<Vec<Fact>> {
    if prepared.changes.is_empty() {
        return Ok(Vec::new());
    }
    prepared.input.fence(c, tenant).await?;
    let t = tenant.to_string();
    let mut results = Vec::new();
    for change in prepared.changes {
        match change {
            Change::Refresh(association) => {
                crate::identity_projection::association(c, tenant, &association).await?
            }
            Change::Write(request, hardware, state) => {
                let result =
                    write::persist(c, &t, "device-associations", &request, &hardware, state)
                        .await?;
                results.push((request.operation_id, result));
            }
        }
    }

    let audit = RequestAudit::new(
        t.clone(),
        "device_association_automatic",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.identify_service("device-associations");
    let mut facts = Vec::new();
    for (operation, result) in results {
        let value = serde_json::to_value(&result).map_err(|_| Error::Storage)?;
        let digest =
            Sha256::digest(serde_json::to_vec(&result).map_err(|_| Error::Storage)?).to_vec();
        sqlx::query("INSERT INTO mdm_devices.operations(tenant_id,operation_id,actor,instance,digest,result) VALUES($1::uuid,$2,'device-associations','system',$3,$4)").bind(&t).bind(operation).bind(digest).bind(&value).execute(&mut *c).await?;
        let fact_audit = audit.fact_copy("device_association_automatic");
        fact_audit.operation(
            operation,
            "device_association_automatic",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        fact_audit.target(&result.id.to_string());
        facts.push(
            Fact::business(
                &fact_audit,
                &format!("device_association:{operation}"),
                200,
                "success",
                None,
            )?
            .with_details(serde_json::json!({"association":value}))?,
        );
    }
    audit.finalize(None);
    Ok(facts)
}
fn command(old: Option<&Association>, members: &[Member], evidence: &str) -> Confirm {
    Confirm {
        operation_id: Uuid::new_v4(),
        association_id: old.map(|a| a.id),
        expected_version: old.map_or(0, |a| a.version),
        mdm: members
            .iter()
            .find(|m| m.channel == Channel::Mdm)
            .expect("two selected channels")
            .clone(),
        agent: members
            .iter()
            .find(|m| m.channel == Channel::Agent)
            .expect("two selected channels")
            .clone(),
        evidence: evidence.into(),
    }
}
