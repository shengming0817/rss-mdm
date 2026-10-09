use super::*;
use rss_mdm_device_service::{Associations, Confirm, Revoke, State, ViewQuery};
use rss_mdm_registration_service::device::endpoints::{self, PrimaryRegistration};
use serde_json::json;

pub(super) async fn setup() -> anyhow::Result<(
    Arc<Database>,
    Associations,
    AuthorizedPrincipal,
    PgConnection,
)> {
    let (access, _, admin, root) = fixture().await?;
    crate::test_support::identity::set_grants(
        case_a(),
        admin.principal_id(),
        crate::test_support::identity::device_grants(
            None,
            &[
                "inventory_read",
                "device_association_write",
                "enrollment",
                "credentials",
            ],
        )?,
    )
    .await?;
    let service = Associations::new(
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
        TenantId::parse(case_a())?,
        &[7; 32],
    )?;
    Ok((access, service, admin, root))
}
pub(super) fn query(limit: usize) -> ViewQuery {
    ViewQuery {
        cursor: None,
        limit,
        descending: false,
        status: None,
        channel: None,
        source: None,
    }
}
pub(super) fn seed(device: &str, channel: &str, serial: &str) -> anyhow::Result<Uuid> {
    let source = if channel == "mdm" {
        "mdm.windows"
    } else {
        "agent.builtin"
    };
    let (registration, epoch) =
        crate::test_support::inventory::seed_source(device, channel, source, "model")?;
    hardware(device, registration, epoch, source, serial)?;
    Ok(registration)
}
fn hardware(
    _device: &str,
    registration: Uuid,
    epoch: Uuid,
    source: &str,
    serial: &str,
) -> anyhow::Result<()> {
    use rss_mdm_inventory::FieldKey;
    let field = FieldKey::parse("device.serial_number")?;
    let definition = crate::test_support::inventory::definition("hardware", source, &[field]);
    crate::test_support::inventory::register_definition(&definition)?;
    let scope = rss_mdm_registration_service::device::scope_dataset(
        TenantId::parse(case_a())?,
        registration,
        source,
        epoch,
        "hardware",
    )?
    .encode()?;
    let coverage = serde_json::to_string(&definition.coverage()?)?;
    let value = serde_json::to_string(&rss_mdm_inventory::Scalar::String(serial.into()))?;
    crate::test_support::pg(&format!(
        "INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,last_known,last_known_batch,last_known_observed,last_known_received,registration,source,epoch,collection_sequence) VALUES('{}','mdm.observation.v1','inventory-v4','{}','{}','device.serial_number','{}','hardware-fixture',1,2,'known','{}','hardware-fixture',1,2,'{}','{}','{}',0)",
        case_a(),
        scope.replace('\'', "''"),
        coverage.replace('\'', "''"),
        value.replace('\'', "''"),
        value.replace('\'', "''"),
        registration,
        source,
        epoch
    ))?;
    Ok(())
}
pub(super) async fn member(
    c: &mut PgConnection,
    device: &str,
    channel: Channel,
) -> anyhow::Result<PrimaryRegistration> {
    Ok(endpoints::current_in(c, case_a(), device, channel)
        .await?
        .context("primary")?)
}
fn audit(action: &'static str) -> RequestAudit {
    RequestAudit::new(case_a().into(), action)
}

#[tokio::test]
#[ignore = "MODULE=device.associations: real tenant transaction and authority"]
async fn automatic_match_duplicate_detection_and_revocation_suppression() -> anyhow::Result<()> {
    let (access, s, admin, mut c) = setup().await?;
    let mdm = crate::test_support::case::name("association-mdm");
    let agent = crate::test_support::case::name("association-agent");
    seed(mdm, "mdm", " 00-test.serial ")?;
    seed(agent, "agent", "00-TEST.SERIAL")?;
    assert_eq!(s.reconcile().await?, 1);
    assert_eq!(s.reconcile().await?, 0);
    let page = s.views(&admin, &query(64)).await?;
    assert_eq!(
        page["statistics"],
        json!({"endpointCount":2,"deviceViewCount":1})
    );
    let id: Uuid = serde_json::from_value(page["items"][0]["reference"]["id"].clone())?;
    let old = s.get(&admin, id).await?;
    assert_eq!(old.state, State::Confirmed);
    let duplicate = crate::test_support::case::name("association-duplicate");
    seed(duplicate, "mdm", "00-test.serial")?;
    assert_eq!(s.get(&admin, id).await?.state, State::NeedsVerification);
    assert_eq!(s.reconcile().await?, 1);
    let pending = s.get(&admin, id).await?;
    assert_eq!(pending.state, State::NeedsVerification);
    let request = Revoke {
        operation_id: Uuid::new_v4(),
        expected_version: pending.version,
        reason: "separate managed instances".into(),
    };
    let revoked = s
        .revoke(&admin, id, &request, &audit("device_association_revoke"))
        .await?;
    assert_eq!(revoked.state, State::Revoked);
    assert_eq!(
        s.revoke(&admin, id, &request, &audit("device_association_revoke"))
            .await?
            .version,
        revoked.version
    );
    sqlx::query("UPDATE mdm_access.registrations SET state='revoked' WHERE tenant_id=$1::uuid AND device=$2").bind(case_a()).bind(duplicate).execute(&mut c).await?;
    assert_eq!(s.reconcile().await?, 0);
    assert_eq!(
        s.views(&admin, &query(64)).await?["statistics"]["deviceViewCount"],
        3
    );
    let restore = Confirm {
        operation_id: Uuid::new_v4(),
        association_id: Some(id),
        expected_version: revoked.version,
        mdm: member(&mut c, mdm, Channel::Mdm).await?,
        agent: member(&mut c, agent, Channel::Agent).await?,
        evidence: "verified physical possession".into(),
    };
    let result = s
        .confirm(&admin, &restore, &audit("device_association_confirm"))
        .await?;
    assert_eq!(result.state, State::Confirmed);
    assert_eq!(s.get(&admin, id).await?.state, State::Confirmed);
    assert!(matches!(
        s.revoke(&admin, id, &request, &audit("device_association_revoke"))
            .await,
        Ok(_)
    )); // exact replay returns its immutable receipt
    let mut wrong = restore.clone();
    wrong.evidence = "changed operation".into();
    assert!(matches!(
        s.confirm(&admin, &wrong, &audit("device_association_confirm"))
            .await,
        Err(rss_mdm_device_service::Error::Conflict)
    ));
    access.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=device.associations: real tenant transaction and authority"]
async fn generation_continues_after_delayed_report_and_keeps_members_pending() -> anyhow::Result<()>
{
    let (access, s, admin, mut c) = setup().await?;
    let mdm = crate::test_support::case::name("generation-mdm");
    let agent = crate::test_support::case::name("generation-agent");
    seed(mdm, "mdm", "generation-serial")?;
    let old = seed(agent, "agent", "GENERATION-SERIAL")?;
    s.reconcile().await?;
    let page = s.views(&admin, &query(64)).await?;
    let id: Uuid = serde_json::from_value(page["items"][0]["reference"]["id"].clone())?;
    let new = Uuid::new_v4();
    let epoch = Uuid::new_v4();
    sqlx::query(
        "UPDATE mdm_access.registrations SET state='superseded' WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_a())
    .bind(old)
    .execute(&mut c)
    .await?;
    sqlx::query("INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,agent_grant_id,state,purpose,epoch) SELECT tenant_id,$3,device,channel,generation+1,agent_grant_id,'active',purpose,$4 FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2").bind(case_a()).bind(old).bind(new).bind(Uuid::new_v4()).execute(&mut c).await?;
    sqlx::query("INSERT INTO mdm_access.credentials SELECT tenant_id,$3,$4,channel,$5,'active' FROM mdm_access.credentials WHERE tenant_id=$1::uuid AND registration=$2").bind(case_a()).bind(old).bind(Uuid::new_v4()).bind(new).bind(format!("{:064x}",new.as_u128())).execute(&mut c).await?;
    sqlx::query("INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled) VALUES($1::uuid,$2,'agent.builtin',$3,true)").bind(case_a()).bind(new).bind(epoch).execute(&mut c).await?;
    assert_eq!(s.get(&admin, id).await?.state, State::NeedsVerification);
    s.reconcile().await?;
    let pending = s.get(&admin, id).await?;
    assert!(pending.members.iter().any(|m| m.registration_id == old));
    assert_eq!(
        s.views(&admin, &query(64)).await?["statistics"]["deviceViewCount"],
        1
    );
    hardware(agent, new, epoch, "agent.builtin", "generation-serial")?;
    assert_eq!(s.reconcile().await?, 1);
    let continued = s.get(&admin, id).await?;
    assert_eq!(continued.state, State::Confirmed);
    assert!(
        continued
            .members
            .iter()
            .any(|m| m.registration_id == new && m.generation == 2)
    );
    assert_eq!(s.reconcile().await?, 0);
    access.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=device.associations: concurrent membership claims settle atomically"]
async fn competing_confirmations_have_one_receipt_and_no_orphan_relation() -> anyhow::Result<()> {
    let (access, s, admin, mut c) = setup().await?;
    let mdm = crate::test_support::case::name("race-mdm");
    let one = crate::test_support::case::name("race-agent-one");
    let two = crate::test_support::case::name("race-agent-two");
    seed(mdm, "mdm", "race")?;
    seed(one, "agent", "one")?;
    seed(two, "agent", "two")?;
    let first = Confirm {
        operation_id: Uuid::new_v4(),
        association_id: None,
        expected_version: 0,
        mdm: member(&mut c, mdm, Channel::Mdm).await?,
        agent: member(&mut c, one, Channel::Agent).await?,
        evidence: "verified by operator".into(),
    };
    let mut second = first.clone();
    second.operation_id = Uuid::new_v4();
    second.agent = member(&mut c, two, Channel::Agent).await?;
    let a = audit("device_association_confirm");
    let b = audit("device_association_confirm");
    let (a, b) = tokio::join!(
        s.confirm(&admin, &first, &a),
        s.confirm(&admin, &second, &b)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(matches!(
        a.as_ref().err().or(b.as_ref().err()),
        Some(rss_mdm_device_service::Error::Conflict)
    ));
    let count:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_devices.associations WHERE tenant_id=$1::uuid),(SELECT count(*) FROM mdm_devices.members WHERE tenant_id=$1::uuid),(SELECT count(*) FROM mdm_devices.operations WHERE tenant_id=$1::uuid)").bind(case_a()).fetch_one(&mut c).await?;
    assert_eq!(count, (1, 2, 1));
    let result = a.or(b)?;
    assert_eq!(s.get(&admin, result.id).await?.state, State::Confirmed);
    let mut changes = s.changes(&admin, None).await?;
    let mut found = 0;
    loop {
        found += changes["items"].as_array().context("changes")?.len();
        if let Some(cursor) = changes["nextCursor"].as_str() {
            changes = s.changes(&admin, Some(cursor)).await?;
        } else {
            break;
        }
    }
    assert_eq!(found, 1);
    access.close().await;
    Ok(())
}
