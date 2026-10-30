use super::views::people;
use super::*;
use rss_mdm_device_service::{Associations, Confirm, Revoke, State};
use rss_mdm_registration_service::device::endpoints::{self, PrimaryRegistration};
use serde_json::json;

pub(crate) async fn setup() -> anyhow::Result<(
    crate::test_support::runtime::Resources,
    crate::test_support::device_worker::DeviceOwner,
    AuthorizedPrincipal,
    PgConnection,
    Arc<rss_mdm_audit_integration::AuditStore>,
)> {
    let admin = admin(case_a(), "admin-a").await?;
    let (pool, source, audit) = crate::audit_test_support::request_store().await?;
    let mut access = crate::test_support::runtime::Resources::default();
    access.resource(crate::test_support::runtime::PoolResource(pool));
    access.resource(crate::test_support::runtime::SourceResource(source.clone()));
    let mut root = PgConnection::connect_with(&options("postgres")?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_a())
        .execute(&mut root)
        .await?;
    crate::test_support::identity::seed_grants(
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
    let service = crate::test_support::device_worker::DeviceOwner::new(
        audit.clone(),
        source,
        TenantId::parse(case_a())?,
    )
    .await?;
    access.resource(service.scheduler.clone());
    Ok((access, service, admin, root, audit))
}
pub(super) fn query(limit: usize) -> rss_mdm_query::directory::Query {
    parameters(limit, None, None)
}
pub(super) fn parameters(
    limit: usize,
    filter: Option<&str>,
    cursor: Option<&str>,
) -> rss_mdm_query::directory::Query {
    let mut url = url::form_urlencoded::Serializer::new(String::new());
    url.append_pair("limit", &limit.to_string());
    if let Some(filter) = filter {
        url.append_pair("filter", filter);
    }
    if let Some(cursor) = cursor {
        url.append_pair("cursor", cursor);
    }
    rss_mdm_device_service::directory::parse(&url.finish()).unwrap()
}
pub(super) fn window(cursor: Option<&str>) -> rss_mdm_query::window::Query {
    rss_mdm_device_service::changes::SCHEMA
        .parse(&format!(
            "limit=64{}",
            cursor.map(|c| format!("&cursor={c}")).unwrap_or_default()
        ))
        .unwrap()
        .0
}
pub(crate) fn seed(device: &str, channel: &str, serial: &str) -> anyhow::Result<Uuid> {
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
pub(crate) fn hardware(
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
    let canonical = rss_mdm_inventory::builtin::fields()
        .into_iter()
        .find(|definition| definition.key == field)
        .context("serial field")?
        .canonical_value(rss_mdm_inventory::Scalar::String(serial.into()))?;
    let value = serde_json::to_string(&canonical)?;
    crate::test_support::process::pg(&format!(
        "INSERT INTO mdm.inventory(field_scope,tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,last_known,last_known_batch,last_known_observed,last_known_received,registration,source,epoch,collection_sequence) VALUES(replace(jsonb_build_object('kind','device')::text,' ',''),'{}','mdm.observation.v1','inventory-projection-v1','{}','{}','device.serial_number','{}','hardware-fixture',1,2,'known','{}','hardware-fixture',1,2,'{}','{}','{}',0)",
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
    endpoints::current_in(c, case_a(), device, channel)
        .await?
        .context("primary")
}
fn audit(action: &'static str) -> RequestAudit {
    RequestAudit::new(
        case_a().into(),
        action,
        rss_mdm_audit_integration::AuditIntent::Management,
    )
}

#[tokio::test]
#[ignore = "MODULE=device.associations: real tenant transaction and authority"]
async fn automatic_match_duplicate_detection_and_revocation_suppression() -> anyhow::Result<()> {
    let mut authority = crate::test_support::authority::Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
    let (access, s, admin, mut c, _audit_store) = setup().await?;
    let mdm = crate::test_support::case::name("association-mdm");
    let agent = crate::test_support::case::name("association-agent");
    seed(mdm, "mdm", " 00-test.serial ")?;
    seed(agent, "agent", "00-TEST.SERIAL")?;
    assert_eq!(s.drain().await.context("reconcile changed")?, 1);
    assert_eq!(s.drain().await.context("reconcile unchanged")?, 0);
    let page = s.views(&admin, &query(64), &people(&authority)?).await.map(|value|serde_json::to_value(value).expect("device response serializes")).context("device views")?;
    assert_eq!(
        s.statistics(&admin,&query(64),&people(&authority)?).await.map(|value|serde_json::to_value(value).expect("device response serializes"))?["statistics"],
        json!({"endpointCount":2,"deviceViewCount":1})
    );
    let id: Uuid = serde_json::from_value(page["items"][0]["reference"]["id"].clone())?;
    let old = s.get(&admin, id).await?;
    assert_eq!(old.state, State::Confirmed);
    let duplicate = crate::test_support::case::name("association-duplicate");
    seed(duplicate, "mdm", "00-test.serial")?;
    assert_eq!(s.get(&admin, id).await?.state, State::NeedsVerification);
    assert_eq!(s.drain().await.context("reconcile changed")?, 1);
    let pending = s.get(&admin, id).await?;
    assert_eq!(pending.state, State::NeedsVerification);
    assert_eq!(pending.evidence, old.evidence);
    assert_eq!(pending.confirmed_at, old.confirmed_at);
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
    assert_eq!(s.drain().await.context("reconcile unchanged")?, 0);
    assert_eq!(
        s.statistics(&admin, &query(64), &people(&authority)?).await.map(|value|serde_json::to_value(value).expect("device response serializes")).context("device views")?["statistics"]["deviceViewCount"],
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
    assert_eq!(
        serde_json::to_value(
            s.revoke(&admin, id, &request, &audit("device_association_revoke"))
                .await?
        )?,
        serde_json::to_value(revoked)?
    );
    assert_eq!(s.get(&admin, id).await?.state, State::Confirmed);
    let mut wrong = restore.clone();
    wrong.evidence = "changed operation".into();
    assert!(matches!(
        s.confirm(&admin, &wrong, &audit("device_association_confirm"))
            .await,
        Err(rss_mdm_device_service::Error::Conflict)
    ));
    access.finish(async { Ok(()) }).await?;
    Ok(())

    }).await
}

#[tokio::test]
#[ignore = "MODULE=device.associations: real tenant transaction and authority"]
async fn generation_continues_after_delayed_report_and_keeps_members_pending() -> anyhow::Result<()>
{
    let mut authority = crate::test_support::authority::Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
    let (access, s, admin, mut c, _audit_store) = setup().await?;
    let mdm = crate::test_support::case::name("generation-mdm");
    let agent = crate::test_support::case::name("generation-agent");
    seed(mdm, "mdm", "generation-serial")?;
    let old = seed(agent, "agent", "GENERATION-SERIAL")?;
    s.drain().await?;
    let page = s
        .views(&admin, &query(64), &people(&authority)?)
        .await.map(|value|serde_json::to_value(value).expect("device response serializes"))
        .context("device views")?;
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
    s.drain().await?;
    let pending = s.get(&admin, id).await?;
    assert!(pending.members.iter().any(|m| m.registration_id == old));
    assert_eq!(
        s.statistics(&admin, &query(64), &people(&authority)?)
            .await.map(|value|serde_json::to_value(value).expect("device response serializes"))
            .context("device views")?["statistics"]["deviceViewCount"],
        1
    );
    hardware(agent, new, epoch, "agent.builtin", "generation-serial")?;
    assert_eq!(s.drain().await.context("reconcile changed")?, 1);
    let continued = s.get(&admin, id).await?;
    assert_eq!(continued.state, State::Confirmed);
    assert!(
        continued
            .members
            .iter()
            .any(|m| m.registration_id == new && m.generation == 2)
    );
    assert_eq!(s.drain().await.context("reconcile unchanged")?, 0);
    access.finish(async { Ok(()) }).await?;
    Ok(())

    }).await
}

#[tokio::test]
#[ignore = "MODULE=device.associations: concurrent membership claims settle atomically"]
async fn competing_confirmations_have_one_receipt_and_no_orphan_relation() -> anyhow::Result<()> {
    let (access, s, admin, mut c, _audit_store) = setup().await?;
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
    let mut hold = c.begin().await?;
    rss_mdm_registration_service::lifecycle::lock_device_in(&mut hold, case_a(), mdm).await?;
    let release = async {
        let observed=tokio::time::timeout(Duration::from_secs(3),async {
            loop {
                let waiting:bool=sqlx::query_scalar("WITH RECURSIVE blocked(pid) AS (SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND pg_backend_pid()=ANY(pg_blocking_pids(pid)) UNION SELECT a.pid FROM pg_stat_activity a JOIN blocked b ON b.pid=ANY(pg_blocking_pids(a.pid)) WHERE a.datname=current_database()) SELECT count(*)=2 FROM blocked").fetch_one(&mut *hold).await?;
                if waiting {return Ok::<_,sqlx::Error>(());}
                sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut *hold).await?;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await;
        observed
            .context("both membership contenders must overlap at their common device fence")??;
        hold.rollback().await?;
        Ok::<_, anyhow::Error>(())
    };
    let (a, b, released) = tokio::join!(
        s.confirm(&admin, &first, &a),
        s.confirm(&admin, &second, &b),
        release
    );
    released?;
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(matches!(
        a.as_ref().err().or(b.as_ref().err()),
        Some(rss_mdm_device_service::Error::Conflict)
    ));
    let count:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_devices.associations WHERE tenant_id=$1::uuid),(SELECT count(*) FROM mdm_devices.members WHERE tenant_id=$1::uuid),(SELECT count(*) FROM mdm_devices.operations WHERE tenant_id=$1::uuid)").bind(case_a()).fetch_one(&mut c).await?;
    assert_eq!(count, (1, 2, 1));
    let result = a.or(b)?;
    assert_eq!(
        s.get(&admin, result.id)
            .await
            .context("get committed association")?
            .state,
        State::Confirmed
    );

    let mut changes = serde_json::to_value(s.changes(&admin, &window(None)).await?)?;
    let mut found = 0;
    loop {
        found += changes["items"].as_array().context("changes")?.len();
        if let Some(cursor) = changes["nextCursor"].as_str() {
            changes = serde_json::to_value(s.changes(&admin, &window(Some(cursor))).await?)?;
        } else {
            break;
        }
    }
    assert_eq!(found, 1);
    access.finish(async { Ok(()) }).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=device.associations: recovery preserves association, membership, receipt and audit"]
async fn confirmation_and_worker_recover_unknown_commit_without_duplicate_facts()
-> anyhow::Result<()> {
    let (access, original, admin, mut c, audit_store) = setup().await?;
    let store = audit_store.clone();
    let s = original.clone();
    let mdm = crate::test_support::case::name("recovery-mdm");
    let agent = crate::test_support::case::name("recovery-agent");
    seed(mdm, "mdm", "recovery-serial")?;
    seed(agent, "agent", "RECOVERY-SERIAL")?;
    let request = Confirm {
        operation_id: Uuid::new_v4(),
        association_id: None,
        expected_version: 0,
        mdm: member(&mut c, mdm, Channel::Mdm).await?,
        agent: member(&mut c, agent, Channel::Agent).await?,
        evidence: "physically verified".into(),
    };
    store
        .inject_next_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitPending);
    assert!(matches!(
        s.confirm(&admin, &request, &audit("device_association_confirm"))
            .await,
        Err(rss_mdm_device_service::Error::CommitUnknown)
    ));
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_devices.associations WHERE tenant_id=$1::uuid",
    )
    .bind(case_a())
    .fetch_one(&mut c)
    .await?;
    assert_eq!(count, 0);
    let receipts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mdm_devices.operations WHERE tenant_id=$1::uuid")
            .bind(case_a())
            .fetch_one(&mut c)
            .await?;
    assert_eq!(receipts, 0);
    let members: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mdm_devices.members WHERE tenant_id=$1::uuid")
            .bind(case_a())
            .fetch_one(&mut c)
            .await?;
    assert_eq!(members, 0);
    store.inject_next_fault(
        rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
    );
    assert!(matches!(
        s.confirm(&admin, &request, &audit("device_association_confirm"))
            .await,
        Err(rss_mdm_device_service::Error::CommitUnknown)
    ));
    let s = original.clone();
    let recovered = s
        .confirm(&admin, &request, &audit("device_association_confirm"))
        .await?;
    let mut stale = request.clone();
    stale.operation_id = Uuid::new_v4();
    stale.association_id = Some(recovered.id);
    stale.expected_version = recovered.version + 1;
    assert!(matches!(
        s.confirm(&admin, &stale, &audit("device_association_confirm"))
            .await,
        Err(rss_mdm_device_service::Error::Conflict)
    ));
    let other_mdm = crate::test_support::case::name("worker-recovery-mdm");
    let other_agent = crate::test_support::case::name("worker-recovery-agent");
    seed(other_mdm, "mdm", "worker-serial")?;
    seed(other_agent, "agent", "WORKER-SERIAL")?;
    while crate::planning::test_support::input_step(s.work.as_ref(), "mdm.devices").await? {}
    use rss_reconcile::{DurableStore, Reconciler};
    let work:Uuid=sqlx::query_scalar("SELECT id FROM mdm_devices.association_work WHERE tenant_id=$1::uuid AND kind='device' AND value=$2").bind(case_a()).bind(other_mdm).fetch_one(&mut c).await?;
    let timer = rss_mdm_execution_service::recovery::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(12), &cancel);
    let claims = s
        .work
        .claim_due(
            &rss_reconcile::Scope::new(TenantId::parse(case_a())?, "mdm.devices")?,
            64,
            Duration::from_secs(30),
            &control,
        )
        .await?
        .claims;
    let mut selected = None;
    for claim in claims {
        if claim.target().entity() == format!("work:{work}") {
            selected = Some(claim);
        } else {
            s.work.release(&claim, &control).await?;
        }
    }
    let claim = selected.context("device claim")?;
    let diff =
        crate::test_support::runtime::reconcile_ready(s.work.observe(&claim, &control).await?);
    store.inject_next_fault(
        rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
    );
    assert_eq!(
        s.work
            .apply(&claim, diff, &control)
            .await
            .unwrap_err()
            .kind(),
        rss_reconcile::ErrorKind::CommitUnknown
    );
    s.work.release(&claim, &control).await?;
    assert_eq!(s.drain().await.context("reconcile unchanged")?, 0);
    let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_devices.associations WHERE tenant_id=$1::uuid),(SELECT count(*) FROM mdm_devices.members WHERE tenant_id=$1::uuid),(SELECT count(*) FROM mdm_devices.operations WHERE tenant_id=$1::uuid)").bind(case_a()).fetch_one(&mut c).await?;
    assert_eq!(counts, (2, 4, 2));
    let checkpoint:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM mdm.asset_changes e WHERE e.tenant_id=c.tenant_id AND NOT mdm.asset_visible(c.from_cut,e.revision)) FROM mdm_devices.checkpoints c WHERE tenant_id=$1::uuid").bind(case_a()).fetch_one(&mut c).await?;
    assert!(checkpoint);

    let mut changes = serde_json::to_value(s.changes(&admin, &window(None)).await?)?;
    let mut found = 0;
    loop {
        found += changes["items"].as_array().context("changes")?.len();
        if let Some(cursor) = changes["nextCursor"].as_str() {
            changes = serde_json::to_value(s.changes(&admin, &window(Some(cursor))).await?)?;
        } else {
            break;
        }
    }
    assert_eq!(found, 2);
    access.finish(async { Ok(()) }).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=device.associations: ordinary navigation, refresh and authorization binding"]
async fn change_navigation_refreshes_and_revalidates_authorization() -> anyhow::Result<()> {
    use rss_mdm_inventory_service::objects::ObjectReader;
    let (access, service, admin, mut c, audit_store) = setup().await?;
    async fn drain(
        service: &Associations,
        admin: &AuthorizedPrincipal,
        mut page: serde_json::Value,
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let mut items = Vec::new();
        loop {
            assert!(page.get("checkpoint").is_none());
            items.extend(page["items"].as_array().context("items")?.iter().cloned());
            if let Some(next) = page["nextCursor"].as_str() {
                page = serde_json::to_value(service.changes(admin, &window(Some(next))).await?)?;
            } else {
                return Ok(items);
            }
        }
    }
    assert!(
        drain(
            &service,
            &admin,
            serde_json::to_value(service.changes(&admin, &window(None)).await?)?
        )
        .await?
        .is_empty()
    );
    let mdm = crate::test_support::case::name("navigation-mdm");
    let agent = crate::test_support::case::name("navigation-agent");
    seed(mdm, "mdm", "navigation-serial")?;
    seed(agent, "agent", "navigation-serial")?;
    let objects = rss_mdm_device_service::planning::PlanningObjects;
    let tenant = TenantId::parse(case_a())?;
    let before = objects.relation_revision(&mut c, tenant).await?;
    let request = Confirm {
        operation_id: Uuid::new_v4(),
        association_id: None,
        expected_version: 0,
        mdm: member(&mut c, mdm, Channel::Mdm).await?,
        agent: member(&mut c, agent, Channel::Agent).await?,
        evidence: "verified by operator".into(),
    };
    let relation = service
        .seed_confirmation_history(&admin, request, 66)
        .await?;
    let revision = objects.relation_revision(&mut c, tenant).await?;
    assert!(revision > before);
    let first = serde_json::to_value(service.changes(&admin, &window(None)).await?)?;
    let cursor = first["nextCursor"]
        .as_str()
        .context("next page")?
        .to_owned();
    let event = audit("device_association_revoke");
    service
        .revoke(
            &admin,
            relation.id,
            &Revoke {
                operation_id: Uuid::new_v4(),
                expected_version: relation.version,
                reason: "verified separate instances".into(),
            },
            &event,
        )
        .await?;
    event.finalize(None);
    assert!(objects.relation_revision(&mut c, tenant).await? > revision);
    // A later commit can appear on a later navigation page; there is no frozen membership.
    let items = drain(&service, &admin, first).await?;
    assert_eq!(items.len(), 67);
    let versions = items
        .iter()
        .map(|item| item["association"]["version"].as_i64().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(versions, (1..=67).collect());
    for pair in items.windows(2) {
        assert!(pair[1]["position"].as_u64() > pair[0]["position"].as_u64());
    }
    let restarted = Associations::new(audit_store, tenant, &[7; 32])?;
    assert_eq!(
        drain(
            &restarted,
            &admin,
            serde_json::to_value(restarted.changes(&admin, &window(None)).await?)?
        )
        .await?
        .len(),
        67
    );
    crate::test_support::identity::change_grants(
        case_a(),
        admin.principal_id(),
        crate::test_support::identity::device_grants(Some(mdm), &["inventory_read"])?,
    )
    .await?;
    assert!(matches!(
        restarted.changes(&admin, &window(Some(&cursor))).await,
        Err(rss_mdm_device_service::Error::CursorInvalidated)
    ));
    let hidden_first = serde_json::to_value(restarted.changes(&admin, &window(None)).await?)?;
    assert_eq!(hidden_first["items"], json!([]));
    assert!(hidden_first["nextCursor"].is_string());
    assert!(drain(&restarted, &admin, hidden_first).await?.is_empty());
    access.finish(async { Ok(()) }).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=device.associations: accepted retirement freezes both registrations atomically"]
async fn retirement_fences_complete_target_and_rolls_back_with_acceptance() -> anyhow::Result<()> {
    use rss_mdm_device_service::lifecycle::{self, Acceptance};
    use rss_mdm_inventory_service::objects::{ObjectReader, ObjectRef};
    let (access, s, principal, mut c, _audit_store) = setup().await?;
    crate::test_support::identity::seed_grants(
        case_a(),
        principal.principal_id(),
        crate::test_support::identity::device_grants(
            None,
            &[
                "inventory_read",
                "device_association_write",
                "device_unmanage",
            ],
        )?,
    )
    .await?;
    let mdm = crate::test_support::case::name("retirement-mdm");
    let agent = crate::test_support::case::name("retirement-agent");
    seed(mdm, "mdm", "retirement-serial")?;
    seed(agent, "agent", "retirement-serial")?;
    let other_mdm = crate::test_support::case::name("retirement-other-mdm");
    let other_agent = crate::test_support::case::name("retirement-other-agent");
    seed(other_mdm, "mdm", "retirement-other-serial")?;
    seed(other_agent, "agent", "retirement-other-serial")?;
    s.drain().await.context("identity preparation")?;
    let association:Uuid=sqlx::query_scalar("SELECT association_id FROM mdm_devices.members WHERE tenant_id=$1::uuid AND device=$2 AND NOT released").bind(case_a()).bind(mdm).fetch_one(&mut c).await?;
    let other_association:Uuid=sqlx::query_scalar("SELECT association_id FROM mdm_devices.members WHERE tenant_id=$1::uuid AND device=$2 AND NOT released").bind(case_a()).bind(other_mdm).fetch_one(&mut c).await?;
    let tenant = TenantId::parse(case_a())?;
    let reader = rss_mdm_device_service::planning::PlanningObjects;
    let snapshot = reader.capture(&mut c, tenant, None).await?;
    let target = reader
        .lookup(
            &mut c,
            tenant,
            snapshot.id,
            &ObjectRef::Association(association),
        )
        .await?;
    assert!(target.verified && target.members.len() == 2);
    let other_target = reader
        .lookup(
            &mut c,
            tenant,
            snapshot.id,
            &ObjectRef::Association(other_association),
        )
        .await?;
    let authority =
        rss_mdm_authorization_service::snapshot_on(&mut c, case_a(), principal.instance_id())
            .await?;
    let grant = rss_mdm_authorization_service::OperationAuthority::all_devices(
        &authority,
        &principal,
        crate::authorization::Permission::DeviceUnmanage,
    )?;
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let mut input = Acceptance {
        origin: rss_mdm_audit_integration::activity::ActivityOrigin::Policy,
        policy: Uuid::new_v4(),
        version: Uuid::new_v4(),
        occurrence: "explicit:test",
        target: &target,
        actor: grant.actor(),
        delivery_seconds: 300,
        now,
    };
    c.execute("BEGIN").await?;
    let first = lifecycle::accept_in(&mut c, tenant, &reader, &input)
        .await
        .context("associated acceptance")?;
    assert!(!first.1);
    for device in [mdm, agent] {
        assert!(
            !rss_mdm_registration_service::lifecycle::work_allowed_in(&mut c, case_a(), device)
                .await?
        );
    }
    for device in [other_mdm, other_agent] {
        assert!(
            rss_mdm_registration_service::lifecycle::work_allowed_in(&mut c, case_a(), device)
                .await?
        );
    }
    c.execute("ROLLBACK").await?;
    for device in [mdm, agent, other_mdm, other_agent] {
        assert!(
            rss_mdm_registration_service::lifecycle::work_allowed_in(&mut c, case_a(), device)
                .await?
        );
    }
    // Independent objects belong to separate owner tasks; each associated pair
    // remains one atomic acceptance rather than a tenant-wide lifecycle batch.
    c.execute("BEGIN").await?;
    let second_input = Acceptance {
        target: &other_target,
        ..input
    };
    let second = lifecycle::accept_in(&mut c, tenant, &reader, &second_input)
        .await
        .context("independent associated acceptance")?;
    assert_ne!(first.0, second.0);
    c.execute("ROLLBACK").await?;
    c.execute("BEGIN").await?;
    let accepted = lifecycle::accept_in(&mut c, tenant, &reader, &input)
        .await
        .context("associated acceptance")?;
    assert_eq!(
        lifecycle::accept_in(&mut c, tenant, &reader, &input).await?,
        (accepted.0, true)
    );
    input.policy = Uuid::new_v4();
    input.version = Uuid::new_v4();
    assert_eq!(
        lifecycle::accept_in(&mut c, tenant, &reader, &input).await?,
        (accepted.0, false)
    );
    assert_eq!(
        lifecycle::read_in(&mut c, tenant, accepted.0)
            .await?
            .channels
            .len(),
        2
    );
    assert_eq!(
        lifecycle::policy_operations_in(&mut c, tenant, input.policy, &target.object.key()).await?,
        vec![accepted.0]
    );
    c.execute("COMMIT").await?;
    let before = lifecycle::read_in(&mut c, tenant, accepted.0).await?;
    {
        s.force_retirement(
            &principal,
            accepted.0,
            &rss_mdm_device_service::lifecycle_management::ForceRevoke {
                operation_id: Uuid::new_v4(),
                reason: "offline exit".into(),
            },
            &audit("device_retirement_force_revoke"),
        )
        .await
        .context("force retirement")?;
    }
    // A worker holding the old cleanup observation cannot move force-revoke back.
    for channel in before.channels {
        lifecycle::observe_in(
            &mut c,
            tenant,
            accepted.0,
            channel.registration,
            lifecycle::Observation::CleanupReady,
        )
        .await?;
        lifecycle::observe_in(
            &mut c,
            tenant,
            accepted.0,
            channel.registration,
            lifecycle::Observation::CleanupBlocked {
                reason: "late_observation",
                execution: None,
                unknown: false,
            },
        )
        .await?;
    }
    let after = lifecycle::read_in(&mut c, tenant, accepted.0).await?;
    assert!(after.forced_at.is_some());
    assert!(
        after
            .channels
            .iter()
            .all(|c| c.stage == lifecycle::Stage::Revoke
                && c.effect == lifecycle::Effect::Unknown
                && c.reason.as_deref() == Some("forced_revoke_cleanup_unconfirmed"))
    );
    access.finish(async { Ok(()) }).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=device.associations: Device and Audit reject a different actual runtime"]
async fn owner_runtime_must_match_the_original_audit_transaction() -> anyhow::Result<()> {
    let (mut resources, owner, _, _, _) = setup().await?;
    let (pool, foreign, _) = crate::audit_test_support::request_store().await?;
    resources.resource(crate::test_support::runtime::PoolResource(pool));
    resources.resource(crate::test_support::runtime::SourceResource(
        foreign.clone(),
    ));
    let rejected = rss_mdm_device_service::worker::DeviceWork::new(
        owner.service.clone(),
        foreign,
        owner.scheduler.store.clone(),
        Arc::new(crate::registration_lifecycle::Bridge),
        2,
        rss_transactional_messaging::policy::OperationDeadline::from_remaining(
            Duration::from_secs(6),
        ),
    )
    .await;
    assert!(rejected.is_err());
    resources.finish(async { Ok(()) }).await
}

#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=device.associations: parallel local computation revalidates a concurrent hardware collision"]
async fn independent_identity_computations_overlap_and_reject_a_new_collision() -> anyhow::Result<()>
{
    let (access, owner, _admin, mut c, _audit) = setup().await?;
    access.finish(async {
        let a = crate::test_support::case::name("parallel-mdm-a");
        let a_peer = crate::test_support::case::name("parallel-agent-a");
        let b = crate::test_support::case::name("parallel-mdm-b");
        let b_peer = crate::test_support::case::name("parallel-agent-b");
        let collision = crate::test_support::case::name("parallel-collision");
        let key_a = format!("parallel-a-{}", Uuid::new_v4());
        let key_b = format!("parallel-b-{}", Uuid::new_v4());
        seed(a, "mdm", &key_a)?;
        seed(a_peer, "agent", &key_a)?;
        seed(b, "mdm", &key_b)?;
        seed(b_peer, "agent", &key_b)?;
        while crate::planning::test_support::input_step(owner.work.as_ref(), "mdm.devices").await? {}
        let mut reached = owner.work.pause_after_compute(vec![a.into(), a_peer.into(), b.into(), b_peer.into()]);
        let mut running = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(40))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let mut launch = running.startup()?.commit();
        launch.stage_deferred_task_with_token(owner.work.clone().registration(Arc::new(tokio::sync::Notify::new())));
        launch.finish();
        let result = async {
            let first = tokio::time::timeout(Duration::from_secs(5), reached.recv()).await?.context("first computation")?;
            let second = tokio::time::timeout(Duration::from_secs(5), reached.recv()).await?.context("second computation")?;
            let pair_a = |device: &str| device == a || device == a_peer;
            anyhow::ensure!(pair_a(&first.device) != pair_a(&second.device), "independent pairs did not compute concurrently");
            // A new, conflicting fact must commit while the old computations are still paused.
            seed(collision, "agent", &key_a)?;
            first.resume.notify_one();
            second.resume.notify_one();
            // Other channel work can reach its one-shot hook after the first attempt
            // releases the pair. Those attempts need no further pause.
            while let Ok(arrival) = reached.try_recv() { arrival.resume.notify_one(); }
            drop(reached);
            let devices = vec![a, a_peer, b, b_peer, collision];
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    let settled: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM mdm.asset_changes e WHERE e.tenant_id=$1::uuid AND NOT mdm.asset_visible((SELECT from_cut FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid),e.revision)) AND NOT EXISTS(SELECT FROM mdm_devices.association_work w WHERE w.tenant_id=$1::uuid AND w.requested>w.completed AND ((w.kind='device' AND w.value=ANY($2)) OR EXISTS(SELECT FROM mdm_devices.identity_keys k WHERE k.tenant_id=w.tenant_id AND k.kind=w.kind AND k.value=w.value AND k.device=ANY($2)))) FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid")
                        .bind(case_a()).bind(&devices).fetch_one(&mut c).await?;
                    if settled { break; }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Ok::<_,anyhow::Error>(())
            }).await??;
            let counts: (i64,i64) = sqlx::query_as("SELECT count(*) FILTER(WHERE m.device=$2),count(*) FILTER(WHERE m.device=$3) FROM mdm_devices.members m JOIN mdm_devices.associations a ON(a.tenant_id,a.id)=(m.tenant_id,m.association_id) WHERE m.tenant_id=$1::uuid AND NOT m.released AND a.state='confirmed'")
                .bind(case_a()).bind(a).bind(b).fetch_one(&mut c).await?;
            anyhow::ensure!(counts == (0,1), "stale uniqueness or unrelated work was lost: {counts:?}");
            Ok::<_,anyhow::Error>(())
        }.await;
        let stopped = running.shutdown().join().await?;
        anyhow::ensure!(stopped.is_clean(), "Device runner did not drain: {stopped:?}");
        c.close().await?;
        result
    }).await
}

#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=device.associations: shutdown drains a real prepared device transaction"]
async fn owner_shutdown_waits_for_prepared_transaction_publication() -> anyhow::Result<()> {
    let (access, owner, _, mut c, _) = setup().await?;
    access.finish(async {
        let mdm = crate::test_support::case::name("drain-mdm");
        let agent = crate::test_support::case::name("drain-agent");
        let key = Uuid::new_v4().to_string();
        seed(mdm, "mdm", &key)?;
        seed(agent, "agent", &key)?;
        while crate::planning::test_support::input_step(owner.work.as_ref(), "mdm.devices").await? {}
        let mut reached = owner.work.pause_after_compute(vec![mdm.into(), agent.into()]);
        let mut running = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(40))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let mut launch = running.startup()?.commit();
        launch.stage_deferred_task_with_token(owner.work.clone().registration(Arc::new(tokio::sync::Notify::new())));
        launch.finish();
        let prepared = tokio::time::timeout(Duration::from_secs(5), reached.recv()).await?.context("prepared transaction")?;
        let stopped = running.shutdown();
        let drained = stopped.join();
        tokio::pin!(drained);
        anyhow::ensure!(tokio::time::timeout(Duration::from_millis(100), &mut drained).await.is_err(), "shutdown cancelled the active transaction");
        drop(reached);
        drop(prepared);
        let outcome = drained.await?;
        anyhow::ensure!(outcome.is_clean(), "unclean drain: {outcome:?}");
        let committed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_devices.members m JOIN mdm_devices.associations a ON(a.tenant_id,a.id)=(m.tenant_id,m.association_id) WHERE m.tenant_id=$1::uuid AND m.device=$2 AND NOT m.released AND a.state='confirmed')")
            .bind(case_a()).bind(mdm).fetch_one(&mut c).await?;
        anyhow::ensure!(committed, "shutdown lost the already prepared business transaction");
        c.close().await?;
        Ok(())
    }).await
}

#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "MODULE=device.associations: only completed association validation can restore trusted evidence"]
async fn ordinary_member_updates_cannot_restore_invalidated_association_evidence()
-> anyhow::Result<()> {
    let (resources, owner, _, mut c, _) = setup().await?;
    resources.finish(async {
        let a = crate::test_support::case::name("a-sticky-mdm");
        let b = crate::test_support::case::name("z-sticky-agent");
        let serial = format!("sticky-{}", Uuid::new_v4());
        let registration = seed(a, "mdm", &serial)?;
        let peer = seed(b, "agent", &serial)?;
        owner.drain().await?;
        let association: Uuid = sqlx::query_scalar("SELECT association_id FROM mdm_devices.members WHERE tenant_id=$1::uuid AND device=$2 AND NOT released")
            .bind(case_a()).bind(a).fetch_one(&mut c).await?;
        let object = format!("association:{association}");
        let evidence: serde_json::Value = sqlx::query_scalar("SELECT v.input FROM mdm_devices.object_heads h JOIN mdm_devices.object_versions v USING(tenant_id,object,revision) WHERE h.tenant_id=$1::uuid AND h.object=$2")
            .bind(case_a()).bind(&object).fetch_one(&mut c).await?;
        assert_eq!(evidence["verified"], true);
        for (serial_value, model) in [
            (Some("contradictory-hardware"), "ordinary-one"),
            (None, "ordinary-later-window"),
            (Some(serial.as_str()), "ordinary-restored-input"),
        ] {
            let mut tx = c.begin().await?;
            if let Some(value) = serial_value {
                let changed = sqlx::query("UPDATE mdm.inventory SET value=$3,last_known=$3 WHERE tenant_id=$1::uuid AND registration=$2 AND field='device.serial_number'")
                    .bind(case_a()).bind(registration.to_string()).bind(serde_json::to_string(&json!({"kind":"string","value":value}))?).execute(&mut *tx).await?;
                assert_eq!(changed.rows_affected(), 1);
            }
            let changed = sqlx::query("UPDATE mdm.inventory SET value=$3,last_known=$3 WHERE tenant_id=$1::uuid AND registration=$2 AND field='device.model'")
                .bind(case_a()).bind(peer.to_string()).bind(serde_json::to_string(&json!({"kind":"string","value":model}))?).execute(&mut *tx).await?;
            assert_eq!(changed.rows_affected(), 1);
            tx.commit().await?;
            while crate::planning::test_support::input_step(owner.work.as_ref(), "mdm.devices").await? {}
            let verified: bool = sqlx::query_scalar("SELECT (v.input->>'verified')::boolean FROM mdm_devices.object_heads h JOIN mdm_devices.object_versions v USING(tenant_id,object,revision) WHERE h.tenant_id=$1::uuid AND h.object=$2")
                .bind(case_a()).bind(&object).fetch_one(&mut c).await?;
            assert!(!verified, "input projection restored evidence before owner validation");
            let accepted: Option<serde_json::Value> = sqlx::query_scalar("SELECT mdm_devices.object_current($1,'agent')")
                .bind(&evidence).fetch_one(&mut c).await?;
            assert!(accepted.is_none(), "old association evidence regained authority");
        }
        owner.drain().await?;
        let accepted: Option<serde_json::Value> = sqlx::query_scalar("SELECT mdm_devices.object_current($1,'agent')")
            .bind(&evidence).fetch_one(&mut c).await?;
        assert!(accepted.is_some(), "completed validation did not restore unchanged association authority");
        Ok(())
    }).await
}

#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "MODULE=device.associations: pending hardware fan-out blocks an existing pair before device recomputation"]
async fn new_hardware_collision_invalidates_pair_before_fanout_runs() -> anyhow::Result<()> {
    let (resources, owner, _, mut c, _) = setup().await?;
    resources.finish(async {
        let a = crate::test_support::case::name("collision-pair-mdm");
        let b = crate::test_support::case::name("collision-pair-agent");
        let third = crate::test_support::case::name("collision-third-agent");
        let serial = format!("pending-collision-{}", Uuid::new_v4());
        seed(a, "mdm", &serial)?;
        seed(b, "agent", &serial)?;
        owner.drain().await?;
        let evidence: serde_json::Value = sqlx::query_scalar("SELECT v.input FROM mdm_devices.members m JOIN mdm_devices.object_heads h ON h.tenant_id=m.tenant_id AND h.object='association:'||m.association_id::text JOIN mdm_devices.object_versions v ON(v.tenant_id,v.object,v.revision)=(h.tenant_id,h.object,h.revision) WHERE m.tenant_id=$1::uuid AND m.device=$2 AND NOT m.released")
            .bind(case_a()).bind(a).fetch_one(&mut c).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar("SELECT mdm_devices.object_current($1,'agent')")
            .bind(&evidence).fetch_one(&mut c).await?;
        assert!(before.is_some());
        seed(third, "agent", &serial)?;
        while crate::planning::test_support::input_step(owner.work.as_ref(), "mdm.devices").await? {}
        let projected: bool = sqlx::query_scalar("SELECT NOT rebuilding AND NOT EXISTS(SELECT FROM mdm.asset_changes e WHERE e.tenant_id=$1::uuid AND NOT mdm.asset_visible(p.from_cut,e.revision)) FROM mdm_devices.checkpoints p WHERE tenant_id=$1::uuid")
            .bind(case_a()).fetch_one(&mut c).await?;
        assert!(projected, "must exercise the gap after input catch-up");
        let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_devices.association_work WHERE tenant_id=$1::uuid AND kind='serial' AND requested>completed)")
            .bind(case_a()).fetch_one(&mut c).await?;
        assert!(pending, "key fan-out must not have run yet");
        let accepted: Option<serde_json::Value> = sqlx::query_scalar("SELECT mdm_devices.object_current($1,'agent')")
            .bind(&evidence).fetch_one(&mut c).await?;
        assert!(accepted.is_none(), "new colliding endpoint left prior pairing authorized");
        owner.drain().await?;
        let state: String = sqlx::query_scalar("SELECT state FROM mdm_devices.associations WHERE tenant_id=$1::uuid AND id=$2")
            .bind(case_a()).bind(Uuid::parse_str(evidence["object"]["id"].as_str().context("association identity")?)?).fetch_one(&mut c).await?;
        assert_eq!(state, "needs_verification");
        let accepted: Option<serde_json::Value> = sqlx::query_scalar("SELECT mdm_devices.object_current($1,'agent')")
            .bind(&evidence).fetch_one(&mut c).await?;
        assert!(accepted.is_none());
        Ok(())
    }).await
}
