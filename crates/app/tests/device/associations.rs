use super::views::people;
use super::*;
use rss_mdm_device_service::{Associations, Confirm, Revoke, State};
use rss_mdm_registration_service::device::endpoints::{self, PrimaryRegistration};
use serde_json::json;

pub(crate) async fn setup() -> anyhow::Result<(
    Arc<Database>,
    Associations,
    AuthorizedPrincipal,
    PgConnection,
)> {
    let (access, _, admin, root) = fixture().await?;
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
    let service = Associations::new(
        access
            .audit_store_fixture(&crate::config::AuditConfig::Plain)
            .await?,
        TenantId::parse(case_a())?,
        &[7; 32],
    )?;
    Ok((access, service, admin, root))
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
    rss_mdm_query::window::Query {
        limit: 64,
        cursor: cursor.map(str::to_owned),
    }
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
    RequestAudit::new(case_a().into(), action)
}

#[tokio::test]
#[ignore = "MODULE=device.associations: real tenant transaction and authority"]
async fn automatic_match_duplicate_detection_and_revocation_suppression() -> anyhow::Result<()> {
    let mut authority = crate::test_support::authority::Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
    let (access, s, admin, mut c) = setup().await?;
    let mdm = crate::test_support::case::name("association-mdm");
    let agent = crate::test_support::case::name("association-agent");
    seed(mdm, "mdm", " 00-test.serial ")?;
    seed(agent, "agent", "00-TEST.SERIAL")?;
    assert_eq!(s.reconcile().await.context("reconcile changed")?, 1);
    assert_eq!(s.reconcile().await.context("reconcile unchanged")?, 0);
    let page = s.views(&admin, &query(64), &people(&authority)?).await.context("device views")?;
    assert_eq!(
        s.statistics(&admin,&query(64),&people(&authority)?).await?["statistics"],
        json!({"endpointCount":2,"deviceViewCount":1})
    );
    let id: Uuid = serde_json::from_value(page["items"][0]["reference"]["id"].clone())?;
    let old = s.get(&admin, id).await?;
    assert_eq!(old.state, State::Confirmed);
    let duplicate = crate::test_support::case::name("association-duplicate");
    seed(duplicate, "mdm", "00-test.serial")?;
    assert_eq!(s.get(&admin, id).await?.state, State::NeedsVerification);
    assert_eq!(s.reconcile().await.context("reconcile changed")?, 1);
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
    assert_eq!(s.reconcile().await.context("reconcile unchanged")?, 0);
    assert_eq!(
        s.statistics(&admin, &query(64), &people(&authority)?).await.context("device views")?["statistics"]["deviceViewCount"],
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
    access.close().await;
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
    let (access, s, admin, mut c) = setup().await?;
    let mdm = crate::test_support::case::name("generation-mdm");
    let agent = crate::test_support::case::name("generation-agent");
    seed(mdm, "mdm", "generation-serial")?;
    let old = seed(agent, "agent", "GENERATION-SERIAL")?;
    s.reconcile().await?;
    let page = s
        .views(&admin, &query(64), &people(&authority)?)
        .await
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
    s.reconcile().await?;
    let pending = s.get(&admin, id).await?;
    assert!(pending.members.iter().any(|m| m.registration_id == old));
    assert_eq!(
        s.statistics(&admin, &query(64), &people(&authority)?)
            .await
            .context("device views")?["statistics"]["deviceViewCount"],
        1
    );
    hardware(agent, new, epoch, "agent.builtin", "generation-serial")?;
    assert_eq!(s.reconcile().await.context("reconcile changed")?, 1);
    let continued = s.get(&admin, id).await?;
    assert_eq!(continued.state, State::Confirmed);
    assert!(
        continued
            .members
            .iter()
            .any(|m| m.registration_id == new && m.generation == 2)
    );
    assert_eq!(s.reconcile().await.context("reconcile unchanged")?, 0);
    access.close().await;
    Ok(())

    }).await
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
    let mut hold = c.begin().await?;
    rss_mdm_inventory_postgres::lock_watermark_in(&mut hold, TenantId::parse(case_a())?).await?;
    let release = async {
        let observed=tokio::time::timeout(Duration::from_secs(3),async {
            loop {
                let waiting:bool=sqlx::query_scalar("WITH RECURSIVE blocked(pid) AS (SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND pg_backend_pid()=ANY(pg_blocking_pids(pid)) UNION SELECT a.pid FROM pg_stat_activity a JOIN blocked b ON b.pid=ANY(pg_blocking_pids(a.pid)) WHERE a.datname=current_database()) SELECT count(*)=2 FROM blocked").fetch_one(&mut *hold).await?;
                if waiting {return Ok::<_,sqlx::Error>(());}
                sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut *hold).await?;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await;
        observed.context("both membership contenders must overlap at the publication fence")??;
        // A staged source producer must reach the publication fence before authorization
        // or endpoint locks, otherwise the online owner can form the reverse wait edge.
        let free: bool =
            sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,2363))")
                .bind(format!("{}:{}", admin.tenant_id(), admin.instance_id()))
                .fetch_one(&mut *hold)
                .await?;
        anyhow::ensure!(
            free,
            "association waiter acquired authorization before watermark"
        );
        for device in [mdm, one, two] {
            let key = serde_json::to_string(&(case_a(), device))?;
            let free: bool =
                sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,2790))")
                    .bind(key)
                    .fetch_one(&mut *hold)
                    .await?;
            anyhow::ensure!(
                free,
                "association waiter acquired lifecycle before watermark"
            );
        }
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
    crate::audit_test_support::projection::drain(
        TenantId::parse(case_a())?,
        rss_audit_postgres::Integrity::Plain,
    )
    .await?;
    let mut changes = s.changes(&admin, &window(None)).await?;
    let mut found = 0;
    loop {
        found += changes["items"].as_array().context("changes")?.len();
        if let Some(cursor) = changes["nextCursor"].as_str() {
            changes = s.changes(&admin, &window(Some(cursor))).await?;
        } else {
            break;
        }
    }
    assert_eq!(found, 1);
    access.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=device.associations: recovery preserves association, membership, receipt and audit"]
async fn confirmation_and_worker_recover_unknown_commit_without_duplicate_facts()
-> anyhow::Result<()> {
    let (access, _, admin, mut c) = setup().await?;
    let store = access
        .audit_store_fixture(&crate::config::AuditConfig::Plain)
        .await?;
    let s = Associations::new(store.clone(), TenantId::parse(case_a())?, &[7; 32])?;
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
    let s = Associations::new(store.clone(), TenantId::parse(case_a())?, &[7; 32])?;
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
    store.inject_next_fault(
        rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
    );
    assert!(matches!(
        s.reconcile().await,
        Err(rss_mdm_device_service::Error::CommitUnknown)
    ));
    assert_eq!(s.reconcile().await.context("reconcile unchanged")?, 0);
    let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_devices.associations WHERE tenant_id=$1::uuid),(SELECT count(*) FROM mdm_devices.members WHERE tenant_id=$1::uuid),(SELECT count(*) FROM mdm_devices.operations WHERE tenant_id=$1::uuid)").bind(case_a()).fetch_one(&mut c).await?;
    assert_eq!(counts, (2, 4, 2));
    let checkpoint:bool=sqlx::query_scalar("SELECT c.watermark=a.revision FROM mdm_devices.checkpoints c JOIN mdm.asset_clock a USING(tenant_id) WHERE tenant_id=$1::uuid").bind(case_a()).fetch_one(&mut c).await?;
    assert!(checkpoint);
    crate::audit_test_support::projection::drain(
        TenantId::parse(case_a())?,
        rss_audit_postgres::Integrity::Plain,
    )
    .await?;
    let mut changes = s.changes(&admin, &window(None)).await?;
    let mut found = 0;
    loop {
        found += changes["items"].as_array().context("changes")?.len();
        if let Some(cursor) = changes["nextCursor"].as_str() {
            changes = s.changes(&admin, &window(Some(cursor))).await?;
        } else {
            break;
        }
    }
    assert_eq!(found, 2);
    access.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=device.associations: signed checkpoints span empty and frozen audit windows"]
async fn change_checkpoints_resume_after_empty_pages_and_restart() -> anyhow::Result<()> {
    let (access, service, admin, mut c) = setup().await?;
    async fn drain(
        service: &Associations,
        admin: &AuthorizedPrincipal,
        mut page: serde_json::Value,
    ) -> anyhow::Result<(Vec<serde_json::Value>, String)> {
        let mut items = Vec::new();
        loop {
            items.extend(page["items"].as_array().context("items")?.iter().cloned());
            if let Some(next) = page["nextCursor"].as_str() {
                assert!(page["checkpoint"].is_null());
                page = service.changes(admin, &window(Some(next))).await?;
            } else {
                return Ok((
                    items,
                    page["checkpoint"]
                        .as_str()
                        .context("terminal checkpoint")?
                        .into(),
                ));
            }
        }
    }
    let (items, empty) = drain(
        &service,
        &admin,
        service.changes(&admin, &window(None)).await?,
    )
    .await?;
    assert!(items.is_empty());
    let idle = service.changes(&admin, &window(Some(&empty))).await?;
    assert_eq!(idle["items"], json!([]));
    assert_eq!(idle["checkpoint"], empty);
    let mdm = crate::test_support::case::name("checkpoint-mdm");
    let agent = crate::test_support::case::name("checkpoint-agent");
    seed(mdm, "mdm", "checkpoint-serial")?;
    seed(agent, "agent", "checkpoint-serial")?;
    let mut request = Confirm {
        operation_id: Uuid::new_v4(),
        association_id: None,
        expected_version: 0,
        mdm: member(&mut c, mdm, Channel::Mdm).await?,
        agent: member(&mut c, agent, Channel::Agent).await?,
        evidence: "verified by operator".into(),
    };
    let clock = crate::test_support::runtime::monotonic();
    let started = clock.now();
    let relation = service
        .seed_confirmation_history(&admin, request.clone(), 66)
        .await?;
    println!(
        "CHECKPOINT_PREPARATION confirmations=66 transactions=1 seconds={:.3}",
        clock
            .now()
            .checked_duration_since(started)
            .context("fixture clock moved backwards")?
            .as_secs_f64()
    );
    request.association_id = Some(relation.id);
    request.expected_version = relation.version;
    crate::audit_test_support::projection::drain(
        TenantId::parse(case_a())?,
        rss_audit_postgres::Integrity::Plain,
    )
    .await?;
    let first = service.changes(&admin, &window(Some(&empty))).await?;
    assert!(first["nextCursor"].is_string());
    // A write after the first page must wait for the next polling window.
    let event = audit("device_association_revoke");
    service
        .revoke(
            &admin,
            request.association_id.context("relation")?,
            &Revoke {
                operation_id: Uuid::new_v4(),
                expected_version: request.expected_version,
                reason: "verified separate instances".into(),
            },
            &event,
        )
        .await?;
    event.finalize(None);
    let (items, checkpoint) = drain(&service, &admin, first).await?;
    assert_eq!(items.len(), 66);
    assert!(
        items
            .iter()
            .all(|item| item["action"] == "device_association_confirm")
    );
    for (index, item) in items.iter().enumerate() {
        assert_eq!(item["association"]["id"], relation.id.to_string());
        assert_eq!(item["association"]["version"], index as i64 + 1);
        if index > 0 {
            assert!(item["position"].as_u64() > items[index - 1]["position"].as_u64());
        }
    }
    let last = items.last().context("last event")?["position"]
        .as_u64()
        .context("position")?;
    let restarted = Associations::new(
        access
            .audit_store_fixture(&crate::config::AuditConfig::Plain)
            .await?,
        TenantId::parse(case_a())?,
        &[7; 32],
    )?;
    crate::audit_test_support::projection::drain(
        TenantId::parse(case_a())?,
        rss_audit_postgres::Integrity::Plain,
    )
    .await?;
    let (items, checkpoint) = drain(
        &restarted,
        &admin,
        restarted
            .changes(&admin, &window(Some(&checkpoint)))
            .await?,
    )
    .await?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["action"], "device_association_revoke");
    assert!(items[0]["position"].as_u64().context("position")? > last);
    for _ in 0..2 {
        let page = restarted
            .changes(&admin, &window(Some(&checkpoint)))
            .await?;
        assert_eq!(page["items"], json!([]));
        assert!(page["nextCursor"].is_null());
        assert_eq!(page["checkpoint"], checkpoint);
    }
    crate::test_support::identity::change_grants(
        case_a(),
        admin.principal_id(),
        crate::test_support::identity::device_grants(Some(mdm), &["inventory_read"])?,
    )
    .await?;
    assert!(matches!(
        restarted.changes(&admin, &window(Some(&checkpoint))).await,
        Err(rss_mdm_device_service::Error::CursorInvalidated)
    ));
    let hidden_first = restarted.changes(&admin, &window(None)).await?;
    assert_eq!(hidden_first["items"], json!([]));
    assert!(
        hidden_first["nextCursor"].is_string(),
        "filtered page must advance through real history"
    );
    assert!(hidden_first["checkpoint"].is_null());
    let (hidden, checkpoint) = drain(&restarted, &admin, hidden_first).await?;
    assert!(hidden.is_empty());
    assert_eq!(
        restarted
            .changes(&admin, &window(Some(&checkpoint)))
            .await?["items"],
        json!([])
    );
    access.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=device.associations: accepted retirement freezes both registrations atomically"]
async fn retirement_fences_complete_target_and_rolls_back_with_acceptance() -> anyhow::Result<()> {
    use rss_mdm_device_service::lifecycle::{self, Acceptance};
    use rss_mdm_inventory_service::objects::{ObjectReader, ObjectRef, SnapshotProgress};
    let (access, s, principal, mut c) = setup().await?;
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
    s.reconcile().await?;
    let association:Uuid=sqlx::query_scalar("SELECT association_id FROM mdm_devices.members WHERE tenant_id=$1::uuid AND device=$2 AND NOT released").bind(case_a()).bind(mdm).fetch_one(&mut c).await?;
    let other_association:Uuid=sqlx::query_scalar("SELECT association_id FROM mdm_devices.members WHERE tenant_id=$1::uuid AND device=$2 AND NOT released").bind(case_a()).bind(other_mdm).fetch_one(&mut c).await?;
    let tenant = TenantId::parse(case_a())?;
    let reader = rss_mdm_device_service::planning::PlanningObjects::new(
        access
            .audit_store_fixture(&crate::config::AuditConfig::Plain)
            .await?,
    );
    let snapshot = reader.freeze(&mut c, tenant).await?;
    for _ in 0..32 {
        if reader.advance(&mut c, tenant, &snapshot).await? == SnapshotProgress::Ready {
            break;
        }
    }
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
        policy: Uuid::new_v4(),
        version: Uuid::new_v4(),
        occurrence: "explicit:test",
        target: &target,
        authority: &grant,
        delivery_seconds: 300,
        now,
    };
    c.execute("BEGIN").await?;
    let first = lifecycle::accept_in(&mut c, tenant, &reader, &input).await?;
    assert!(!first.1);
    // Acceptance of one associated device must not invalidate another identity
    // in the same sealed batch and original transaction.
    let second_input = Acceptance {
        target: &other_target,
        ..input
    };
    let second = lifecycle::accept_in(&mut c, tenant, &reader, &second_input).await?;
    assert_ne!(first.0, second.0);
    for device in [mdm, agent, other_mdm, other_agent] {
        assert!(
            !rss_mdm_registration_service::lifecycle::work_allowed_in(&mut c, case_a(), device)
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
    c.execute("BEGIN").await?;
    let accepted = lifecycle::accept_in(&mut c, tenant, &reader, &input).await?;
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
    super::views::publication_first(&mut c, &principal, async {
        s.force_retirement(
            &principal,
            accepted.0,
            &rss_mdm_device_service::lifecycle_management::ForceRevoke {
                operation_id: Uuid::new_v4(),
                reason: "offline exit".into(),
            },
            &audit("device_retirement_force_revoke"),
        )
        .await?;
        Ok(())
    })
    .await?;
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
    access.close().await;
    Ok(())
}
