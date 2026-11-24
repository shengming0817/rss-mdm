//! Scoped directory work and duplicate checks under the actual runtime role.
use super::*;
use crate::assembly::operation_reads::{Budgets, Operations, sources::Scope};
use rss_mdm_inventory_service::objects::DeviceObject;
use rss_mdm_management_http::{Error, Failure};
use rss_mdm_query::directory::Position;
use tower::ServiceExt;

async fn runs(c: &Context, version: Uuid, object: &DeviceObject, ids: &[Uuid]) -> Result<()> {
    let at = now();
    let mut tx = command::seed_transaction(c).await?;
    let added = sqlx::query(
        "INSERT INTO mdm_script.runs(expected_epoch,tenant_id,id,policy_version,resource_id,device,occurrence,
         created_at,available_at,deadline,state,dispatch_fingerprint,source_objects,origin,gateway_accepted)
         SELECT current_setting('rss.execution_epoch')::bigint,$1::uuid,id,$2,'budget-script',$3,id::text,
                $4,$4,$5,$6,$7,$8,'\"policy\"',true FROM unnest($9::uuid[]) AS seed(id)")
        .bind(c.tenant.to_string()).bind(version).bind(object.members[0].device.into_uuid())
        .bind(at).bind(at + 300).bind(serde_json::to_value(rss_mdm_task_state::RunState::new(at+300,at)?)?)
        .bind(vec![0u8;32]).bind(json!([object])).bind(ids).execute(&mut *tx).await?;
    assert_eq!(added.rows_affected(), ids.len() as u64);
    tx.commit().await?;
    Ok(())
}

async fn http(
    router: &axum::Router,
    path: &str,
    pairs: &[(&str, &str)],
) -> Result<(axum::http::StatusCode, Value)> {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().copied())
        .finish();
    let request = axum::http::Request::builder()
        .uri(format!("{path}?{query}"))
        .body(axum::body::Body::empty())?;
    let response = router.clone().oneshot(request).await?;
    let status = response.status();
    Ok((
        status,
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 65536).await?)?,
    ))
}

async fn plans(
    h: &Harness,
    device: Uuid,
    busy_device: Uuid,
    native_history: Uuid,
    after: Uuid,
) -> Result<()> {
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query(
        "ANALYZE mdm_script.runs, mdm_devices.control_operations, rss_device_command.commands",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query("SET LOCAL ROLE mdm_command_runtime")
        .execute(&mut *tx)
        .await?;
    let artifacts = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/local-t2/operation-plans");
    std::fs::create_dir_all(&artifacts)?;
    let at_limit = format!("sort=deadline&limit=1&filter=id!={}", Uuid::from_u128(4098));
    let deep_run = Position(vec![json!(after), json!("action_run")]);
    let deep_command = Position(vec![json!(Uuid::from_u128(1_000_250)), json!("command")]);
    let desc_cursor = Position(vec![json!(Uuid::from_u128(4096)), json!("action_run")]);
    let multi_cursor = Position(vec![json!(Uuid::from_u128(1)), json!("command")]);
    let business_scope = format!("filter=device=in=({device},{native_history})&limit=1");
    for (label, raw, device, position, budget, expected) in [
        ("desc-first", "sort=-id&limit=1", busy_device, None, None, 2),
        (
            "desc-next",
            "sort=-id&limit=1",
            busy_device,
            Some(&desc_cursor),
            None,
            2,
        ),
        ("multi-first", "limit=1", device, None, None, 2),
        (
            "multi-next",
            "limit=1",
            device,
            Some(&multi_cursor),
            None,
            2,
        ),
        (
            "multi-filter",
            business_scope.as_str(),
            device,
            None,
            None,
            2,
        ),
        ("first", "limit=1", device, None, None, 2),
        ("deep", "limit=1", device, Some(&deep_run), None, 2),
        (
            "native-deep",
            "limit=1",
            native_history,
            Some(&deep_command),
            None,
            2,
        ),
        ("statistics", "", device, None, Some(4), 4),
        ("deadline", at_limit.as_str(), busy_device, None, None, 2),
        (
            "deadline-over",
            "sort=deadline&limit=1",
            busy_device,
            None,
            None,
            0,
        ),
        ("wide-statistics", "", busy_device, None, Some(4097), 4097),
    ] {
        let query = SCHEMA.parse(raw)?;
        let allowed = match label {
            "multi-filter" => None,
            "multi-first" | "multi-next" => Some(vec![device, native_history]),
            _ => Some(vec![device]),
        };
        let scope = Scope::new(h.c.tenant.to_string(), allowed, &query);
        let mut sql = sqlx::QueryBuilder::new("EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT JSON) ");
        if let Some(budget) = budget {
            scope.totals(&mut sql, budget)?;
        } else {
            scope.page(&mut sql, position, 2)?;
        }
        let plan: Value = sql.build_query_scalar().fetch_one(&mut *tx).await?;
        std::fs::write(
            artifacts.join(format!("{label}.json")),
            serde_json::to_vec_pretty(&plan)?,
        )?;
        check_plan(label, &plan, expected);
        let expected_ids = match label {
            "desc-first" => Some([4098, 4097]),
            "desc-next" => Some([4095, 4094]),
            "multi-first" | "multi-filter" => Some([1, 8192]),
            "multi-next" => Some([8192, 16384]),
            _ => None,
        };
        if let Some(ids) = expected_ids {
            let mut sql = sqlx::QueryBuilder::new("");
            scope.page(&mut sql, position, 2)?;
            let documents: Vec<Value> = sql.build_query_scalar().fetch_all(&mut *tx).await?;
            assert_eq!(
                documents
                    .iter()
                    .map(|row| row["id"].clone())
                    .collect::<Vec<_>>(),
                ids.map(|i| json!(Uuid::from_u128(i))),
                "{label}"
            );
        }
    }
    tx.rollback().await?;
    Ok(())
}

fn check_plan(label: &str, plan: &Value, expected: u64) {
    let mut nodes = vec![&plan[0]["Plan"]];
    let mut selected = None;
    let mut sort_input = None;
    let mut script_rows = 0;
    let mut native_rows = 0;
    while let Some(node) = nodes.pop() {
        let rows = node["Actual Rows"].as_u64().unwrap();
        let loops = node["Actual Loops"].as_u64().unwrap();
        let examined = (rows + node["Rows Removed by Filter"].as_u64().unwrap_or(0)) * loops;
        match node["Subplan Name"].as_str() {
            Some("CTE selected") => selected = Some(rows * loops),
            Some("CTE sort_input") => sort_input = Some(rows * loops),
            _ => (),
        }
        match (node["Schema"].as_str(), node["Relation Name"].as_str()) {
            (Some("mdm_script"), Some("runs")) => script_rows += examined,
            (Some("mdm_devices"), Some("control_operations")) => native_rows += examined,
            _ => (),
        }
        nodes.extend(node["Plans"].as_array().into_iter().flatten());
    }
    assert_eq!(selected, Some(expected), "{label} scoped probe");
    match label {
        "deadline" => assert_eq!(sort_input, Some(4096)),
        "deadline-over" => assert_eq!(sort_input, Some(4097)),
        "wide-statistics" => assert!(script_rows >= 4097),
        "native-deep" => assert!(
            (1..64).contains(&native_rows),
            "{label} examined {native_rows} native rows"
        ),
        _ => {
            assert!(
                (1..128).contains(&script_rows),
                "{label} examined {script_rows} Script rows"
            );
            assert!(
                native_rows < 64,
                "{label} examined {native_rows} native rows"
            );
        }
    }
}
#[tokio::test]
#[ignore = "T2: scoped PostgreSQL scans, exact statistics, live keysets and candidate-only ownership"]
async fn scoped_pages_and_statistics_charge_only_eligible_history() -> Result<()> {
    let mut h = Harness::open().await?;
    let peer = Context::open("shared", &[]).await?;
    let result = verify(&mut h, &peer).await;
    peer.close().await;
    h.close().await?;
    result
}

#[expect(
    clippy::cognitive_complexity,
    reason = "exercise grant, filter, continuation and corrupt-identity boundaries against the same committed fixture"
)]
async fn verify(h: &mut Harness, peer: &Context) -> Result<()> {
    let (_, version) = h.policy("budget-script").await?;
    let hidden = h.object.clone();
    let native = super::super::retirement::native_controls(h, 1).await?;
    let command_id = Uuid::from_u128(1);
    let first = Uuid::from_u128(8192);
    let second = Uuid::from_u128(16384);
    let extra = Uuid::from_u128(32768);
    runs(&h.c, version, &h.object, &[first, second, extra]).await?;
    runs(
        &h.c,
        version,
        &hidden,
        &(2..4099).map(Uuid::from_u128).collect::<Vec<_>>(),
    )
    .await?;
    // A different tenant owns the same UUID as the visible native command.
    let other = planning::endpoint(peer).await?;
    let scope = planning::published(peer, &other).await?.scope;
    let (_, other_version) = Harness::script_policy(peer, scope, "budget-script", "system").await?;
    runs(peer, other_version, &other, &[command_id]).await?;

    let account = h.c.account(&[Permission::OperationRead]).await?;
    scope_account(&h.c, &account, native.device, 0).await?;
    let proof = Arc::new(h.c.authenticate(&account).await?);
    let operations = Arc::new(directory(
        h,
        Budgets {
            page: 3,
            statistics: 3,
        },
    ));
    let codec = CursorCodec::new(&[8; 32])?;
    let router = rss_mdm_management_http::execution::http::read_routes()
        .with_state::<()>(operations.clone())
        .layer(axum::Extension(codec.clone()))
        .layer(axum::Extension(h.c.read_auth(proof.clone())))
        .layer(axum::Extension(h.c.request(&proof)?))
        .into_axum();
    let router = axum::Router::new().nest("/api/v1/tenants/{tenant}", router);
    let path = format!("/api/v1/tenants/{}/operations", h.c.tenant);
    let stats_path = format!("{path}/statistics");
    let matching = format!(
        "id!={extra};((device=={};kind==command),authorization.state==not_applicable)",
        native.device
    );
    let filter = format!("id!={extra}");
    filtered_pages(
        &router,
        &path,
        [&filter, &matching],
        [first, second, command_id],
    )
    .await?;
    filtered_totals(
        &router,
        &path,
        hidden.members[0].device.into_uuid(),
        [first, second, extra],
    )
    .await?;
    // Unclassified lists stop at the first lookahead even if the eligible set is larger.
    assert_eq!(
        http(&router, &path, &[("limit", "1"), ("fields", "id")])
            .await?
            .0,
        axum::http::StatusCode::OK
    );
    let request = h.c.read_auth(proof.clone());
    let audit = h.c.request(&proof)?;
    over_budget(&operations, &request, &audit, &codec, &router, &stats_path).await?;
    let native_history =
        super::super::retirement::native_controls_in(h, 1_000_000..=1_000_255).await?;
    plans(
        h,
        native.device.into_uuid(),
        hidden.members[0].device.into_uuid(),
        native_history.device.into_uuid(),
        first,
    )
    .await?;

    sorted_budget(h, hidden.members[0].device).await?;
    independent_statistics(h, &hidden, version).await?;

    // A conflicting owner on a hidden device remains detectable even when the
    // query selects only commands, and even for an id-only response.
    runs(&h.c, version, &hidden, &[command_id]).await?;
    let q = SCHEMA.parse("filter=kind==command&fields=id&limit=1")?;
    assert!(matches!(
        operations.directory(&request, &q, &codec, &audit).await,
        Err(Error::Unavailable(Failure::CommandInvariant))
    ));
    let q = SCHEMA.statistics("filter=kind==command")?;
    assert!(matches!(
        operations.statistics(&request, &q, &audit).await,
        Err(Error::Unavailable(Failure::CommandInvariant))
    ));
    let classified = SCHEMA.statistics("filter=kind==command;authorization.state==authorized")?;
    assert!(matches!(
        operations.statistics(&request, &classified, &audit).await,
        Err(Error::Unavailable(Failure::CommandInvariant))
    ));
    let (status, page) = http(
        &router,
        &path,
        &[("filter", &format!("id=={first}")), ("fields", "id")],
    )
    .await?;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(page["items"], json!([{"id":first}]));
    Ok(())
}
async fn filtered_pages(
    router: &axum::Router,
    path: &str,
    expressions: [&str; 2],
    ids: [Uuid; 3],
) -> Result<()> {
    let stats_path = format!("{path}/statistics");
    let [first, second, command_id] = ids;
    for expression in expressions {
        let mut cursor = None::<String>;
        for expected in [first, second, command_id] {
            // Same non-null policy sorts by id, followed by the command's NULL policy.
            let mut pairs = vec![
                ("filter", expression),
                ("sort", "policy"),
                ("limit", "1"),
                ("fields", "id,kind"),
            ];
            if let Some(token) = cursor.as_deref() {
                pairs.push(("cursor", token));
            }
            let (status, page) = http(router, path, &pairs).await?;
            assert_eq!(status, axum::http::StatusCode::OK, "{page}");
            assert_eq!(page["items"].as_array().unwrap().len(), 1);
            assert_eq!(page["items"][0]["id"], json!(expected));
            cursor = page["nextCursor"].as_str().map(str::to_owned);
            assert_eq!(cursor.is_some(), expected != command_id);
        }
        let (status, totals) = http(router, &stats_path, &[("filter", expression)]).await?;
        assert_eq!(status, axum::http::StatusCode::OK, "{totals}");
        assert_eq!(
            totals["statistics"],
            json!({"total":3,"commands":1,"actionRuns":2,"unknown":0})
        );
    }
    Ok(())
}

async fn filtered_totals(
    router: &axum::Router,
    path: &str,
    hidden: Uuid,
    ids: [Uuid; 3],
) -> Result<()> {
    let [first, second, extra] = ids;
    let stats_path = format!("{path}/statistics");
    let classified_only = format!(
        "id!={extra};(device=={},authorization.state==not_applicable)",
        hidden
    );
    let (status, filtered) = http(
        router,
        path,
        &[("filter", &classified_only), ("fields", "id")],
    )
    .await?;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(filtered["items"], json!([{"id":first},{"id":second}]));
    let (status, filtered) = http(router, &stats_path, &[("filter", &classified_only)]).await?;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(
        filtered["statistics"],
        json!({"total":2,"commands":0,"actionRuns":2,"unknown":0})
    );
    Ok(())
}
async fn over_budget(
    operations: &Operations,
    request: &rss_mdm_authorization_service::context::RequestAuth,
    audit: &RequestAudit,
    codec: &CursorCodec,
    router: &axum::Router,
    stats_path: &str,
) -> Result<()> {
    for raw in ["", "filter=authorization.state==blocked"] {
        let q = SCHEMA.statistics(raw)?;
        assert!(matches!(
            operations.statistics(request, &q, audit).await,
            Err(Error::Unavailable(Failure::Capacity))
        ));
        assert_eq!(
            http(
                router,
                stats_path,
                &if raw.is_empty() {
                    vec![]
                } else {
                    vec![("filter", "authorization.state==blocked")]
                }
            )
            .await?
            .0,
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }
    let q = SCHEMA.parse("filter=authorization.state==blocked&limit=1&fields=id")?;
    assert!(matches!(
        operations.directory(request, &q, codec, audit).await,
        Err(Error::Unavailable(Failure::Capacity))
    ));
    Ok(())
}
fn directory(h: &Harness, budgets: Budgets) -> Operations {
    Operations {
        budgets,
        apple: Arc::new(rss_mdm_apple_channel::flow_store::Store {
            protection: h.a.resources.protection.clone(),
        }),
        tasks: h.a.task_reads.clone(),
        registration: h.a.registration.native.clone(),
        recovery: None,
        execution: h.a.service.clone(),
    }
}

async fn sorted_budget(h: &Harness, device: rss_mdm_agent_wire::DeviceId) -> Result<()> {
    let account = h.c.account(&[Permission::OperationRead]).await?;
    let proof = Arc::new(h.c.authenticate(&account).await?);
    let operations = directory(h, Default::default());
    let request = h.c.read_auth(proof.clone());
    let codec = CursorCodec::new(&[8; 32])?;
    let audit = h.c.request(&proof)?;
    let q = SCHEMA.parse(&format!(
        "sort=deadline&limit=1&fields=id&filter=device=={device}"
    ))?;
    assert!(matches!(
        operations.directory(&request, &q, &codec, &audit).await,
        Err(Error::Unavailable(Failure::Capacity))
    ));
    let last = Uuid::from_u128(4097);
    let q=SCHEMA.parse(&format!("sort=deadline&limit=1&fields=id&filter=device=={device};id!={};(id=={last},authorization.state==blocked)",Uuid::from_u128(4098)))?;
    let page = operations.directory(&request, &q, &codec, &audit).await?;
    assert_eq!(serde_json::to_value(page.items)?, json!([{"id":last}]));
    assert!(page.next_cursor.is_none());
    Ok(())
}

async fn independent_statistics(h: &Harness, busy: &DeviceObject, version: Uuid) -> Result<()> {
    let account = h.c.account(&[Permission::OperationRead]).await?;
    let proof = Arc::new(h.c.authenticate(&account).await?);
    let operations = Arc::new(directory(
        h,
        Budgets {
            page: 3,
            statistics: 4097,
        },
    ));
    let router = rss_mdm_management_http::execution::http::read_routes()
        .with_state::<()>(operations.clone())
        .layer(axum::Extension(CursorCodec::new(&[8; 32])?))
        .layer(axum::Extension(h.c.read_auth(proof.clone())))
        .layer(axum::Extension(h.c.request(&proof)?))
        .into_axum();
    let router = axum::Router::new().nest("/api/v1/tenants/{tenant}", router);
    let path = format!("/api/v1/tenants/{}/operations/statistics", h.c.tenant);
    // AllDevices with an OR whose device set is not finite. The id range selects
    // just the 4,097 busy-device runs, and still requires full classification.
    let mixed = format!(
        "id=ge={};id=le={};(device=={},authorization.state==not_applicable)",
        Uuid::from_u128(2),
        Uuid::from_u128(4098),
        Uuid::new_v4()
    );
    let expected = json!({"total":4097,"commands":0,"actionRuns":4097,"unknown":0});
    exact_totals(&router, &path, &mixed, &expected).await?;
    // Five explicit grants used to send classified statistics into the list sort fallback.
    scope_account(&h.c, &account, busy.members[0].device, 4).await?;
    let filter = "authorization.state==not_applicable";
    exact_totals(&router, &path, filter, &expected).await?;
    runs(&h.c, version, busy, &[Uuid::from_u128(4099)]).await?;
    let q = SCHEMA.statistics(&format!("filter={filter}"))?;
    assert!(matches!(
        operations
            .statistics(&h.c.read_auth(proof.clone()), &q, &h.c.request(&proof)?)
            .await,
        Err(Error::Unavailable(Failure::Capacity))
    ));
    assert_eq!(
        http(&router, &path, &[("filter", filter)]).await?.0,
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    Ok(())
}

async fn scope_account(
    c: &Context,
    account: &crate::authority_t2_support::Account,
    device: rss_mdm_agent_wire::DeviceId,
    extra: usize,
) -> Result<()> {
    use rss_mdm_authorization_service::{Grant, Rule, Scope as DeviceScope, Subject};
    let mut grants = vec![Grant {
        operation: Permission::OperationRead,
        scope: DeviceScope::Device { id: device },
    }];
    for _ in 0..extra {
        let endpoint = planning::endpoint(c).await?;
        grants.push(Grant {
            operation: Permission::OperationRead,
            scope: DeviceScope::Device {
                id: endpoint.members[0].device,
            },
        });
    }
    let rule = Rule {
        subject: Subject::User {
            user: account.user.clone(),
        },
        grants,
    };
    sqlx::query("UPDATE mdm_access.authorization_rules SET document=$3,revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string()).bind(account.rule).bind(serde_json::to_value(rule)?).execute(&c.operator).await?;
    Ok(())
}

async fn exact_totals(
    router: &axum::Router,
    path: &str,
    filter: &str,
    expected: &Value,
) -> Result<()> {
    let (status, body) = http(router, path, &[("filter", filter)]).await?;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(&body["statistics"], expected);
    Ok(())
}
