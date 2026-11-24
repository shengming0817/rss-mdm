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

async fn plans(h: &Harness, device: Uuid, busy_device: Uuid, after: Uuid) -> Result<()> {
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("ANALYZE mdm_script.runs")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL ROLE mdm_command_runtime")
        .execute(&mut *tx)
        .await?;
    let artifacts = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/local-t2/operation-plans");
    std::fs::create_dir_all(&artifacts)?;
    for label in ["first", "deep", "statistics", "deadline", "wide-statistics"] {
        let busy = matches!(label, "deadline" | "wide-statistics");
        let query = SCHEMA.parse(if label == "deadline" {
            "sort=deadline&limit=1"
        } else {
            "limit=1"
        })?;
        let scope = Scope::new(
            h.c.tenant.to_string(),
            Some(vec![if busy { busy_device } else { device }]),
            &query,
        );
        let mut sql = sqlx::QueryBuilder::new("EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT JSON) ");
        match label {
            "first" | "deadline" => scope.page(&mut sql, None, 2)?,
            "deep" => scope.page(
                &mut sql,
                Some(&Position(vec![json!(after), json!("action_run")])),
                2,
            )?,
            "wide-statistics" => scope.totals(&mut sql, 4096)?,
            _ => scope.totals(&mut sql, 4)?,
        }
        let plan: Value = sql.build_query_scalar().fetch_one(&mut *tx).await?;
        std::fs::write(
            artifacts.join(format!("{label}.json")),
            serde_json::to_vec_pretty(&plan)?,
        )?;
        let (selected, script_rows) = plan_rows(&plan);
        let expected = match label {
            "statistics" => 4,
            "wide-statistics" => 4096,
            _ => 2,
        };
        assert_eq!(selected, Some(expected), "{label} scoped probe");
        eprintln!("operations {label}: selected={expected} run table rows examined={script_rows}");
        assert!(
            script_rows > 0 && (busy || script_rows < 128),
            "{label} examined {script_rows} run rows with 4096 unrelated rows"
        );
    }
    tx.rollback().await?;
    Ok(())
}

fn plan_rows(plan: &Value) -> (Option<u64>, u64) {
    let mut nodes = vec![&plan[0]["Plan"]];
    let mut selected = None;
    let mut script_rows = 0;
    while let Some(node) = nodes.pop() {
        let actual = node["Actual Rows"].as_u64().unwrap();
        let loops = node["Actual Loops"].as_u64().unwrap();
        if node["Subplan Name"] == "CTE selected" {
            selected = Some(actual * loops);
        }
        if node["Relation Name"] == "runs" && node["Schema"] == "mdm_script" {
            script_rows += loops * (actual + node["Rows Removed by Filter"].as_u64().unwrap_or(0));
        }
        nodes.extend(node["Plans"].as_array().into_iter().flatten());
    }
    (selected, script_rows)
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
        &(2..4098).map(Uuid::from_u128).collect::<Vec<_>>(),
    )
    .await?;
    // A different tenant owns the same UUID as the visible native command.
    let other = planning::endpoint(peer).await?;
    let scope = planning::published(peer, &other).await?.scope;
    let (_, other_version) = Harness::script_policy(peer, scope, "budget-script", "system").await?;
    runs(peer, other_version, &other, &[command_id]).await?;

    let account = h.c.account(&[Permission::OperationRead]).await?;
    let rule = rss_mdm_authorization_service::Rule {
        subject: rss_mdm_authorization_service::Subject::User {
            user: account.user.clone(),
        },
        grants: vec![rss_mdm_authorization_service::Grant {
            operation: Permission::OperationRead,
            scope: rss_mdm_authorization_service::Scope::Device { id: native.device },
        }],
    };
    sqlx::query("UPDATE mdm_access.authorization_rules SET document=$3,revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2")
            .bind(h.c.tenant.to_string()).bind(account.rule).bind(serde_json::to_value(rule)?).execute(&h.c.operator).await?;
    let proof = Arc::new(h.c.authenticate(&account).await?);
    let operations = Arc::new(Operations {
        budgets: Budgets {
            page: 3,
            statistics: 3,
        },
        apple: Arc::new(rss_mdm_apple_channel::flow_store::Store {
            protection: h.a.resources.protection.clone(),
        }),
        tasks: h.a.task_reads.clone(),
        registration: h.a.registration.native.clone(),
        recovery: None,
        execution: h.a.service.clone(),
    });
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
    plans(
        h,
        native.device.into_uuid(),
        hidden.members[0].device.into_uuid(),
        first,
    )
    .await?;

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
