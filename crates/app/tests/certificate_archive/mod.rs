//! Real HTTP, Identity, PostgreSQL isolation and encrypted history recovery.
use crate::test_support::*;
use rss_mdm_authorization_service::{Grant, Permission, Scope};
use rss_mdm_certificate_archive_service::{Archive, Clock, Error};
use sqlx::Acquire;
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;
struct TestClock {
    start: std::time::Instant,
    elapsed: AtomicU64,
}
impl Clock for TestClock {
    fn now(&self) -> std::time::Instant {
        self.start + Duration::from_secs(self.elapsed.load(Ordering::SeqCst))
    }
    fn unix_seconds(&self) -> std::result::Result<i64, Error> {
        Ok(1_790_000_000 + self.elapsed.load(Ordering::SeqCst) as i64)
    }
}
struct Fixture {
    authority: authority::Authority,
    archive: Arc<Archive>,
    clock: Arc<TestClock>,
    router: Router,
    admin: Browser,
    subject: String,
}
impl Fixture {
    async fn open() -> Result<Self> {
        let authority = authority::Authority::open().await?;
        let clock = Arc::new(TestClock {
            start: rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer),
            elapsed: AtomicU64::new(0),
        });
        let archive = Arc::new(Archive::new(
            authority.access.archive_pool(),
            authority.audit.clone(),
            clock.clone(),
        ));
        let router = Self::routes(&authority, archive.clone())?;
        let admin = authority.browser("admin")?;
        let subject = browser_subject(&admin, &router).await?;
        identity::set_grants(
            case_tenant(),
            &subject,
            [
                Permission::CertificateArchiveRead,
                Permission::CertificateArchiveWrite,
                Permission::CertificateArchiveUnlock,
                Permission::CertificateArchiveExport,
            ]
            .into_iter()
            .map(|operation| Grant {
                operation,
                scope: Scope::Tenant,
            })
            .collect(),
        )
        .await?;
        Ok(Self {
            authority,
            archive,
            clock,
            router,
            admin,
            subject,
        })
    }
    fn routes(authority: &authority::Authority, archive: Arc<Archive>) -> Result<Router> {
        authority.router(
            Router::new()
                .nest(
                    "/api/v1",
                    rss_mdm_management_http::certificate_archive::routes().with_state(archive),
                )
                .merge(authority.authorization()),
        )
    }
    async fn call(
        &mut self,
        method: Method,
        path: &str,
        value: Option<Value>,
    ) -> Result<(StatusCode, Value)> {
        self.admin
            .call(
                &self.router,
                method,
                &format!("/api/v1/certificate-archive{path}"),
                value,
            )
            .await
    }
    async fn ok(&mut self, method: Method, path: &str, value: Option<Value>) -> Result<Value> {
        let (status, result) = self.call(method, path, value).await?;
        ensure!(
            status == StatusCode::OK,
            "archive {path}: {status} {}",
            result.get("code").unwrap_or(&Value::Null)
        );
        Ok(result)
    }
    async fn write(&mut self, path: &str, value: Value) -> Result<Value> {
        self.admin.operation = Some(Uuid::new_v4());
        self.ok(Method::POST, path, Some(value)).await
    }
    async fn initialize(&mut self) -> Result<()> {
        self.write(
            "/vault/initialize",
            json!({"password":"first archive password"}),
        )
        .await?;
        self.ok(
            Method::POST,
            "/vault/unlock",
            Some(json!({"password":"first archive password"})),
        )
        .await?;
        Ok(())
    }
}
fn metadata(name: &str) -> Value {
    json!({"name":name,"category":"custom","labels":["fixture"],"usages":["manual"],"owner":"operator","notes":""})
}
fn import(entry: Uuid, revision: i64, contents: &str) -> Value {
    use base64::Engine;
    json!({"entryId":entry,"expectedRevision":revision,"metadata":metadata("historic"),"requestVersion":null,"files":[{"name":"source.bin","format":"opaque","data":base64::engine::general_purpose::STANDARD.encode(contents),"password":null}]})
}
#[tokio::test]
#[ignore = "make t2 MODULE=certificate-archive.http"]
async fn real_http_preserves_history_rewraps_and_restarts_locked() -> Result<()> {
    let mut f = Fixture::open().await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let router = f.router.clone();
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let _server = planning_http::Server(server);
    f.admin.network = Some((
        Client::builder().no_proxy().build()?,
        format!("http://{address}"),
    ));
    f.initialize().await?;
    let entry = Uuid::new_v4();
    let operation = Uuid::new_v4();
    f.admin.operation = Some(operation);
    f.authority
        .audit
        .inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
    ensure!(
        f.call(
            Method::POST,
            "/import",
            Some(import(entry, 0, "first original material"))
        )
        .await?
        .0 == StatusCode::SERVICE_UNAVAILABLE
    );
    let first = f
        .ok(Method::GET, &format!("/operations/{operation}"), None)
        .await?;
    ensure!(first["version"] == 1);
    let same = f
        .ok(
            Method::POST,
            "/import",
            Some(import(entry, 0, "first original material")),
        )
        .await?;
    ensure!(first == same);
    ensure!(
        f.call(Method::POST, "/import", Some(import(entry, 0, "different")))
            .await?
            .0
            == StatusCode::CONFLICT
    );
    f.write("/import", import(entry, 1, "second original material"))
        .await?;
    f.admin.operation = Some(Uuid::new_v4());
    f.ok(
        Method::PUT,
        &format!("/entries/{entry}/metadata"),
        Some(json!({"expectedRevision":2,"metadata":metadata("new metadata")})),
    )
    .await?;
    let history = f
        .ok(Method::GET, &format!("/entries/{entry}/versions"), None)
        .await?;
    ensure!(history.as_array().unwrap().len() == 3);
    ensure!(history[2]["metadata"]["name"] == "historic");
    let opaque = pg(&format!(
        "SELECT position(convert_to('first original material','UTF8') in sealed)=0 FROM mdm_certificate_archive.versions WHERE tenant_id='{}' AND entry_id='{entry}' AND version=1",
        case_tenant()
    ))?;
    ensure!(opaque.trim() == "t");
    let change = Uuid::new_v4();
    f.admin.operation = Some(change);
    let body =
        json!({"oldPassword":"first archive password","newPassword":"second archive password"});
    let changed = f
        .ok(Method::POST, "/vault/password", Some(body.clone()))
        .await?;
    ensure!(f.ok(Method::POST, "/vault/password", Some(body)).await? == changed);
    ensure!(f.ok(Method::GET, "/vault", None).await?["unlockedUntil"].is_null());
    ensure!(
        f.call(
            Method::POST,
            "/vault/unlock",
            Some(json!({"password":"first archive password"}))
        )
        .await?
        .0 == StatusCode::FORBIDDEN
    );
    f.ok(
        Method::POST,
        "/vault/unlock",
        Some(json!({"password":"second archive password"})),
    )
    .await?;
    let exported = f
        .write("/export", json!({"entryId":entry,"version":1}))
        .await?;
    use base64::Engine;
    ensure!(
        base64::engine::general_purpose::STANDARD
            .decode(exported["files"][0]["data"].as_str().unwrap())?
            == b"first original material"
    );
    f.admin.network = None;
    let restarted = Arc::new(Archive::new(
        f.authority.access.archive_pool(),
        f.authority.audit.clone(),
        f.clock.clone(),
    ));
    f.router = Fixture::routes(&f.authority, restarted)?;
    ensure!(f.ok(Method::GET, "/vault", None).await?["unlockedUntil"].is_null());
    ensure!(
        f.call(
            Method::POST,
            "/export",
            Some(json!({"entryId":entry,"version":1}))
        )
        .await?
        .0 == StatusCode::LOCKED
    );
    f.ok(
        Method::POST,
        "/vault/unlock",
        Some(json!({"password":"second archive password"})),
    )
    .await?;
    f.write("/export", json!({"entryId":entry,"version":1}))
        .await?;
    f.clock.elapsed.store(901, Ordering::SeqCst);
    ensure!(f.ok(Method::GET, "/vault", None).await?["unlockedUntil"].is_null());
    ensure!(
        f.call(
            Method::POST,
            "/export",
            Some(json!({"entryId":entry,"version":1}))
        )
        .await?
        .0 == StatusCode::LOCKED
    );
    Ok(())
}
#[tokio::test]
#[ignore = "make t2 MODULE=certificate-archive.http"]
async fn permissions_rls_immutable_versions_and_tampering_are_enforced() -> Result<()> {
    let mut f = Fixture::open().await?;
    f.initialize().await?;
    let entry = Uuid::new_v4();
    f.write("/import", import(entry, 0, "protected data"))
        .await?;
    let mut other = f.authority.browser("other")?;
    let denied = other
        .call(
            &f.router,
            Method::GET,
            "/api/v1/certificate-archive/entries",
            None,
        )
        .await?;
    ensure!(denied.0 == StatusCode::FORBIDDEN);
    identity::set_grants(
        case_tenant(),
        &f.subject,
        vec![Grant {
            operation: Permission::CertificateArchiveRead,
            scope: Scope::Tenant,
        }],
    )
    .await?;
    ensure!(
        f.call(
            Method::POST,
            "/export",
            Some(json!({"entryId":entry,"version":1}))
        )
        .await?
        .0 == StatusCode::FORBIDDEN
    );
    let mut connection = f.authority.access.archive_pool().acquire().await?;
    let mut tx = connection.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case::peer())
        .execute(&mut *tx)
        .await?;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_certificate_archive.versions")
        .fetch_one(&mut *tx)
        .await?;
    ensure!(n == 0);
    tx.rollback().await?;
    let mut tx = connection.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    ensure!(
        sqlx::query("DELETE FROM mdm_certificate_archive.versions")
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await?;
    let mut tx = connection.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    ensure!(
        sqlx::query("UPDATE mdm_certificate_archive.versions SET metadata='{}'")
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await?;
    drop(connection);
    identity::set_grants(
        case_tenant(),
        &f.subject,
        [
            Permission::CertificateArchiveRead,
            Permission::CertificateArchiveUnlock,
            Permission::CertificateArchiveExport,
        ]
        .into_iter()
        .map(|operation| Grant {
            operation,
            scope: Scope::Tenant,
        })
        .collect(),
    )
    .await?;
    pg(&format!(
        "UPDATE mdm_certificate_archive.versions SET sealed=set_byte(sealed,octet_length(sealed)-1,get_byte(sealed,octet_length(sealed)-1)#1) WHERE tenant_id='{}' AND entry_id='{entry}'",
        case_tenant()
    ))?;
    ensure!(
        f.call(
            Method::POST,
            "/export",
            Some(json!({"entryId":entry,"version":1}))
        )
        .await?
        .0 == StatusCode::INTERNAL_SERVER_ERROR
    );
    let (_, v) = f.call(Method::GET, "/entries", None).await?;
    ensure!(v["items"].as_array().unwrap().len() == 1);
    Ok(())
}
#[tokio::test]
#[ignore = "make t2 MODULE=certificate-archive.http"]
async fn generation_alerts_and_two_sessions_use_one_tenant_identity() -> Result<()> {
    let mut f = Fixture::open().await?;
    f.initialize().await?;
    let mut other = f.authority.browser("other")?;
    let subject = browser_subject(&other, &f.router).await?;
    identity::set_grants(
        case_tenant(),
        &subject,
        [
            Permission::CertificateArchiveRead,
            Permission::CertificateArchiveUnlock,
            Permission::CertificateArchiveExport,
        ]
        .into_iter()
        .map(|operation| Grant {
            operation,
            scope: Scope::Tenant,
        })
        .collect(),
    )
    .await?;
    ensure!(
        other
            .call(
                &f.router,
                Method::GET,
                "/api/v1/certificate-archive/vault",
                None
            )
            .await?
            .1["unlockedUntil"]
            .is_null()
    );
    let ca = Uuid::new_v4();
    let mut input = json!({"entryId":ca,"expectedRevision":0,"metadata":metadata("CA"),"profile":"ca","algorithm":"rsa2048","commonName":"Archive Test CA","organization":"Test","sans":[],"days":3650,"issuer":null,"scepUrl":null});
    f.write("/generate", input.clone()).await?;
    let leaf = Uuid::new_v4();
    input["entryId"] = json!(leaf);
    input["metadata"] = metadata("HTTPS");
    input["profile"] = json!("https");
    input["commonName"] = json!("test.example");
    input["sans"] = json!(["test.example"]);
    input["days"] = json!(20);
    input["issuer"] = json!({"entryId":ca,"version":1});
    f.write("/generate", input).await?;
    let page = f.ok(Method::GET, "/entries", None).await?;
    ensure!(page["alerts"]["expiring"] == 1);
    f.clock.elapsed.store(21 * 86400, Ordering::SeqCst);
    let page = f.ok(Method::GET, "/entries", None).await?;
    ensure!(page["alerts"]["expired"] == 1);
    ensure!(
        f.ok(Method::GET, "/entries", None).await?["items"]
            .as_array()
            .unwrap()
            .len()
            == 2
    );
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=certificate-archive.http"]
async fn issued_results_keep_exact_request_versions_and_pem_work_drains() -> Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut f = Fixture::open().await?;
    f.initialize().await?;
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(10))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let startup = owner.startup()?;
    let mut launch = startup.commit();
    launch.stage_task_with_token(f.archive.clone().registration());
    launch.finish();
    let request = Uuid::new_v4();
    f.write("/generate", json!({"entryId":request,"expectedRevision":0,"metadata":metadata("request"),"profile":"csr","algorithm":"p256","commonName":"issued.example","organization":"Test","sans":[],"days":0,"issuer":null,"scepUrl":null})).await?;
    let exported = f
        .write("/export", json!({"entryId":request,"version":1}))
        .await?;
    let files = exported["files"].as_array().unwrap();
    let csr = files.iter().find(|v| v["name"] == "request.csr").unwrap();
    let key = files
        .iter()
        .find(|v| v["name"].as_str().unwrap().ends_with(".pk8"))
        .unwrap();
    let work = tempfile::tempdir()?;
    std::fs::write(
        work.path().join("request.pem"),
        STANDARD.decode(csr["data"].as_str().unwrap())?,
    )?;
    std::fs::write(
        work.path().join("key.der"),
        STANDARD.decode(key["data"].as_str().unwrap())?,
    )?;
    let signed = tokio::process::Command::new("openssl")
        .current_dir(work.path())
        .args([
            "x509",
            "-req",
            "-in",
            "request.pem",
            "-signkey",
            "key.der",
            "-keyform",
            "DER",
            "-days",
            "30",
            "-set_serial",
            "1",
            "-out",
            "certificate.pem",
        ])
        .output()
        .await?;
    ensure!(
        signed.status.success(),
        "fixture certificate signing failed"
    );
    let encrypted = tokio::process::Command::new("openssl")
        .current_dir(work.path())
        .args([
            "pkey",
            "-inform",
            "DER",
            "-in",
            "key.der",
            "-aes-256-cbc",
            "-passout",
            "pass:fixture",
            "-out",
            "encrypted.pem",
        ])
        .output()
        .await?;
    ensure!(encrypted.status.success(), "fixture key encryption failed");
    let mut pem = import(Uuid::new_v4(), 0, "");
    pem["files"][0]["format"] = json!("private_key");
    pem["files"][0]["data"] =
        json!(STANDARD.encode(std::fs::read(work.path().join("encrypted.pem"))?));
    // More failures than the worker capacity must release every permit.
    for _ in 0..3 {
        f.admin.operation = Some(Uuid::new_v4());
        let (status, body) = tokio::time::timeout(
            Duration::from_secs(2),
            f.call(Method::POST, "/import", Some(pem.clone())),
        )
        .await??;
        ensure!(status == StatusCode::BAD_REQUEST);
        ensure!(body["code"] == "archive_material_invalid");
    }
    pem["files"][0]["password"] = json!("fixture");
    f.write("/import", pem).await?;
    // A second request entry and a newer version have the same public key.
    let duplicate = Uuid::new_v4();
    let mut copy = import(duplicate, 0, "");
    copy["files"] =
        json!([{"name":"request.pem","format":"csr","data":csr["data"],"password":null}]);
    f.write("/import", copy).await?;
    f.admin.operation = Some(Uuid::new_v4());
    f.ok(
        Method::PUT,
        &format!("/entries/{request}/metadata"),
        Some(json!({"expectedRevision":1,"metadata":metadata("new request description")})),
    )
    .await?;
    let result = Uuid::new_v4();
    let original_ref = json!({"entryId":request,"version":1});
    let duplicate_ref = json!({"entryId":duplicate,"version":1});
    let mut issued = import(result, 0, "");
    issued["requestVersion"] = original_ref.clone();
    issued["files"] = json!([{"name":"certificate.pem","format":"certificate","data":STANDARD.encode(std::fs::read(work.path().join("certificate.pem"))?),"password":null}]);
    f.write("/import", issued.clone()).await?;
    issued["expectedRevision"] = json!(1);
    issued["requestVersion"] = duplicate_ref.clone();
    f.write("/import", issued).await?;
    f.admin.operation = Some(Uuid::new_v4());
    f.ok(
        Method::PUT,
        &format!("/entries/{result}/metadata"),
        Some(json!({"expectedRevision":2,"metadata":metadata("issued result")})),
    )
    .await?;
    ensure!(owner.shutdown().join().await?.is_clean());
    let restarted = Arc::new(Archive::new(
        f.authority.access.archive_pool(),
        f.authority.audit.clone(),
        f.clock.clone(),
    ));
    f.router = Fixture::routes(&f.authority, restarted)?;
    let history = f
        .ok(Method::GET, &format!("/entries/{result}/versions"), None)
        .await?;
    ensure!(history[2]["requestVersion"] == original_ref);
    ensure!(history[1]["requestVersion"] == duplicate_ref);
    ensure!(history[0]["requestVersion"] == duplicate_ref);
    let page = f.ok(Method::GET, "/entries", None).await?;
    let latest = &page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == json!(result))
        .unwrap()["latest"];
    ensure!(latest["requestVersion"] == duplicate_ref);
    let history = f
        .ok(Method::GET, &format!("/entries/{request}/versions"), None)
        .await?;
    ensure!(
        history
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["requestVersion"].is_null())
    );
    Ok(())
}

async fn wait_for_archive_locks(blocker: i32, count: usize) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let n = pg(&format!("WITH RECURSIVE blocked(pid) AS (SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND {blocker}=ANY(pg_blocking_pids(pid)) UNION SELECT a.pid FROM pg_stat_activity a JOIN blocked b ON b.pid=ANY(pg_blocking_pids(a.pid)) WHERE a.datname=current_database()) SELECT count(*) FROM blocked"))?;
            if n.trim().parse::<usize>()? >= count {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await??;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=certificate-archive.http"]
async fn replayed_export_rechecks_generation_after_peer_password_change() -> Result<()> {
    let mut f = Fixture::open().await?;
    f.initialize().await?;
    let entry = Uuid::new_v4();
    f.write("/import", import(entry, 0, "private historic material"))
        .await?;
    let operation = Uuid::new_v4();
    f.admin.operation = Some(operation);
    f.ok(
        Method::POST,
        "/export",
        Some(json!({"entryId":entry,"version":1})),
    )
    .await?;
    let peer_access = database(&f.authority.base).await?;
    let config: Config = serde_json::from_value(f.authority.base.clone())?;
    let peer = Arc::new(Archive::new(
        peer_access.archive_pool(),
        peer_access.audit_store(&config.audit).await?,
        f.clock.clone(),
    ));
    let peer_router = Fixture::routes(&f.authority, peer)?;
    let mut peer_browser = f.authority.browser("admin")?;
    ensure!(browser_subject(&peer_browser, &peer_router).await? == f.subject);
    peer_browser.operation = Some(Uuid::new_v4());
    // Queue the password writer first at the tenant lock. It holds the authorization
    // lock, so the old-instance export prepares plaintext then waits behind it.
    let mut blocker = f.authority.access.archive_pool().begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2641))")
        .bind(case_tenant())
        .execute(&mut *blocker)
        .await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    let change = tokio::spawn(async move {
        peer_browser.call(&peer_router, Method::POST, "/api/v1/certificate-archive/vault/password", Some(json!({"oldPassword":"first archive password","newPassword":"second archive password"}))).await
    });
    wait_for_archive_locks(blocker_pid, 1).await?;
    let router = f.router.clone();
    let mut browser = f.admin;
    let replay = tokio::spawn(async move {
        browser
            .call(
                &router,
                Method::POST,
                "/api/v1/certificate-archive/export",
                Some(json!({"entryId":entry,"version":1})),
            )
            .await
    });
    wait_for_archive_locks(blocker_pid, 2).await?;
    blocker.rollback().await?;
    ensure!(change.await??.0 == StatusCode::OK);
    let (status, body) = replay.await??;
    ensure!(status == StatusCode::LOCKED);
    ensure!(body.get("files").is_none());
    Ok(())
}
