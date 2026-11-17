//! The real installation owner observes a running App, rotates, and restores quiesced state.
use super::*;
use crate::installation::{backup, configure, install, protection, runtime_files};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    },
};

pub(super) struct Gateway {
    pub address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Gateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct Listener {
    tcp: tokio::net::TcpListener,
    tls: TlsAcceptor,
}
impl axum::serve::Listener for Listener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, peer) = self.tcp.accept().await.unwrap();
            if let Ok(Ok(stream)) =
                tokio::time::timeout(Duration::from_secs(5), self.tls.accept(stream)).await
            {
                return (stream, peer);
            }
        }
    }
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.tcp.local_addr()
    }
}
impl Gateway {
    pub async fn open(backend: SocketAddr, certificate: &Path, key: &Path) -> Result<Self> {
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from_pem_file(certificate)?],
                PrivateKeyDer::from_pem_file(key)?,
            )?;
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = tcp.local_addr()?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(8))
            .build()?;
        let router = axum::Router::new().route(
            "/readyz",
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let client = client.clone();
                async move {
                    use axum::response::IntoResponse;
                    let host = headers
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("mdm.example.test");
                    let response = client
                        .get(format!("http://{backend}/readyz"))
                        .header("host", host)
                        .header("x-rss-public-origin", format!("https://{host}"))
                        .header("x-forwarded-for", "127.0.0.1")
                        .send()
                        .await;
                    match response {
                        Ok(response) => (
                            response.status(),
                            response.bytes().await.unwrap_or_default(),
                        )
                            .into_response(),
                        Err(_) => axum::http::StatusCode::BAD_GATEWAY.into_response(),
                    }
                }
            }),
        );
        let task = tokio::spawn(async move {
            axum::serve(
                Listener {
                    tcp,
                    tls: TlsAcceptor::from(Arc::new(tls)),
                },
                router,
            )
            .await
            .unwrap();
        });
        Ok(Self { address, task })
    }
}
struct Running {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::result::Result<(), crate::ProcessError>>,
}
impl Drop for Running {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
impl Running {
    #[allow(
        clippy::disallowed_methods,
        reason = "integration supplies the production monotonic clock"
    )]
    async fn open(runtime: &Value) -> Result<Self> {
        let config: crate::config::Config = serde_json::from_value(runtime.clone())?;
        let address = config.listen;
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(crate::serve(
            config,
            async move {
                stopped
                    .await
                    .map_err(|_| std::io::Error::other("test shutdown"))
            },
            Arc::new(crate::Monotonic(std::time::Instant::now)),
        ));
        let mut running = Self {
            stop: Some(stop),
            task,
        };
        let client = reqwest::Client::builder().no_proxy().build()?;
        let ready_url = format!("http://{address}/readyz");
        tokio::select! {
            result = &mut running.task => anyhow::bail!("maintenance App exited: {result:?}"),
            ready = tokio::time::timeout(Duration::from_secs(90), super::super::ready(&client, &ready_url)) => { ready??; }
        }
        Ok(running)
    }
    async fn close(mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        tokio::time::timeout(Duration::from_secs(70), &mut self.task).await???;
        Ok(())
    }
}
fn desired(root: &Path, host: Uuid) -> Result<Value> {
    Ok(serde_json::from_slice(&std::fs::read(
        root.join("installation")
            .join(format!("rss-mdm-{}", host.simple()))
            .join("requested-runtime.json"),
    )?)?)
}
fn input(value: &Value) -> Result<install::Input> {
    Ok(serde_json::from_value(value.clone())?)
}
async fn capture(root: &Path, source: &Value, name: &str) -> Result<backup::Receipt> {
    let telemetry = serde_json::from_slice(&std::fs::read(
        root.join("installation/telemetry-request.json"),
    )?)?;
    Ok(backup::capture(backup::Request {
        installation: input(source)?,
        operation_id: Uuid::new_v4(),
        directory: root.join(name),
        authorities: vec![],
        telemetry: vec![telemetry],
    })
    .await?)
}

pub(super) async fn exercise(
    root: &Path,
    source: &Value,
    first: &install::Receipt,
    management: &str,
) -> Result<()> {
    // The ordinary initial installation must already be cold-backup eligible.
    let initial = capture(root, source, "initial-backup").await?;
    ensure!(
        initial.stage == backup::Stage::Complete,
        "initial cold backup"
    );
    let original = desired(root, first.host_id)?;
    let mut running = Running::open(&original).await?;
    // A real configuration operation changes the full input/binding before key rotation.
    let operation = Uuid::new_v4();
    let change = json!({"installation":source,"operation_id":operation,"tenant":null,
        "expected_revision":original["runtime_binding"]["revision"],"change":{"kind":"enrollment_entries","settings":{"windows":null,"macos":"https://mdm.example.test/enroll"}}});
    let pending = configure::run(serde_json::from_value(change.clone())?).await?;
    ensure!(
        pending.deployment_required && pending.applied.is_none(),
        "desired is not applied"
    );
    ensure!(
        capture(root, source, "unapplied-backup").await.is_err(),
        "pending desired cannot enter cold backup"
    );
    running.close().await?;
    running = Running::open(&desired(root, first.host_id)?).await?;
    let applied = configure::run(serde_json::from_value(change)?).await?;
    ensure!(
        applied.applied.is_some(),
        "configuration observed through actual App"
    );
    let configured = desired(root, first.host_id)?;
    ensure!(
        configured["enrollment_entries"]["macos"] == "https://mdm.example.test/enroll",
        "configuration is retained in the current input"
    );
    // Install each optional key owner through the ordinary configuration command.
    for change in [
        json!({"kind":"oidc","settings":{"group_facts_max_age_seconds":300,"return_targets":{},"assurance_profiles":[],"private_providers":[]}}),
        json!({"kind":"recovery","profile":"mdm","recipient":{"kind":"generate"}}),
        json!({"kind":"channels","settings":{"windows":{"entra":null,"enrollment":{"origin":"https://mdm.example.test"},"management":{"origin":"https://mdm.example.test"},"protocol_protection":null,"provider_id":"RSS-MDM","poll":{"interval_for_first_set_of_retries":15,"number_of_first_retries":0,"interval_for_second_set_of_retries":0,"number_of_second_retries":0,"interval_for_remaining_scheduled_retries":0,"number_of_remaining_scheduled_retries":0,"poll_on_login":true,"all_users_poll_on_first_login":false},"additional_management":[]},"apple":null,"agent":{"mode":"disabled"},"providers":[],"apple_material_roots":[]}}),
    ] {
        let runtime = desired(root, first.host_id)?;
        let request = json!({"installation":source,"operation_id":Uuid::new_v4(),"tenant":first.tenant_id,"expected_revision":runtime["runtime_binding"]["revision"],"change":change});
        let pending = configure::run(serde_json::from_value(request.clone())?).await?;
        ensure!(
            pending.deployment_required && pending.applied.is_none(),
            "material change awaits deployment"
        );
        running.close().await?;
        running = Running::open(&desired(root, first.host_id)?).await?;
        ensure!(
            configure::run(serde_json::from_value(request)?)
                .await?
                .applied
                .is_some(),
            "material configuration observed"
        );
    }
    for (purpose, path) in [
        (
            protection::Purpose::Native,
            "/native_protection/active_file",
        ),
        (
            protection::Purpose::Windows,
            "/native_protocols/windows/protocol_protection/active_file",
        ),
        (
            protection::Purpose::OidcCredentials,
            "/identity/oidc/active_credential_key",
        ),
        (
            protection::Purpose::Recovery,
            "/recovery_credentials/active_key",
        ),
    ] {
        let before = desired(root, first.host_id)?;
        let rotation = Uuid::new_v4();
        let request = || protection::Request {
            installation: input(source).unwrap(),
            purpose,
            operation_id: rotation,
        };
        let distributed = protection::rotate(request()).await?;
        ensure!(
            distributed.phase == protection::Phase::Distributing,
            "old process does not acknowledge read phase"
        );
        let read = desired(root, first.host_id)?;
        ensure!(
            read.pointer(path) == before.pointer(path),
            "read phase keeps original writer"
        );
        running.close().await?;
        running = Running::open(&read).await?;
        ensure!(
            protection::rotate(request()).await?.phase == protection::Phase::Activating,
            "write phase awaits a new process"
        );
        let write = desired(root, first.host_id)?;
        ensure!(
            write.pointer(path) != before.pointer(path),
            "write phase selects the new key"
        );
        running.close().await?;
        running = Running::open(&write).await?;
        let mut finished = protection::rotate(request()).await?;
        for _ in 0..8 {
            if finished.phase == protection::Phase::Complete {
                break;
            }
            finished = protection::rotate(request()).await?;
        }
        ensure!(
            finished.phase == protection::Phase::Complete,
            "rotation settles original work"
        );
        ensure!(
            protection::rotate(request()).await?.key_id == finished.key_id,
            "rotation replay preserves key"
        );
        let marker: Option<Uuid> = serde_json::from_slice(&std::fs::read(
            root.join("installation/protection-operation.json"),
        )?)?;
        ensure!(marker.is_none(), "rotation releases maintenance marker");
    }
    let write = desired(root, first.host_id)?;
    ensure!(
        write["enrollment_entries"] == configured["enrollment_entries"],
        "all rotations preserve prior configuration"
    );
    let mut browser = Browser::new(source["listen"].as_str().context("listen")?.parse()?)?;
    browser
        .login(management, "platform", "Installation-platform-admin!42")
        .await?;
    let administrator = input(source)?.database.administrator;
    let mut database = administrator.clone();
    database.name = source["database"]["name"].as_str().unwrap().into();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with(database.options()?)
        .await?;
    let mut pending = Vec::new();
    let mut running = Some(running);
    // Inject at real transaction boundaries; never fabricate the pending tenant or account.
    for (stage, table, condition) in [
        (
            "reserved",
            "public.mdm_tenants",
            "NEW.used AND NOT OLD.used",
        ),
        (
            "used",
            "public.mdm_tenant_operations",
            "NEW.action='administrator_create'",
        ),
        ("account", "mdm_initialization.baselines", "true"),
    ] {
        let operation = Uuid::new_v4();
        let event = if stage == "used" { "INSERT" } else { "UPDATE" };
        let sql = format!(
            "CREATE FUNCTION public.maintenance_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF {condition} THEN RAISE EXCEPTION 'maintenance boundary'; END IF; RETURN NEW; END $$; CREATE TRIGGER maintenance_fault BEFORE {event} ON {table} FOR EACH ROW EXECUTE FUNCTION public.maintenance_fault()"
        );
        sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
            .execute(&pool)
            .await?;
        let body = json!({"name":format!("Pending {stage}"),"administratorLogin":"administrator","administratorPassword":"Pending-installation-admin!42"});
        let _ = browser
            .call(
                Method::POST,
                "/api/v1/tenant-administration/provisionings",
                Some(body.clone()),
                Some(operation),
            )
            .await;
        let row: (Uuid, Value, Value) = sqlx::query_as("SELECT tenant_id,request,receipt FROM public.mdm_tenant_operations WHERE operation_id=$1 AND action='provision'").bind(operation).fetch_one(&pool).await?;
        let used: bool =
            sqlx::query_scalar("SELECT used FROM public.mdm_tenants WHERE tenant_id=$1")
                .bind(row.0)
                .fetch_one(&pool)
                .await?;
        let account: Option<Value> = sqlx::query_scalar("SELECT receipt FROM public.mdm_tenant_operations WHERE operation_id=$1 AND action='administrator_create'").bind(Uuid::parse_str(row.1["administratorOperationId"].as_str().unwrap())?).fetch_optional(&pool).await?;
        ensure!(
            used == (stage != "reserved") && account.is_some() == (stage == "account"),
            "actual provisioning boundary {stage}"
        );
        pending.push((operation, row.0, row.1, body, account));
        if stage == "account" {
            running.take().context("running App")?.close().await?;
        }
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP TRIGGER maintenance_fault ON {table}; DROP FUNCTION public.maintenance_fault()"
        )))
        .execute(&pool)
        .await?;
        if stage == "account" {
            break;
        }
    }
    let mut accounts = vec![
        json!({"tenant_id":management,"account":{"principal_id":first.platform_principal_id,"login":"platform","password_file":root.join("platform-password")}}),
        json!({"tenant_id":first.tenant_id,"account":{"principal_id":first.administrator_id,"login":"administrator","password_file":root.join("administrator-password")}}),
    ];
    private(
        &root.join("second-password"),
        "Installation-second-admin!42",
    )?;
    private(
        &root.join("pending-password"),
        "Pending-installation-admin!42",
    )?;
    let existing: Vec<(Uuid,String)> = sqlx::query_as("SELECT tenant_id,receipt->'result'->>'principalId' FROM public.mdm_tenant_operations WHERE action='administrator_create'").fetch_all(&pool).await?;
    for (tenant, principal) in existing {
        let password = if pending.iter().any(|row| row.1 == tenant) {
            "pending-password"
        } else {
            "second-password"
        };
        accounts.push(json!({"tenant_id":tenant,"account":{"principal_id":principal,"login":"administrator","password_file":root.join(password)}}));
    }
    pool.close().await;
    let archived = capture(root, source, "current-backup").await?;
    ensure!(
        archived.stage == backup::Stage::Complete,
        "current cold backup"
    );
    let telemetry: Value = serde_json::from_slice(&std::fs::read(
        root.join("installation/telemetry-request.json"),
    )?)?;
    let mut admin = sqlx::PgConnection::connect_with(&administrator.options()?).await?;
    use sqlx::Connection;
    for name in [
        database.name.as_str(),
        telemetry["administrator"]["name"].as_str().unwrap(),
    ] {
        ensure!(
            name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "fixture database identifier"
        );
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {name} WITH (FORCE)"
        )))
        .execute(&mut admin)
        .await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE DATABASE {name} TEMPLATE template0"
        )))
        .execute(&mut admin)
        .await?;
    }
    admin.close().await?;
    for directory in ["installation", "runtime", "gateway", "content"] {
        std::fs::remove_dir_all(root.join(directory))?;
    }
    let restore: backup::Restore = serde_json::from_value(
        json!({"directory":root.join("current-backup"),"operation_id":Uuid::new_v4(),"backup_manifest_sha256":archived.manifest_sha256,"administrator":database,"accounts":accounts}),
    )?;
    let restored = backup::restore(restore).await?;
    ensure!(
        restored.stage == backup::Stage::Complete,
        "restore accepts pending tenants without phantom accounts"
    );
    ensure!(
        desired(root, first.host_id)? == write,
        "restore retains the latest complete input and key"
    );
    let running = Running::open(&desired(root, first.host_id)?).await?;
    runtime_files::observe_installation(input(source)?).await?;
    let mut browser = Browser::new(source["listen"].as_str().unwrap().parse()?)?;
    browser
        .login(management, "platform", "Installation-platform-admin!42")
        .await?;
    for (operation, tenant, request, body, _) in pending {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with(database.options()?)
            .await?;
        let unchanged: Value = sqlx::query_scalar(
            "SELECT request FROM public.mdm_tenant_operations WHERE operation_id=$1",
        )
        .bind(operation)
        .fetch_one(&pool)
        .await?;
        assert_eq!(unchanged, request);
        pool.close().await;
        let (status, value) = browser
            .call(
                Method::POST,
                "/api/v1/tenant-administration/provisionings",
                Some(body),
                Some(operation),
            )
            .await?;
        ensure!(
            matches!(status, 200 | 202 | 503),
            "resume pending: {status}: {value}"
        );
        browser.configured(operation).await?;
        let mut business = Browser::new(browser.address)?;
        business
            .login(
                &tenant.to_string(),
                "administrator",
                "Pending-installation-admin!42",
            )
            .await?;
        business.defaults(&tenant.to_string()).await?;
    }
    running.close().await?;
    Ok(())
}
