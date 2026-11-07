//! Same tenant and business identity remain distinct through shared RSS owners.
use super::*;
use rss_mdm_audit_integration::budget::AuditBudget;
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::{PgError, PgRuntime};

fn deadline() -> OperationDeadline {
    OperationDeadline::from_remaining(Duration::from_secs(10))
}

pub async fn verify(c: &Context, trust: rss_mdm_agent_wire::pki::Trust) -> Result<()> {
    reconcile(c).await?;
    // The independent journey has finished. Add the real second product owners only
    // for coexistence; no fake tables or grants to the other product's private state.
    let mut tx = c.seed().await?;
    sqlx::query("SET LOCAL ROLE mdm_owner")
        .execute(&mut *tx)
        .await?;
    for (name, sql) in [
        (
            "registration",
            registration::install_sql(StorageProfile::Mdm),
        ),
        ("pki", rss_mdm_pki_service::install_sql(StorageProfile::Mdm)),
        (
            "scope",
            rss_mdm_scope_postgres::install_sql(StorageProfile::Mdm),
        ),
        (
            "scope-relations",
            rss_mdm_scope_postgres::relations_sql(StorageProfile::Mdm),
        ),
    ] {
        rss_mdm_install_support::execute_schema(&mut tx, name, sql, "coexistence owner").await?;
    }
    tx.commit().await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(include_str!("shared-state-grants.sql")))
        .execute(&c.operator)
        .await?;
    let operation = Uuid::new_v4();
    for (profile, role) in [
        (StorageProfile::Mdm, "mdm_scope_runtime"),
        (DA, "da_scope_runtime"),
    ] {
        let runtime = c.inputs.runtime(role, c.tenant).await?;
        let result = receipt(c, profile, &runtime, operation).await;
        runtime.close().await;
        result?;
    }
    pki(c, trust).await
}

async fn reconcile(c: &Context) -> Result<()> {
    use rss_mdm_policy_service::worker::jobs;
    use rss_mdm_scope_service::tasks;
    use rss_reconcile::{Completion, DurableStore, ResourceSet, Scope, Target};
    let pool = c.inputs.database("da_command_runtime").pool().await?;
    let result = async {
        let timer = rss_mdm_policy_service::clock::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(20), &cancel);
        let store = rss_reconcile_postgres::PgStore::new(pool.clone(), &control).await?;
        let id = Uuid::new_v4();
        let input = |domain| Target::new(Scope::new(c.tenant, domain).unwrap(), "inputs").unwrap();
        let pairs = [
            (
                jobs::job_target(StorageProfile::Mdm, c.tenant, id),
                jobs::job_target(DA, c.tenant, id),
            ),
            (
                jobs::event_target(StorageProfile::Mdm, c.tenant, id),
                jobs::event_target(DA, c.tenant, id),
            ),
            (
                tasks::target(StorageProfile::Mdm, c.tenant, id),
                tasks::target(DA, c.tenant, id),
            ),
            (
                input(jobs::domain(StorageProfile::Mdm)),
                input(jobs::domain(DA)),
            ),
            (
                input(tasks::domain(StorageProfile::Mdm)),
                input(tasks::domain(DA)),
            ),
        ];
        for (mdm, da) in pairs {
            store
                .wake(&mdm, &ResourceSet::empty(c.tenant), &control)
                .await?;
            store
                .wake(&da, &ResourceSet::empty(c.tenant), &control)
                .await?;
            let m = store
                .claim_due(mdm.scope(), 64, Duration::from_secs(30), &control)
                .await?;
            let d = store
                .claim_due(da.scope(), 64, Duration::from_secs(30), &control)
                .await?;
            assert!(m.claims.iter().any(|v| v.target() == &mdm));
            assert!(
                d.claims.iter().any(|v| v.target() == &da),
                "MDM must not claim DA work with the same ID"
            );
            for claim in m.claims.iter().chain(&d.claims) {
                store.finish(claim, Completion::Converged, &control).await?;
            }
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    pool.close().await;
    result
}

async fn receipt(
    c: &Context,
    profile: StorageProfile,
    runtime: &Arc<PgRuntime>,
    id: Uuid,
) -> Result<()> {
    let store = rss_mdm_scope_postgres::ScopeBinding::new(profile, runtime.clone(), c.tenant);
    let value = json!({"product":format!("{profile:?}")});
    for replay in [false, true] {
        runtime
            .local_tx_with_context(
                c.tenant,
                deadline(),
                (&store, &value),
                |(store, value), tx| {
                    Box::pin(async move {
                        let old = store
                            .replay_operation_in(
                                tx,
                                "same-actor",
                                "11111111-1111-4111-8111-111111111111",
                                id,
                                &[9; 32],
                            )
                            .await
                            .map_err(|e| PgError::from(sqlx::Error::Protocol(e.to_string())))?;
                        if replay {
                            assert_eq!(old.as_ref(), Some(*value));
                        } else {
                            assert!(old.is_none());
                            store
                                .record_operation_in(
                                    tx,
                                    "same-actor",
                                    "11111111-1111-4111-8111-111111111111",
                                    id,
                                    &[9; 32],
                                    value,
                                )
                                .await
                                .map_err(|e| PgError::from(sqlx::Error::Protocol(e.to_string())))?;
                        }
                        Ok(())
                    })
                },
            )
            .await
            .fold(Ok, Err, Err, Err, Err, Err)?;
    }
    runtime
        .local_tx_with_context(c.tenant, deadline(), &store, |store, tx| {
            Box::pin(async move {
                assert!(matches!(
                    store
                        .replay_operation_in(
                            tx,
                            "same-actor",
                            "11111111-1111-4111-8111-111111111111",
                            id,
                            &[8; 32]
                        )
                        .await,
                    Err(rss_mdm_scope_postgres::BindingError::Conflict)
                ));
                Ok(())
            })
        })
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    Ok(())
}

async fn pki(c: &Context, trust: rss_mdm_agent_wire::pki::Trust) -> Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use rss_mdm_pki_service::{
        Configuration, StepCa,
        providers::{Provider, Providers},
        registry::Registry,
    };
    use tokio::io::{AsyncBufReadExt, BufReader};
    let crl = c.inputs.directory.join("isolation.crl");
    std::fs::write(&crl, STANDARD.decode(&trust.issuers[0].crl)?)?;
    let tls = c.inputs.directory.parent().unwrap();
    let mut server = tokio::process::Command::new("python3")
        .args(["-u","-c",r#"
import http.server,ssl,sys
from pathlib import Path
body=Path(sys.argv[3]).read_bytes()
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path!='/crl': self.send_error(404); return
        self.send_response(200); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self,*args): pass
server=http.server.HTTPServer(('127.0.0.1',0),Handler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(sys.argv[1],sys.argv[2])
server.socket=context.wrap_socket(server.socket,server_side=True)
print(server.server_port,flush=True)
server.serve_forever()
"#]).arg(tls.join("server.crt")).arg(tls.join("server.key")).arg(&crl)
        .stdout(std::process::Stdio::piped()).kill_on_drop(true).spawn()?;
    let result = async {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5),BufReader::new(server.stdout.take().unwrap()).read_line(&mut line)).await??;
        let port:u16=line.trim().parse()?;
        let key = tokio::process::Command::new("openssl")
            .args(["pkcs8","-topk8","-nocrypt","-outform","DER","-in"])
            .arg(c.inputs.directory.join("task-trust-ca/ca.key")).output().await?;
        anyhow::ensure!(key.status.success(),"fixture provisioner key conversion");
        let providers = Arc::new(Providers::new(vec![Provider {
            purpose:trust.purpose,issuer:trust.issuers[0].digest.clone(),scep_url:None,
            client:Arc::new(StepCa::at_address(Configuration {
                origin:format!("https://localhost:{port}"),provisioner:"rss-agent".into(),kid:"task-trust".into()
            },&std::fs::read(tls.join("ca.crt"))?,&key.stdout,([127,0,0,1],port).into())?),
        }])?);
        for (profile,role) in [(StorageProfile::Mdm,"mdm_access"),(DA,"da_access")] {
            let pool = c.inputs.database(role).pool().await?;
            let runtime = c.inputs.runtime(role,c.tenant).await?;
            let result = async {
                let budget = AuditBudget::new(Duration::from_secs(10));
                let audit = Arc::new(c.audit.on_runtime(runtime.clone(),c.tenant,&budget.control()).await?);
                let registry = Registry::new(profile,pool.clone(),audit.clone(),vec![rss_mdm_device_trust::DeviceTrust::new(trust.clone(),trust.purpose,now())?],providers.clone());
                registry.admit(c.tenant,now()).await?;
                registry.admit(c.tenant,now()).await?; // The owner replay does not append a second fact.
                // A new business mutation cannot silently reuse either product's existing fact.
                use sha2::{Digest,Sha256};
                let hash=Sha256::digest(serde_json::to_vec(&trust)?);
                let id=Uuid::from_bytes(hash[..16].try_into()?);
                let request=RequestAudit::new(rss_mdm_audit_integration::Origin::Request, profile,c.tenant.to_string(),"device_pki_admit",AuditIntent::Management);
                request.identify_service("service:device-pki");
                request.operation(id,"device_pki_admit",AuditIntent::Management);
                let fact=rss_mdm_audit_integration::Fact::observation(&request,&format!("pki:{id}:admit"),200,"success",None)?;
                let append=runtime.local_tx_with_context(c.tenant,deadline(),(&audit,&fact),|(audit,fact),tx|Box::pin(async move {
                    audit.bind_in(tx).await.map_err(PgError::from)?;
                    audit.append_in(tx,fact).await.map_err(PgError::from)
                })).await.fold(Ok,Err,Err,Err,Err,Err);
                assert!(append.is_err(),"duplicate business fact accepted for {profile:?}");
                request.finalize(None);
                Ok::<_,anyhow::Error>(())
            }.await;
            runtime.close().await;
            pool.close().await;
            result?;
        }
        let counts:Vec<(String,i64)>=sqlx::query_as("SELECT source_id,count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid AND source_id IN('mdm.business','da.business') AND event_id=$2 GROUP BY source_id ORDER BY source_id")
            .bind(c.tenant.to_string()).bind({use sha2::{Digest,Sha256};let hash=Sha256::digest(serde_json::to_vec(&trust)?);let id=Uuid::from_bytes(hash[..16].try_into()?);format!("e-{:x}",Sha256::digest(format!("pki:{id}:admit").as_bytes()))})
            .fetch_all(&c.operator).await?;
        assert_eq!(counts,vec![("da.business".into(),1),("mdm.business".into(),1)]);
        Ok::<_,anyhow::Error>(())
    }.await;
    server.kill().await?;
    result
}
