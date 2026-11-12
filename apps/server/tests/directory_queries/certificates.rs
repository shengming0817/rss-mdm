//! Native and Agent metadata consumers retain the original enrollment/signing coordinates.
use super::*;
use crate::{
    command_runtime_t2_support::seed_transaction, device_material_support as material,
    native_identity_t2_support as native,
};
use sha2::{Digest, Sha256};
#[expect(
    clippy::cognitive_complexity,
    reason = "One linear legal fixture batch preserves the original owner coordinates and collects real directory consumer proofs"
)]
pub(super) async fn seed(
    c: &Context,
    p: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
    cases: &mut Vec<(String, String, Value)>,
) -> Result<(Value, tokio::process::Child)> {
    let n = native::seed(c, "windows").await?;
    let _windows = crate::windows_t2::windows(c, &n).await?;
    let materials = super::super::registration_installation_t2::support::materials(
        c,
        &n,
        Uuid::new_v4(),
        Uuid::new_v4(),
    )
    .await?;
    let (ca_server, ca_origin, ca_root) = crl_server(c, &n.trust).await?;
    let provider = rss_mdm_pki_service::StepCa::new(
        rss_mdm_pki_service::Configuration {
            origin: ca_origin.clone(),
            provisioner: "rss-agent".into(),
            kid: "task-trust".into(),
        },
        &std::fs::read(&ca_root)?,
        &std::fs::read(materials.directory.join("provider.pk8"))?,
    )?;
    let (device, grant) = material::seed_registration(c).await?;
    let _agent = material::authenticated_agent(
        c,
        grant,
        &device,
        vec![rss_mdm_agent_wire::runtime::Capability::InventoryCollectionV1],
    )
    .await?;
    let mut tx = seed_transaction(c).await?;
    let issuer = format!("{:x}", Sha256::digest(&n.root));
    let operation = Uuid::new_v4();
    let rotation = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_pki.issuers(tenant_id,purpose,digest,revision,state,chain,provider,not_after) VALUES($1::uuid,'windows',$2,1,'active',$3,'step_ca',$4)").bind(c.tenant.to_string()).bind(&issuer).bind(&n.root).bind(time::OffsetDateTime::now_utc().unix_timestamp()+86400).execute(&mut *tx).await?;
    let profile:Vec<u8>=sqlx::query_scalar("SELECT profile FROM mdm_access.enrollment_intents WHERE tenant_id=$1::uuid AND request_id=$2").bind(c.tenant.to_string()).bind(n.request).fetch_one(&mut *tx).await?;
    let profile = rss_mdm_certificate::windows::IssuanceProfile::decode(&profile)?;
    let csr = rss_mdm_certificate::windows::Csr::verify(&n.csr)?;
    let pem = csr.pem()?;
    let deadline = time::OffsetDateTime::now_utc().unix_timestamp() + 300;
    rss_mdm_pki_service::signing::authorize_in(
        rss_mdm_install_support::StorageProfile::Mdm,
        &mut tx,
        Uuid::parse_str(&c.tenant.to_string())?,
        "windows",
        &issuer,
        &provider,
        rss_mdm_pki_service::Sign {
            attempt: n.attempt,
            csr_pem: &pem,
            csr_digest: &csr.digest(),
            subject: &profile.device,
            sans: &[],
            start: profile.start,
            end: profile.end,
            deadline,
        },
    )
    .await?;
    sqlx::query(
        "UPDATE mdm_pki.signing SET state='unknown' WHERE tenant_id=$1::uuid AND attempt=$2",
    )
    .bind(c.tenant.to_string())
    .bind(n.attempt)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO mdm_pki.operations(tenant_id,actor,instance,operation,phase,digest,receipt,signing_recovery_attempt) VALUES($1::uuid,$2,$3,$4,'signing_recover',$5,$6,$7)").bind(c.tenant.to_string()).bind(p.principal_id()).bind(p.instance_id()).bind(operation).bind(vec![17u8;32]).bind(b"null".to_vec()).bind(n.attempt).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_pki.rotations VALUES($1::uuid,$2,'windows',$3,$4,1,'activated')")
        .bind(c.tenant.to_string())
        .bind(rotation)
        .bind(&issuer)
        .bind("b".repeat(64))
        .execute(&mut *tx)
        .await?;
    let issuance: Uuid = sqlx::query_scalar(
        "SELECT id FROM mdm_access.certificate_issuances WHERE tenant_id=$1::uuid AND grant_id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(grant)
    .fetch_one(&mut *tx)
    .await?;
    let recovery = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_access.registration_operations(tenant_id,actor,operation_id,digest,result,instance,agent_issuance_recovery,action,device,self_enrollment) VALUES($1::uuid,$2,$3,repeat('a',64),$4,$5,$6,'device_certificate_result',$7,false)").bind(c.tenant.to_string()).bind(p.principal_id()).bind(recovery).bind(serde_json::to_string(&issuance)?).bind(p.instance_id()).bind(issuance).bind(&device).execute(&mut *tx).await?;
    cases.extend([
        (
            format!("/api/v1/devices/{}/windows-certificate-requests", n.device),
            format!(
                "attempt=={};kind==enrollment;enrollmentId=={}",
                n.attempt, n.request
            ),
            json!(n.attempt),
        ),
        (
            format!(
                "/api/v1/devices/{}/windows-certificate-requests/{}/recovery-operations",
                n.device, n.attempt
            ),
            format!("operationId=={operation};instance=={}", p.instance_id()),
            json!(operation),
        ),
        (
            format!("/api/v1/pki/windows/rotations/{rotation}/blockers"),
            format!("kind==unresolved_signing;id=={}", n.attempt),
            json!(n.attempt),
        ),
        (
            format!("/api/v1/devices/{device}/agent-requests"),
            format!("device=={device};issuanceState==issued;activated==true"),
            json!(grant),
        ),
        (
            format!("/api/v1/agent-issuances/{issuance}/recovery-operations"),
            format!("operationId=={recovery};instance=={}", p.instance_id()),
            json!(recovery),
        ),
    ]);
    tx.commit().await?;
    let mut trust = n.trust.clone();
    trust.purpose = rss_mdm_agent_wire::pki::Purpose::Agent;
    trust.origin = "https://agent.example.test".into();
    let trust_file = c
        .inputs
        .directory
        .join(format!("directory-agent-trust-{}.json", c.tenant));
    std::fs::write(&trust_file, serde_json::to_vec(&trust)?)?;
    Ok((
        json!({"agent_pki":{"mode":"step_ca","endpoint":{"origin":"https://agent.example.test"},"trust_file":trust_file,"lifetime":{"mode":"development","days":1}},"device_pki":[{"purpose":"agent","issuer":issuer,"origin":ca_origin,"tls_root_file":ca_root,"provisioner":"rss-agent","kid":"task-trust","provisioner_key_file":materials.directory.join("provider.pk8")}]}),
        ca_server,
    ))
}

// Serve the real fixture CA's signed CRL over TLS; this carrier never fabricates signatures.
async fn crl_server(
    c: &Context,
    trust: &rss_mdm_agent_wire::pki::Trust,
) -> Result<(tokio::process::Child, String, std::path::PathBuf)> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use tokio::io::{AsyncBufReadExt, BufReader};
    let crl = c
        .inputs
        .directory
        .join(format!("directory-{}.crl", c.tenant));
    std::fs::write(&crl, STANDARD.decode(&trust.issuers[0].crl)?)?;
    let tls = c.inputs.directory.parent().context("TLS materials")?;
    let mut child=tokio::process::Command::new("python3")
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
    let mut port = String::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        BufReader::new(child.stdout.take().context("CA stdout")?).read_line(&mut port),
    )
    .await??;
    let port: u16 = port.trim().parse()?;
    Ok((
        child,
        format!("https://localhost:{port}"),
        tls.join("ca.crt"),
    ))
}
