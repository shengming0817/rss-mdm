//! Reuse the actual retained software and credential owners for ordinary directory consumption.
use super::*;
use crate::{command_runtime_t2_support::seed_transaction, planning_t2_support as planning};
use rss_mdm_resource as r;
pub(super) async fn seed(c: &Context, cases: &mut Vec<(String, String, Value)>) -> Result<Value> {
    let support = super::super::software_t2::support::software_with_export(
        c,
        "directory-publication",
        r::SoftwareExport::Winget {
            locale: "en-US".into(),
            name: "Directory".into(),
            publisher: "Acme".into(),
            description: "Directory proof".into(),
            license: "MIT".into(),
        },
    )
    .await?;
    super::super::reference_blockers_t2::publication::withdrawn(c, &support).await?;
    cases.push((
        "/api/v1/software/publications".into(),
        "id==retained-publication;withdrawn==true".into(),
        json!("retained-publication"),
    ));
    cases.push((
        "/api/v1/software/publication-targets".into(),
        "id==private;protocol==winget".into(),
        json!("private"),
    ));
    let r::Declaration::Software { definition } = support.variants()[0].declaration() else {
        anyhow::bail!("software")
    };
    let spec = definition.spec();
    let installer = &spec.artifacts["package"];
    let package = Uuid::new_v4();
    let mut tx = seed_transaction(c).await?;
    let lifecycle = rss_mdm_software_service::catalog::binding_on(
        &mut tx,
        c.tenant,
        support.resource().as_str(),
        "1",
        support.digest().bytes(),
    )
    .await?
    .context("reviewed software")?;
    let document = rss_mdm_agent_wire::enroll::configuration::Package {
        release_id: package,
        tenant_id: Uuid::parse_str(&c.tenant.to_string())?,
        target: rss_mdm_agent_wire::enroll::configuration::Target {
            platform: rss_mdm_agent_wire::runtime::TaskPlatform::Windows,
            architecture: rss_mdm_agent_wire::runtime::TaskArchitecture::X86_64,
        },
        version: spec.version.clone(),
        format: rss_mdm_agent_wire::enroll::configuration::InstallerFormat::WindowsMsi,
        filename: "directory-agent.msi".into(),
        length: installer.length,
        installer_sha256: installer.sha256,
    };
    let binding = json!({"variant":"msi","software":spec,"resource":support.resource().as_str(),"version":"1","digest":support.digest().bytes(),"lifecycle":lifecycle,"installer":installer});
    sqlx::query("INSERT INTO mdm_agent_packages.releases(tenant_id,id,document,binding,state) VALUES($1::uuid,$2,$3,$4,'published')").bind(c.tenant.to_string()).bind(package).bind(serde_json::to_value(document)?).bind(binding).execute(&mut *tx).await?;
    tx.commit().await?;
    cases.push((
        "/api/v1/agent-packages".into(),
        "state==published;filename==directory-agent.msi;target.platform==windows".into(),
        json!(package),
    ));
    let (_, _, _, _, agent) = super::super::software_t2::support::endpoints(c).await?;
    let mut tx = seed_transaction(c).await?;
    let association: Uuid = sqlx::query_scalar(
        "SELECT association_id FROM mdm_devices.members WHERE tenant_id=$1::uuid AND device=$2",
    )
    .bind(c.tenant.to_string())
    .bind(agent.device())
    .fetch_one(&mut *tx)
    .await?;
    tx.rollback().await?;
    cases.push((
        "/api/v1/device-associations".into(),
        format!("id=={association};confirmedAt=gt=0;association.evidence==operator-verified"),
        json!(association),
    ));
    let object = planning::endpoint(c).await?;
    let device = object.members[0].device.clone();
    use rss_mdm_recovery_credentials as recovery;
    let key_path = c.inputs.directory.join("native.key");
    let key = std::fs::read(&key_path)?;
    let keys = recovery::KeyRing::new(
        "directory".into(),
        vec![("directory".into(), zeroize::Zeroizing::new(key))],
    )?;
    let custody = recovery::Custody::new(rss_mdm_install_support::StorageProfile::Mdm, None);
    let mut tx = seed_transaction(c).await?;
    let operation = Uuid::new_v4();
    let binding = recovery::Binding {
        device: device.clone(),
        subject: recovery::Subject::LocalAdministrator {
            sid: "S-1-5-21-1-2-3-500".into(),
        },
    };
    let coordinate = recovery::storage::reserve_in(
        custody,
        &mut tx,
        Uuid::parse_str(&c.tenant.to_string())?,
        &binding,
        operation,
        0,
    )
    .await?;
    recovery::storage::ingest_in(
        custody,
        &mut tx,
        &keys,
        &coordinate,
        operation,
        b"Directory-password!42",
    )
    .await?;
    tx.commit().await?;
    cases.push((
        format!("/api/v1/devices/{device}/recovery-credentials"),
        format!(
            "id=={};escrowed==true;binding.subject.kind==local_administrator",
            coordinate.material
        ),
        json!(coordinate.material),
    ));
    let ca = c.inputs.directory.join("task-trust-ca");
    let recipient = recovery::Recipient::from_pem(
        &std::fs::read(ca.join("ca.pem"))?,
        &std::fs::read(ca.join("ca.key"))?,
    )?;
    Ok(
        json!({"active_key":"directory","key_files":{"directory":key_path},"active_recipient":recipient.id(),"recipients":[{"certificate_file":ca.join("ca.pem"),"private_key_file":ca.join("ca.key")}]}),
    )
}
