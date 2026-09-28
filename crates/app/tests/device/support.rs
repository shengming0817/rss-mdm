#![allow(
    clippy::cognitive_complexity,
    reason = "sequential integration matrices preserve each failure and recovery assertion; production code remains checked"
)]
use super::*;
use crate::enrollment::Password;
use anyhow::Context;
use sqlx::postgres::{PgConnectOptions, PgSslMode};
pub(crate) const A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
pub(crate) const B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
pub(crate) fn proof(tenant: &str, channel: Channel, key: u8) -> VerifiedChannelCredential {
    VerifiedChannelCredential {
        tenant: TenantId::parse(tenant).unwrap(),
        channel,
        source: match channel {
            Channel::Agent => ReportSource::AgentBuiltin,
            Channel::Mdm => ReportSource::MdmWindows,
        },
        locator: [key; 32],
    }
}
pub(crate) async fn admin(tenant: &str, token: &str) -> anyhow::Result<AuthorizedPrincipal> {
    let identity = crate::test_support::identity::identity(tenant).await?;
    let login = match (tenant, token) {
        (A, "admin-a") | (B, "admin-b") => "admin",
        (A, "other-a") => "other",
        _ => anyhow::bail!("credential tenant mismatch"),
    };
    let secret = crate::test_support::identity::credential(&identity, login)?;
    // This direct-store matrix is one bounded fixture operation; HTTP requests use their own budget.
    let proof = identity
        .authority
        .inspect_session(
            identity.tenant,
            secret,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                Duration::from_secs(900),
            ),
        )
        .await?;
    let access = Database::connect(options("mdm_access")?).await?;
    let proof = AuthorizedPrincipal::new(proof)?
        .load_authorization(&access)
        .await?;
    access.close().await;
    Ok(proof)
}

pub(crate) fn options(user: &str) -> anyhow::Result<PgConnectOptions> {
    Ok(std::env::var(if user == "postgres" {
        "MDM_ADMIN_URL"
    } else {
        "DATABASE_URL"
    })?
    .parse::<PgConnectOptions>()?
    .username(user)
    .password(match user {
        "mdm_access" => "access-fixture",
        "mdm_runtime" => "runtime-fixture",
        "mdm_api" => "api-fixture",
        _ => "local-fixture",
    })
    .ssl_mode(PgSslMode::VerifyFull)
    .ssl_root_cert(std::env::var("PG_CA_FILE")?))
}
pub(crate) async fn request(
    store: &Database,
    admin: &AuthorizedPrincipal,
    device: &str,
    channel: Channel,
) -> anyhow::Result<Uuid> {
    let audit = RequestAudit::new(admin.tenant_id().into(), "enrollment_create");
    admin.bind_audit(&audit).unwrap();
    audit.target(device);
    let key = Uuid::new_v4();
    audit.operation(key, "enrollment_create");
    let receipt = crate::enrollment::store::create_enrollment(
        store
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?
            .as_ref(),
        admin.enrollment(device)?,
        &Password::new(crate::enrollment::random())?,
        match channel {
            Channel::Agent => ReportSource::AgentBuiltin,
            Channel::Mdm => ReportSource::MdmWindows,
        },
        Uuid::new_v4(),
        key,
        &audit,
    )
    .await?;
    audit.finalize(None);
    Ok(receipt.enrollment_id)
}
pub(crate) async fn bind(
    service: &DeviceService,
    admin: &AuthorizedPrincipal,
    proof: &VerifiedChannelCredential,
    device: &str,
    generation: i64,
) -> anyhow::Result<(BindRegistration, RegistrationReceipt)> {
    let command = BindRegistration {
        operation_id: Uuid::new_v4(),
        request_id: request(&service.access, admin, device, proof.channel).await?,
        expected_generation: generation,
        source: match proof.channel {
            Channel::Mdm => ReportSource::MdmWindows,
            Channel::Agent => ReportSource::AgentBuiltin,
        },
    };
    let receipt = service
        .bind(admin, proof, command.clone())
        .await
        .context("device bind")?;
    Ok((command, receipt))
}
