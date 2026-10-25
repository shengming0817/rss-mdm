#![allow(
    clippy::cognitive_complexity,
    reason = "sequential integration matrices preserve each failure and recovery assertion; production code remains checked"
)]
use super::*;
use anyhow::Context;
use sqlx::postgres::{PgConnectOptions, PgSslMode};
pub(crate) fn case_a() -> &'static str {
    crate::test_support::case::tenant()
}
pub(crate) fn case_b() -> &'static str {
    crate::test_support::case::peer()
}
pub(crate) fn proof(tenant: &str, channel: Channel, key: u8) -> VerifiedChannelCredential {
    ChannelMount::new(
        TenantId::parse(tenant).unwrap(),
        match channel {
            Channel::Agent => ReportSource::AgentBuiltin,
            Channel::Mdm => ReportSource::MdmWindows,
        },
        rss_mdm_registration_service::Purpose::Primary,
    )
    .credential(crate::test_support::runtime::secret(&format!(
        "channel-proof-{key}"
    )))
    .expect("native credential proof")
}
pub(crate) async fn admin(tenant: &str, token: &str) -> anyhow::Result<AuthorizedPrincipal> {
    let (identity, identity_resources) = crate::test_support::identity::identity(tenant).await?;
    identity_resources
        .finish(async {
            let login = match (tenant, token) {
                (tenant, "admin-a") if tenant == case_a() => "admin",
                (tenant, "admin-b") if tenant == case_b() => "admin",
                (tenant, "other-a") if tenant == case_a() => "other",
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
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect_with(options("mdm_access")?)
                .await?;
            let access = rss_mdm_authorization_service::Store::from_pool(
                pool.clone(),
                Arc::new(crate::lifecycle::RuntimeTimer),
            );
            let result = AuthorizedPrincipal::new(proof)?
                .load_authorization(&access)
                .await;
            pool.close().await;
            let proof = result?;
            Ok(proof)
        })
        .await
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
        "mdm_owner" => "owner-fixture",
        _ => "local-fixture",
    })
    .ssl_mode(PgSslMode::VerifyFull)
    .ssl_root_cert(std::env::var("PG_CA_FILE")?))
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
        request_id: service
            .fixture_request(admin, device, proof.channel())
            .await?,
        expected_generation: generation,
        source: match proof.channel() {
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
