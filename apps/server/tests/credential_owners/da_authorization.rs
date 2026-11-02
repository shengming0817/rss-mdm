//! Real Identity step-up authorizes the exact DA-to-Agent delivery before consumers use it.
use super::*;
use crate::authority_t2_support::{Account, deadline};
use rss_mdm_agent_wire::runtime::Secret;
use rss_mdm_authorization_service::{
    Permission, context::AuthorizedPrincipal, credential::RequestCredential,
};
use rss_mdm_device_access_postgres::{self as pg, delivery};
use rss_mdm_install_support::StorageProfile;
use rss_mdm_registration_service::{DevicePrincipal, device::endpoints::DaRegistration};
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};

async fn session(
    c: &Context,
    account: &Account,
) -> Result<rss_identity_postgres::AuthenticatedSession> {
    let RequestCredential::Cookie(secret) = account.credential()? else {
        anyhow::bail!("cookie session required for delivery authorization")
    };
    Ok(c.authority
        .inspect_session(c.tenant, secret, deadline())
        .await?)
}

async fn proof(
    c: &Context,
    account: &Account,
    context: rss_identity_core::step_up::StepUpContext,
) -> Result<Secret> {
    let origin = url::Url::parse("https://localhost")?;
    let webauthn = rss_identity_postgres::WebauthnAuthority::connect(
        c.authority.clone(),
        "localhost".into(),
        origin.clone(),
        deadline(),
    )
    .await?;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let registration = webauthn
        .begin_registration(
            session(c, account).await?,
            "DA Agent delivery proof".into(),
            false,
            rss_identity_postgres::RegistrationAuthorization::First,
            deadline(),
        )
        .await?;
    let response = authenticator.do_registration(origin.clone(), registration.options)?;
    webauthn
        .finish_registration(
            session(c, account).await?,
            registration.id,
            response,
            deadline(),
        )
        .await?;
    let challenge = webauthn
        .begin_authentication(session(c, account).await?, context, deadline())
        .await?;
    let response = authenticator.do_authentication(origin, challenge.options)?;
    let grant = webauthn
        .finish_authentication(
            session(c, account).await?,
            challenge.id,
            response,
            deadline(),
        )
        .await?;
    Ok(Secret::parse(grant.expose())?)
}

fn audit(c: &Context) -> rss_mdm_audit_integration::RequestAudit {
    rss_mdm_audit_integration::RequestAudit::new(
        StorageProfile::Da,
        c.tenant.to_string(),
        "da-delivery-proof",
        rss_mdm_audit_integration::AuditIntent::Management,
    )
}

async fn counts(c: &Context) -> Result<(i64, i64, i64)> {
    Ok(sqlx::query_as("SELECT (SELECT count(*) FROM rss_da.agent_delivery WHERE tenant_id=$1::uuid),(SELECT count(*) FROM rss_da.operations WHERE tenant_id=$1::uuid),(SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid AND source_id='da.business')")
        .bind(c.tenant.to_string()).fetch_one(&c.operator).await?)
}

#[expect(
    clippy::cognitive_complexity,
    reason = "one real Identity proof must survive a rejected target, authorize once, replay and lose authority after Mdm rule revocation"
)]
pub(super) async fn authorize(
    c: &Context,
    agent: &DevicePrincipal,
    da: &DaRegistration,
) -> Result<Uuid> {
    let pool = c.inputs.pool("shared", "da_access").await?;
    let runtime = crate::identity::open_runtime(
        &c.inputs.database("shared", "da_access"),
        &c.inputs.installation.target,
        &c.inputs.installation.lineage,
        &[(c.tenant, 1)],
        2,
    )
    .await?;
    let identity_runtime = crate::identity::open_runtime(
        &c.inputs.database("shared", "mdm_identity_runtime"),
        &c.inputs.installation.target,
        &c.inputs.installation.lineage,
        &[(c.tenant, 1)],
        2,
    )
    .await?;
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(10));
    let business_audit = Arc::new(
        c.audit
            .on_runtime(runtime.clone(), c.tenant, &budget.control())
            .await?,
    );
    let proof_audit = Arc::new(
        c.audit
            .on_runtime(identity_runtime.clone(), c.tenant, &budget.control())
            .await?,
    );
    let service = pg::Service::new(pg::Assembly {
        cursor: rss_mdm_query::cursor::CursorCodec::new(&[37; 32])?,
        tenant: c.tenant,
        instance: Uuid::parse_str(&c.inputs.installation.instance_id)?,
        store: Arc::new(rss_mdm_registration_service::Store::for_device_access(
            pool.clone(),
        )),
        audit: business_audit,
        access_audit: proof_audit,
        protection: material::protection(c)?,
    })?;
    let account = c.account(&[Permission::AccountWrite]).await?;
    let authorization_store = c.access().for_product(StorageProfile::Da);
    let actor: AuthorizedPrincipal = rss_mdm_authorization_service::session::SessionAuthority::new(
        c.authority.clone(),
        c.tenant,
    )
    .authenticate(&authorization_store, account.credential()?)
    .await?;
    assert_eq!(actor.profile(), StorageProfile::Da);
    assert_eq!(actor.authority_profile(), StorageProfile::Mdm);
    let authorization = delivery::Authorization {
        operation_id: Uuid::new_v4(),
        da: da.clone(),
        agent: delivery::Agent {
            installation: agent.installation(),
            device: agent.device().into(),
            registration: agent.registration(),
            generation: agent.generation(),
        },
        expected_revision: 0,
        enabled: true,
    };
    let grant = Box::pin(proof(c, &account, authorization.step_up_context(&actor)?)).await?;
    let before = counts(c).await?;
    let mut substituted = authorization.clone();
    substituted.agent.generation += 1;
    assert!(
        matches!(
            service
                .authorize_agent_delivery(&actor, &substituted, &grant, &audit(c))
                .await,
            Err(pg::Error::Unauthorized)
        ),
        "proof must bind the exact Agent generation"
    );
    assert_eq!(
        counts(c).await?,
        before,
        "rejected target substitution writes no delivery, receipt or Audit"
    );
    assert_eq!(
        service
            .authorize_agent_delivery(&actor, &authorization, &grant, &audit(c))
            .await?,
        1
    );
    let accepted = counts(c).await?;
    assert_eq!(accepted, (before.0 + 1, before.1 + 1, before.2 + 1));
    assert_eq!(
        service
            .authorize_agent_delivery(&actor, &authorization, &grant, &audit(c))
            .await?,
        1
    );
    assert_eq!(
        counts(c).await?,
        accepted,
        "receipt replay consumes no second proof or fact"
    );
    sqlx::query("DELETE FROM mdm_access.authorization_rules WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string())
        .bind(account.rule)
        .execute(&c.operator)
        .await?;
    assert!(
        matches!(
            service
                .authorize_agent_delivery(&actor, &authorization, &grant, &audit(c))
                .await,
            Err(pg::Error::Forbidden)
        ),
        "a stale DA actor cannot replay after its MDM rule is revoked"
    );
    assert_eq!(counts(c).await?, accepted);
    let copied_rules: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_da.authorization_rules WHERE tenant_id=$1::uuid",
    )
    .bind(c.tenant.to_string())
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(
        copied_rules, 0,
        "host DA consumes MDM authorization without a rule copy"
    );
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(c.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let resolved = delivery::resolve_on(&mut tx, agent).await?;
    assert_eq!(
        (
            resolved.device(),
            resolved.registration(),
            resolved.generation()
        ),
        (da.device.as_str(), da.registration_id, da.generation)
    );
    tx.rollback().await?;
    drop(service);
    identity_runtime.close().await;
    runtime.close().await;
    pool.close().await;
    Ok(Uuid::parse_str(actor.principal_id())?)
}
