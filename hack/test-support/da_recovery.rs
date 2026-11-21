//! Establish an enabled login binding and verified original material through the production storage owners.
use anyhow::Result;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rss_mdm_agent_wire::{da, runtime as w};
use rss_mdm_device_access_postgres::{self as pg, device_access as access};
use rss_mdm_install_support::StorageProfile::Da as DA;
use rss_mdm_recovery_credentials as recovery;
use uuid::Uuid;
pub const SID: &str = "S-1-5-21-1-2-3-1001";
pub async fn seed(
    tx: &mut sqlx::PgConnection,
    registration: &da::Registration,
    principal: Uuid,
    protection: &recovery::Protection,
    recipient: &str,
) -> Result<(access::Binding, w::CredentialReceipt, String)> {
    let tenant = registration.tenant;
    let account = w::AccessAccount::Windows {
        sid: SID.into(),
        authority: w::AccessWindowsAuthority::Local,
    };
    let configuration = w::AccessConfiguration {
        mac: None,
        windows: w::AccessWindowsConfiguration::RssFactor {
            accounts: vec![w::AccessWindowsKind::Local],
        },
        self_enrollment: false,
        enabled: true,
        role: None,
    };
    let publication = rss_mdm_policy_postgres::device_access::Publication {
        managed_fields: vec![],
        id: Uuid::new_v4(),
        revision: 1,
        version: Uuid::new_v4(),
        target: rss_mdm_policy_postgres::device_access::Target::Device {
            device: registration.device,
        },
        enabled: true,
        configuration: configuration.clone(),
    };
    let mut binding = access::Binding {
        operation_id: Uuid::new_v4(),
        account_disposition: w::AccessAccountDisposition::Keep,
        id: Uuid::new_v4(),
        tenant,
        device: registration.device,

        person: rss_mdm_device_access::Person {
            instance: registration.service_id,
            principal,
        },
        origin: access::Origin::SelfEnrollment,
        generation: 3,
        factor_generation: 4,
        revision: 1,
        state: rss_mdm_device_access::State::Pending,
        intent: rss_mdm_device_access::AccountIntent::Existing {
            account: account.clone(),
        },
        account: Some(account.clone()),
        policy: publication.id,
        policy_version: publication.version,
        configuration,
        received_revision: None,
        applied_revision: None,
        deployment_application: None,
        effect: None,
        applied_windows: None,
        created_by_rss: false,
    };
    rss_mdm_policy_postgres::device_access::publish_on(
        tx,
        tenant,
        &publication,
        0,
        serde_json::json!({"kind":"system"}),
        time::OffsetDateTime::now_utc().unix_timestamp(),
    )
    .await?;
    access::storage::insert_in(tx, &binding).await?;

    recovery::Protection::select_on(DA, tx, tenant, recipient).await?;
    let qualification = pg::recovery::eligibility::AccessEligibility { admission: None };
    let custody = recovery::Custody::new(DA, Some(&qualification));
    let anchor = recovery::Binding {
        device: registration.device,
        subject: recovery::Subject::RssLogin {
            binding: binding.id,
            binding_generation: binding.generation,
            sid: SID.into(),
        },
    };
    let first = Uuid::new_v4();
    let coordinates = recovery::storage::reserve_in(custody, tx, tenant, &anchor, first, 0).await?;
    let original = URL_SAFE_NO_PAD.encode([81; 32]);
    recovery::storage::ingest_in(
        custody,
        tx,
        &protection.keys,
        &coordinates,
        first,
        original.as_bytes(),
    )
    .await?;
    recovery::storage::verify_in(custody, tx, &coordinates, first).await?;
    let receipt = w::CredentialReceipt {
        subject: serde_json::from_value(serde_json::to_value(&anchor.subject)?)?,
        material: coordinates.material,
        version: coordinates.version,
    };
    binding.state = rss_mdm_device_access::State::Active;
    binding.received_revision = Some(binding.revision);
    binding.applied_revision = Some(binding.revision);
    binding.applied_windows = Some(w::AccessWindowsFacts::RssFactor(w::AccessRssFacts {
        factor_generation: binding.factor_generation,
        recovery: receipt.clone(),
    }));
    binding.effect = Some(w::AccessEffect::Applied {
        account,
        role: w::AccessRole::Standard,
        mac: None,
        windows: binding.applied_windows.clone(),
    });
    access::storage::save_in(tx, &binding, binding.revision).await?;
    Ok((binding, receipt, original))
}
