//! Explicit one-time device PKI upgrade. Runtime never parses the old local signing format.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_agent_wire::pki::{Purpose, Trust};
use serde::Deserialize;
use x509_cert::{
    Certificate, TbsCertificate,
    der::{Decode, Encode},
};
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Upgrade {
    pub database: crate::config::Database,
    pub installation: Installation,
    pub target_config_file: std::path::PathBuf,
    pub profiles: Vec<Profile>,
    pub trusts: Vec<Trust>,
}
/// Approved stable protocol identity replacement, separate from issuer identity.
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub purpose: Purpose,
    pub previous: String,
    pub current: String,
}

/// Read-only preparation uses the same protected target configuration as the new runtime.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepare {
    pub database: crate::config::Database,
    pub installation: Installation,
    pub target_config_file: std::path::PathBuf,
    pub trusts: Vec<Trust>,
}
fn target_profiles(
    path: &std::path::Path,
    installation: &Installation,
    trusts: &[Trust],
) -> Result<std::collections::BTreeMap<String, String>> {
    let invalid = || MigrationError::at("device-pki-v1", "target runtime configuration rejected");
    let config: crate::config::Config = crate::config::load(path).map_err(|_| invalid())?;
    let config = config.compile().map_err(|_| invalid())?.config;
    if config.identity.instance_id != installation.instance_id
        || !installation.tenants.contains(&config.identity.tenant_id)
    {
        return Err(invalid());
    }
    let now =
        crate::clock::Clock::unix_seconds(&crate::clock::SystemClock).map_err(|_| invalid())?;
    let mut targets = std::collections::BTreeMap::new();
    let check = |path: &std::path::Path, purpose: Purpose| -> Result<()> {
        let target = crate::device_pki::load(path, purpose, now)
            .map_err(|_| invalid())?
            .public()
            .map_err(|_| invalid())?;
        if !trusts.contains(&target) {
            return Err(invalid());
        }
        Ok(())
    };
    if let Some(w) = &config.native_protocols.windows {
        check(&w.trust_file, Purpose::Windows)?;
        let key = crate::config::read(&w.protocol_key_file, 32, true).map_err(|_| invalid())?;
        targets.insert(
            "Windows".into(),
            rss_mdm_windows_channel::protocol_identity(
                &w.enrollment.origin,
                &w.management.origin,
                &w.provider_id,
                &key,
                &w.poll,
            )
            .map_err(|_| invalid())?,
        );
    }
    if let Some(a) = &config.native_protocols.apple {
        check(&a.trust_file, Purpose::Apple)?;
        let options = rss_mdm_apple_channel::Config {
            management: rss_mdm_apple_channel::Origin {
                origin: a.management.origin.clone(),
            },
            apns_topic: a.apns_topic.clone(),
            challenge_webhook: rss_mdm_apple_channel::Webhook {
                id: a.challenge_webhook.id.clone(),
            },
            notify_webhook: rss_mdm_apple_channel::Webhook {
                id: a.notify_webhook.id.clone(),
            },
        };
        targets.insert(
            "Apple".into(),
            rss_mdm_apple_channel::protocol_identity(&options)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        );
    }
    Ok(targets)
}
pub async fn prepare(input: Prepare) -> Result<Upgrade> {
    input.installation.validate()?;
    let targets = target_profiles(
        &input.target_config_file,
        &input.installation,
        &input.trusts,
    )?;
    let invalid = || MigrationError::at("device-pki-v1", "read-only upgrade preparation rejected");
    let options = input.database.options().map_err(|_| invalid())?;
    let mut conn =
        tokio::time::timeout(Duration::from_secs(5), PgConnection::connect_with(&options))
            .await
            .map_err(|_| invalid())?
            .map_err(|_| invalid())?;
    let mut tx = conn.begin().await.map_err(|_| invalid())?;
    sqlx::raw_sql("SET TRANSACTION READ ONLY; SET LOCAL statement_timeout='5s'")
        .execute(&mut *tx)
        .await
        .map_err(|_| invalid())?;
    let installed: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations")
            .fetch_all(&mut *tx)
            .await
            .map_err(|_| invalid())?;
    let baseline: Vec<_> = units()
        .into_iter()
        .filter(|(n, _)| *n != "device-pki-v1")
        .collect();
    if !accepted_ledger(&installed, &baseline) {
        return Err(invalid());
    }
    let mut profiles = Vec::new();
    for tenant in &input.installation.tenants {
        scope(&mut tx, tenant).await?;
        for (purpose, query) in [
            (
                Purpose::Windows,
                "SELECT configuration FROM mdm_access.enrollment_intents WHERE tenant_id=$1::uuid UNION SELECT configuration FROM mdm_windows.renewals WHERE tenant_id=$1::uuid",
            ),
            (
                Purpose::Apple,
                "SELECT DISTINCT encode(configuration,'hex') FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid",
            ),
        ] {
            let previous: Vec<String> = sqlx::query_scalar(query)
                .bind(tenant)
                .fetch_all(&mut *tx)
                .await
                .map_err(|_| invalid())?;
            for previous in previous {
                let current = targets
                    .get(&format!("{purpose:?}"))
                    .ok_or_else(invalid)?
                    .clone();
                if !profiles
                    .iter()
                    .any(|p: &Profile| p.purpose == purpose && p.previous == previous)
                {
                    profiles.push(Profile {
                        purpose,
                        previous,
                        current,
                    });
                }
            }
        }
    }
    tx.rollback().await.map_err(|_| invalid())?;
    conn.close().await.map_err(|_| invalid())?;
    Ok(Upgrade {
        database: input.database,
        installation: input.installation,
        target_config_file: input.target_config_file,
        profiles,
        trusts: input.trusts,
    })
}

pub async fn run(input: Upgrade) -> Result<()> {
    input.installation.validate()?;
    let targets = target_profiles(
        &input.target_config_file,
        &input.installation,
        &input.trusts,
    )?;
    for profile in &input.profiles {
        if targets.get(&format!("{:?}", profile.purpose)) != Some(&profile.current) {
            return Err(MigrationError::at(
                "device-pki-v1",
                "profile does not match target runtime configuration",
            ));
        }
    }
    let options = input
        .database
        .options()
        .map_err(|_| MigrationError::at("device-pki-v1", "database configuration"))?;
    let mut conn =
        tokio::time::timeout(Duration::from_secs(5), PgConnection::connect_with(&options))
            .await
            .map_err(|_| MigrationError::at("device-pki-v1", "connection deadline"))?
            .map_err(|_| MigrationError::at("device-pki-v1", "connection unavailable"))?;
    let result = tokio::time::timeout(Duration::from_secs(60), on(&mut conn, &input))
        .await
        .map_err(|_| MigrationError::at("device-pki-v1", "deadline; result unknown"))
        .and_then(|r| r);
    let closed = matches!(
        tokio::time::timeout(Duration::from_secs(5), conn.close()).await,
        Ok(Ok(()))
    );
    match result {
        Err(mut e) => {
            e.cleanup_failed = !closed;
            Err(e)
        }
        Ok(()) if closed => Ok(()),
        _ => Err(MigrationError::at(
            "device-pki-v1",
            "connection close unavailable",
        )),
    }
}
async fn on(conn: &mut PgConnection, input: &Upgrade) -> Result<()> {
    let invalid = || {
        MigrationError::at(
            "device-pki-v1",
            "old signing work must be resolved and activated by the old executable",
        )
    };
    let baseline: Vec<_> = units()
        .into_iter()
        .filter(|(name, _)| *name != "device-pki-v1")
        .collect();
    // Preserve exact full-manifest admission; this does not relax migrate to accept a prefix.
    let installed: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations")
            .fetch_all(&mut *conn)
            .await
            .map_err(|_| invalid())?;
    if accepted_ledger(&installed, &units()) {
        return migrate_units(conn, &input.installation, &units()).await;
    }
    if installed.is_empty() || !accepted_ledger(&installed, &baseline) {
        return Err(MigrationError::at(
            "device-pki-v1",
            "requires exact completed pre-PKI manifest",
        ));
    }
    migrate_units(conn, &input.installation, &baseline).await?;
    let now =
        crate::clock::Clock::unix_seconds(&crate::clock::SystemClock).map_err(|_| invalid())?;
    let mut checked = Vec::new();
    for trust in &input.trusts {
        if !input
            .installation
            .tenants
            .contains(&trust.tenant.to_string())
            || checked.iter().any(|c: &rss_mdm_device_trust::DeviceTrust| {
                c.public()
                    .is_ok_and(|t| t.tenant == trust.tenant && t.purpose == trust.purpose)
            })
        {
            return Err(invalid());
        }
        checked.push(
            rss_mdm_device_trust::DeviceTrust::new(trust.clone(), trust.purpose, now)
                .map_err(|_| invalid())?,
        );
    }
    for (i, profile) in input.profiles.iter().enumerate() {
        if input.profiles[..i].iter().any(|p| {
            p.purpose == profile.purpose
                && (p.previous == profile.previous || p.current != profile.current)
        }) {
            return Err(invalid());
        }
    }
    let mut tx = conn.begin().await.map_err(|_| invalid())?;
    // The operator must stop old writers first. Locks fence any mistakenly still-running writer.
    sqlx::raw_sql("LOCK TABLE mdm_access.agent_grants,mdm_access.agent_issuances,mdm_access.enrollment_intents,mdm_access.enrollment_certificates,mdm_apple.scep_attempts,mdm_windows.renewals IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *tx).await.map_err(|_|invalid())?;
    let mut windows = Vec::new();
    let mut renewals = Vec::new();
    let mut agents = Vec::new();
    let mut apple = Vec::new();
    for tenant in &input.installation.tenants {
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await
            .map_err(|_| invalid())?;
        let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.agent_issuances WHERE tenant_id=$1::uuid AND (state<>'issued' OR activation_result IS NULL)) OR EXISTS(SELECT 1 FROM mdm_access.enrollment_intents i WHERE i.tenant_id=$1::uuid AND NOT EXISTS(SELECT 1 FROM mdm_access.enrollment_certificates c WHERE c.tenant_id=i.tenant_id AND c.request_id=i.request_id)) OR EXISTS(SELECT 1 FROM mdm_windows.renewals WHERE tenant_id=$1::uuid AND activated_at IS NULL) OR EXISTS(SELECT 1 FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND state IN ('prepared','consumed'))")
            .bind(tenant).fetch_one(&mut *tx).await.map_err(|_|invalid())?;
        if pending {
            return Err(invalid());
        }
        let rows=sqlx::query("SELECT i.request_id,i.registration,i.tbs,i.issuer,i.csr,c.certificate FROM mdm_access.enrollment_intents i JOIN mdm_access.enrollment_certificates c ON (c.tenant_id,c.request_id)=(i.tenant_id,i.request_id) WHERE i.tenant_id=$1::uuid")
            .bind(tenant).fetch_all(&mut *tx).await.map_err(|_|invalid())?;
        for row in rows {
            let der: Vec<u8> = row.try_get("tbs").map_err(|_| invalid())?;
            let tbs = TbsCertificate::from_der(&der).map_err(|_| invalid())?;
            let leaf: Vec<u8> = row.try_get("certificate").map_err(|_| invalid())?;
            if Certificate::from_der(&leaf)
                .map_err(|_| invalid())?
                .tbs_certificate
                .to_der()
                .map_err(|_| invalid())?
                != der
            {
                return Err(invalid());
            }
            let csr: Vec<u8> = row.try_get("csr").map_err(|_| invalid())?;
            rss_mdm_certificate::windows::Csr::verify(&csr).map_err(|_| invalid())?;
            if x509_cert::request::CertReq::from_der(&csr)
                .map_err(|_| invalid())?
                .info
                .public_key
                != tbs.subject_public_key_info
            {
                return Err(invalid());
            }
            let issuer: Vec<u8> = row.try_get("issuer").map_err(|_| invalid())?;
            let registration: uuid::Uuid = row.try_get("registration").map_err(|_| invalid())?;
            if tbs.subject.to_string() != format!("CN={registration}") {
                return Err(invalid());
            }
            let profile = rss_mdm_certificate::windows::IssuanceProfile {
                version: 1,
                registration,
                start: tbs.validity.not_before.to_unix_duration().as_secs() as i64,
                end: tbs.validity.not_after.to_unix_duration().as_secs() as i64,
                spki: Sha256::digest(
                    tbs.subject_public_key_info
                        .to_der()
                        .map_err(|_| invalid())?,
                )
                .into(),
                issuer: Sha256::digest(&issuer).into(),
            };
            let profile = profile.encode().map_err(|_| invalid())?;
            windows.push((
                tenant.clone(),
                row.try_get::<uuid::Uuid, _>("request_id")
                    .map_err(|_| invalid())?,
                registration,
                profile,
                issuer,
                leaf,
            ));
        }
        renewals.extend(sqlx::query("SELECT registration,certificate FROM mdm_windows.renewals WHERE tenant_id=$1::uuid")
            .bind(tenant).fetch_all(&mut *tx).await.map_err(|_|invalid())?.into_iter().map(|row|(tenant.clone(),row)));
        agents.extend(sqlx::query("SELECT credential,metadata,certificate_chain FROM mdm_access.agent_issuances WHERE tenant_id=$1::uuid AND state='issued'")
            .bind(tenant).fetch_all(&mut *tx).await.map_err(|_|invalid())?.into_iter().map(|row|(tenant.clone(),row)));
        apple.extend(sqlx::query("SELECT registration,issuer,certificate FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND certificate IS NOT NULL AND registration IS NOT NULL")
            .bind(tenant).fetch_all(&mut *tx).await.map_err(|_|invalid())?.into_iter().map(|row|(tenant.clone(),row)));
    }
    let sql = rss_mdm_pki_service::INSTALL_SQL
        .strip_prefix(
            "-- Product device PKI; immutable original owner migrations stay unchanged.\nBEGIN;\n",
        )
        .and_then(|sql| sql.strip_suffix("COMMIT;\n"))
        .ok_or_else(invalid)?;
    sqlx::raw_sql(sql)
        .execute(&mut *tx)
        .await
        .map_err(|_| MigrationError::at("device-pki-v1", "PKI schema upgrade"))?;
    for tenant in &input.installation.tenants {
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await
            .map_err(|_| invalid())?;
        for profile in &input.profiles {
            if profile.previous.len() != 64
                || profile.current.len() != 64
                || profile.previous == profile.current
                || !profile
                    .previous
                    .bytes()
                    .chain(profile.current.bytes())
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(invalid());
            }
            match profile.purpose {
                Purpose::Windows => {
                    sqlx::query("UPDATE mdm_access.enrollment_intents SET configuration=$3 WHERE tenant_id=$1::uuid AND configuration=$2")
                        .bind(tenant).bind(&profile.previous).bind(&profile.current).execute(&mut *tx).await.map_err(|_|invalid())?;
                    sqlx::query("UPDATE mdm_windows.renewals SET configuration=$3 WHERE tenant_id=$1::uuid AND configuration=$2")
                        .bind(tenant).bind(&profile.previous).bind(&profile.current).execute(&mut *tx).await.map_err(|_|invalid())?;
                }
                Purpose::Apple => {
                    sqlx::query("UPDATE mdm_apple.scep_attempts SET configuration=decode($3,'hex') WHERE tenant_id=$1::uuid AND configuration=decode($2,'hex')")
                        .bind(tenant).bind(&profile.previous).bind(&profile.current).execute(&mut *tx).await.map_err(|_|invalid())?;
                }
                Purpose::Agent => return Err(invalid()),
            }
        }
    }
    for tenant in &input.installation.tenants {
        scope(&mut tx, tenant).await?;
        for purpose in [Purpose::Windows, Purpose::Apple] {
            let targets = input
                .profiles
                .iter()
                .filter(|p| p.purpose == purpose)
                .map(|p| p.current.clone())
                .collect::<Vec<_>>();
            let query = match purpose {
                Purpose::Windows => {
                    "SELECT EXISTS(SELECT 1 FROM mdm_access.enrollment_intents WHERE tenant_id=$1::uuid AND configuration<>ALL($2)) OR EXISTS(SELECT 1 FROM mdm_windows.renewals WHERE tenant_id=$1::uuid AND configuration<>ALL($2))"
                }
                _ => {
                    "SELECT EXISTS(SELECT 1 FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND encode(configuration,'hex')<>ALL($2))"
                }
            };
            if sqlx::query_scalar::<_, bool>(query)
                .bind(tenant)
                .bind(targets)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| invalid())?
            {
                return Err(MigrationError::at(
                    "device-pki-v1",
                    "protocol configuration mapping is incomplete",
                ));
            }
        }
    }
    for trust in &input.trusts {
        scope(&mut tx, &trust.tenant.to_string()).await?;
        rss_mdm_pki_service::registry::persist(&mut tx, trust)
            .await
            .map_err(|_| invalid())?;
    }
    for (tenant, id, registration, profile, issuer, leaf) in windows {
        history(
            &checked,
            &tenant,
            Purpose::Windows,
            &leaf,
            Some(&rss_mdm_device_trust::digest(&issuer)),
        )?;
        scope(&mut tx, &tenant).await?;
        sqlx::query("UPDATE mdm_access.enrollment_intents SET profile=$3 WHERE tenant_id=$1::uuid AND request_id=$2")
            .bind(&tenant).bind(id).bind(profile).execute(&mut *tx).await.map_err(|_|invalid())?;
        rss_mdm_pki_service::certificates::record_in(
            &mut tx,
            &tenant,
            "windows",
            registration,
            &rss_mdm_device_trust::digest(&issuer),
            &leaf,
        )
        .await
        .map_err(|_| invalid())?;
    }
    for (tenant, row) in renewals {
        scope(&mut tx, &tenant).await?;
        let leaf: Vec<u8> = row.try_get("certificate").map_err(|_| invalid())?;
        let issuer = history(&checked, &tenant, Purpose::Windows, &leaf, None)?;
        let registration: uuid::Uuid = row.try_get("registration").map_err(|_| invalid())?;
        if Certificate::from_der(&leaf)
            .map_err(|_| invalid())?
            .tbs_certificate
            .subject
            .to_string()
            != format!("CN={registration}")
        {
            return Err(invalid());
        }
        rss_mdm_pki_service::certificates::record_in(
            &mut tx,
            &tenant,
            "windows",
            registration,
            &issuer.digest,
            &leaf,
        )
        .await
        .map_err(|_| invalid())?;
    }
    for (tenant, row) in agents {
        scope(&mut tx, &tenant).await?;
        let metadata: LegacyAgentMetadata =
            serde_json::from_value(row.try_get("metadata").map_err(|_| invalid())?)
                .map_err(|_| invalid())?;
        let chain: Vec<String> =
            serde_json::from_value(row.try_get("certificate_chain").map_err(|_| invalid())?)
                .map_err(|_| invalid())?;
        let leaf = STANDARD
            .decode(chain.first().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        let certificate = Certificate::from_der(&leaf).map_err(|_| invalid())?;
        let t = &certificate.tbs_certificate;
        if metadata.profile != rss_mdm_certificate::agent::PROFILE
            || metadata.provisioner != "rss-agent"
            || metadata.identity.is_empty()
            || metadata.fingerprint != <[u8; 32]>::from(Sha256::digest(&leaf))
            || metadata.spki
                != <[u8; 32]>::from(Sha256::digest(
                    t.subject_public_key_info.to_der().map_err(|_| invalid())?,
                ))
            || metadata.serial != t.serial_number.as_bytes()
            || metadata.not_before != t.validity.not_before.to_unix_duration().as_secs() as i64
            || metadata.not_after != t.validity.not_after.to_unix_duration().as_secs() as i64
        {
            return Err(invalid());
        }
        let registration: uuid::Uuid = sqlx::query_scalar(
            "SELECT registration FROM mdm_access.credentials WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(&tenant)
        .bind(
            row.try_get::<uuid::Uuid, _>("credential")
                .map_err(|_| invalid())?,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| invalid())?;
        let issuer = metadata
            .issuer
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let generation = history(&checked, &tenant, Purpose::Agent, &leaf, Some(&issuer))?;
        if rss_mdm_device_trust::agent_identity(&certificate, &generation).map_err(|_| invalid())?
            != metadata.identity
        {
            return Err(invalid());
        }
        let device: String = sqlx::query_scalar(
            "SELECT device FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(&tenant)
        .bind(registration)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| invalid())?;
        if rss_mdm_certificate::agent::identity(
            uuid::Uuid::parse_str(&tenant).map_err(|_| invalid())?,
            &device,
        )
        .map_err(|_| invalid())?
            != metadata.identity
        {
            return Err(invalid());
        }
        sqlx::query("UPDATE mdm_access.agent_issuances SET signing_issuer=$3 WHERE tenant_id=$1::uuid AND credential=$2")
            .bind(&tenant).bind(row.try_get::<uuid::Uuid,_>("credential").map_err(|_|invalid())?).bind(&issuer).execute(&mut *tx).await.map_err(|_|invalid())?;
        rss_mdm_pki_service::certificates::record_in(
            &mut tx,
            &tenant,
            "agent",
            registration,
            &issuer,
            &leaf,
        )
        .await
        .map_err(|_| invalid())?;
    }
    for (tenant, row) in apple {
        scope(&mut tx, &tenant).await?;
        let issuer: Vec<u8> = row.try_get("issuer").map_err(|_| invalid())?;
        let hash = issuer
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        history(
            &checked,
            &tenant,
            Purpose::Apple,
            &row.try_get::<Vec<u8>, _>("certificate")
                .map_err(|_| invalid())?,
            Some(&hash),
        )?;
        rss_mdm_pki_service::certificates::record_in(
            &mut tx,
            &tenant,
            "apple",
            row.try_get("registration").map_err(|_| invalid())?,
            &hash,
            &row.try_get::<Vec<u8>, _>("certificate")
                .map_err(|_| invalid())?,
        )
        .await
        .map_err(|_| invalid())?;
    }
    // Previously revoked credentials remain physically revoked after the owner upgrade.
    for tenant in &input.installation.tenants {
        scope(&mut tx, tenant).await?;
        let revoked: Vec<uuid::Uuid> = sqlx::query_scalar(
            "SELECT id FROM mdm_access.credentials WHERE tenant_id=$1::uuid AND state<>'active'",
        )
        .bind(tenant)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| invalid())?;
        for credential in revoked {
            rss_mdm_pki_service::certificates::revoke_credential_in(&mut tx, tenant, credential)
                .await
                .map_err(|_| invalid())?;
        }
    }
    sqlx::query(
        "INSERT INTO public.mdm_migrations(name,digest,complete) VALUES('device-pki-v1',$1,true)",
    )
    .bind(format!(
        "{:x}",
        Sha256::digest(rss_mdm_pki_service::INSTALL_SQL)
    ))
    .execute(&mut *tx)
    .await
    .map_err(|_| invalid())?;
    tx.commit()
        .await
        .map_err(|_| MigrationError::at("device-pki-v1", "commit acknowledgement unknown"))
}
async fn scope(c: &mut PgConnection, tenant: &str) -> Result<()> {
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(c)
        .await
        .map(|_| ())
        .map_err(|_| MigrationError::at("device-pki-v1", "tenant binding"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyAgentMetadata {
    profile: String,
    identity: String,
    issuer: [u8; 32],
    fingerprint: [u8; 32],
    spki: [u8; 32],
    serial: Vec<u8>,
    not_before: i64,
    not_after: i64,
    provisioner: String,
}

fn history(
    checked: &[rss_mdm_device_trust::DeviceTrust],
    tenant: &str,
    purpose: Purpose,
    leaf: &[u8],
    expected: Option<&str>,
) -> Result<rss_mdm_agent_wire::pki::Issuer> {
    let invalid = || {
        MigrationError::at(
            "device-pki-v1",
            "historical certificate has no unique approved issuer/purpose",
        )
    };
    let trust = checked
        .iter()
        .find(|t| {
            t.public()
                .is_ok_and(|t| t.tenant.to_string() == tenant && t.purpose == purpose)
        })
        .ok_or_else(invalid)?;
    let public = trust.public().map_err(|_| invalid())?;
    let matches = public
        .issuers
        .iter()
        .filter(|g| expected.is_none_or(|e| e == g.digest))
        .filter_map(|g| trust.verify_history(leaf, &g.digest).ok())
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(invalid());
    }
    Ok(matches.into_iter().next().ok_or_else(invalid)?)
}
