//! 仅离线转交认识 V4 文件字段；转换后运行配置只有新领域版本引用。
use crate::setup::{Error, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::PgConnection;
use std::{collections::BTreeMap, path::PathBuf};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Signing {
    private_key_file: PathBuf,
    key_id: String,
    trusted_keys: BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pair {
    certificate_file: PathBuf,
    private_key_file: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Apple {
    #[serde(default)]
    account_keys: BTreeMap<String, Pair>,
    management: Value,
    trust_file: PathBuf,
    profile_certificate_file: PathBuf,
    profile_private_key_file: PathBuf,
    apns_certificate_file: PathBuf,
    apns_private_key_file: PathBuf,
    apns_topic: String,
    challenge_webhook: Value,
    notify_webhook: Value,
}
pub(super) fn protection(
    runtime: &mut Value,
) -> Result<std::sync::Arc<rss_mdm_native_protection::Protector>> {
    let values = runtime.as_object_mut().ok_or(Error::Input)?;
    if values.contains_key("native_protection")
        || values.contains_key("runtime_binding")
        || values.contains_key("apple_material_roots")
    {
        return Err(Error::Conflict);
    }
    let original = values
        .remove("native_protection_key_file")
        .ok_or(Error::Input)?;
    let path = PathBuf::from(original.as_str().ok_or(Error::Input)?);
    let bytes = crate::config::read(&path, 32, true).map_err(|_| Error::Corrupt)?;
    let protection =
        rss_mdm_native_protection::Protector::new(&bytes).map_err(|_| Error::Corrupt)?;
    values.insert(
        "native_protection".into(),
        json!({"active_file":path,"historical_files":[],"fingerprint_file":path}),
    );
    Ok(std::sync::Arc::new(protection))
}
pub(super) async fn signing(
    c: &mut PgConnection,
    runtime: &mut Value,
    operation: Uuid,
    protection: &rss_mdm_native_protection::Protector,
) -> Result<()> {
    if runtime["task_signing"].is_null() {
        return Ok(());
    }
    let source: Signing =
        serde_json::from_value(runtime["task_signing"].clone()).map_err(|_| Error::Input)?;
    let bytes =
        crate::config::read(&source.private_key_file, 4096, true).map_err(|_| Error::Corrupt)?;
    let tenant = rss_request_context::TenantId::parse(
        runtime["identity"]["tenant_id"]
            .as_str()
            .ok_or(Error::Input)?,
    )
    .map_err(|_| Error::Input)?;
    let trust = rss_mdm_execution_service::task_signing::trust::import(
        c,
        tenant,
        operation,
        runtime["product_origin"].as_str().ok_or(Error::Input)?,
        &source.key_id,
        &bytes,
        &source.trusted_keys,
        protection,
    )
    .await
    .map_err(|_| Error::Conflict)?;
    runtime["task_signing"] = json!({"revision":trust.revision});
    Ok(())
}
pub(super) async fn apple(
    c: &mut PgConnection,
    runtime: &mut Value,
    keys: &BTreeMap<String, Uuid>,
    roots: &[PathBuf],
    now: i64,
    protection: &rss_mdm_native_protection::Protector,
) -> Result<()> {
    use rss_mdm_apple_channel::runtime_materials::{
        Purpose,
        transfer::{Material, PrivateKey, import},
    };
    if runtime["native_protocols"]["apple"].is_null() {
        runtime["apple_material_roots"] = json!(roots);
        return Ok(());
    }
    let source: Apple = serde_json::from_value(runtime["native_protocols"]["apple"].clone())
        .map_err(|_| Error::Input)?;
    let tenant = runtime["identity"]["tenant_id"]
        .as_str()
        .ok_or(Error::Input)?;
    let trust = roots
        .iter()
        .map(|p| {
            crate::config::read(p, 131072, false)
                .map(|v| v.to_vec())
                .map_err(|_| Error::Input)
        })
        .collect::<Result<Vec<_>>>()?;
    let mut materials = vec![
        (
            "apns".to_owned(),
            Purpose::Apns,
            1,
            Pair {
                certificate_file: source.apns_certificate_file,
                private_key_file: source.apns_private_key_file,
            },
            Some(source.apns_topic.as_str()),
        ),
        (
            "profile".to_owned(),
            Purpose::Profile,
            1,
            Pair {
                certificate_file: source.profile_certificate_file,
                private_key_file: source.profile_private_key_file,
            },
            None,
        ),
    ];
    let mut accounts = BTreeMap::new();
    for (index, (alias, pair)) in source.account_keys.into_iter().enumerate() {
        let revision = index as i64 + 1;
        materials.push((
            format!("account:{alias}"),
            Purpose::ManagedAccount,
            revision,
            pair,
            None,
        ));
        accounts.insert(alias, revision);
    }
    for (name, purpose, revision, pair, topic) in materials {
        let private =
            crate::config::read(&pair.private_key_file, 32768, true).map_err(|_| Error::Corrupt)?;
        let certificate = crate::config::read(&pair.certificate_file, 131072, false)
            .map_err(|_| Error::Corrupt)?;
        import(
            c,
            tenant,
            Material {
                purpose,
                revision,
                key_id: *keys.get(&name).ok_or(Error::Corrupt)?,
                private_key: if purpose == Purpose::Apns {
                    PrivateKey::Pem(std::str::from_utf8(&private).map_err(|_| Error::Corrupt)?)
                } else {
                    PrivateKey::Pkcs8(&private)
                },
                certificate_chain_pem: std::str::from_utf8(&certificate)
                    .map_err(|_| Error::Corrupt)?,
                expected_topic: topic,
                account_alias: name.strip_prefix("account:"),
            },
            &trust,
            now,
            protection,
        )
        .await
        .map_err(|_| Error::Conflict)?;
    }
    let issuer = original_issuer(&source.trust_file)?;
    runtime["native_protocols"]["apple"] = json!({"management":source.management,"trust_file":source.trust_file,"materials":{"apns":1,"profile":1,"accounts":accounts},"identity_seed":{"challengeId":source.challenge_webhook["id"],"notifyId":source.notify_webhook["id"]},"webhooks":[{"issuer":issuer,"challenge":source.challenge_webhook,"notify":source.notify_webhook}]});
    runtime["apple_material_roots"] = json!(roots);
    Ok(())
}
pub(super) fn apple_keys(runtime: &Value) -> Result<BTreeMap<String, Uuid>> {
    if runtime["native_protocols"]["apple"].is_null() {
        return Ok(BTreeMap::new());
    }
    let source: Apple = serde_json::from_value(runtime["native_protocols"]["apple"].clone())
        .map_err(|_| Error::Input)?;
    let mut keys = BTreeMap::from([
        ("apns".into(), Uuid::new_v4()),
        ("profile".into(), Uuid::new_v4()),
    ]);
    for alias in source.account_keys.keys() {
        keys.insert(format!("account:{alias}"), Uuid::new_v4());
    }
    Ok(keys)
}

fn original_issuer(path: &std::path::Path) -> Result<String> {
    let bytes = crate::config::read(path, 4 * 1024 * 1024, false).map_err(|_| Error::Corrupt)?;
    let trust: rss_mdm_agent_wire::pki::Trust =
        serde_json::from_slice(&bytes).map_err(|_| Error::Corrupt)?;
    // V4 carries only one callback credential pair; never guess bindings across several CAs.
    if trust.issuers.len() != 1 {
        return Err(Error::Conflict);
    }
    Ok(trust.issuers[0].digest.clone())
}
pub(super) fn bootstrap(runtime: &mut Value) -> Result<()> {
    let Some(input) = runtime["agent_pki"]["bootstrap"].as_object_mut() else {
        return Ok(());
    };
    if input.contains_key("webhooks") {
        return Err(Error::Conflict);
    }
    let issuer = original_issuer(std::path::Path::new(
        input
            .get("trust_file")
            .and_then(Value::as_str)
            .ok_or(Error::Input)?,
    ))?;
    let mut callbacks = json!({"issuer":issuer});
    for phase in ["challenge", "notify"] {
        let id = input.remove(&format!("{phase}_id")).ok_or(Error::Input)?;
        let secret = input
            .remove(&format!("{phase}_key_file"))
            .ok_or(Error::Input)?;
        callbacks[phase] = json!({"id":id,"secret_file":secret});
    }
    input.insert("webhooks".into(), json!([callbacks]));
    Ok(())
}
