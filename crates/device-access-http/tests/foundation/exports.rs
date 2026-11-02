//! One persisted signing receipt survives real native wrapping and two independent CMS signers.
use super::*;
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    pkcs7::{Pkcs7, Pkcs7Flags},
    pkey::PKey,
    rsa::Rsa,
    stack::Stack,
    x509::{X509, X509NameBuilder, store::X509StoreBuilder},
};
use rss_mdm_agent_wire::da;
use rss_mdm_apple_mdm::{
    applicability::{Channel, Context as NativeContext, Enrollment, Version},
    native::Target,
};
fn rewrap(bytes: &[u8]) -> Result<Vec<u8>> {
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "DA outer transport")?;
    let name = name.build();
    let mut cert = X509::builder()?;
    cert.set_version(2)?;
    cert.set_subject_name(&name)?;
    cert.set_issuer_name(&name)?;
    cert.set_pubkey(&key)?;
    cert.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    cert.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
    cert.sign(&key, MessageDigest::sha256())?;
    let cert = cert.build();
    let signer = rss_mdm_certificate::apple::ProfileSigner::from_bytes(
        &cert.to_pem()?,
        &key.private_key_to_pkcs8()?,
        now(),
    )?;
    let signed = signer.sign(bytes, now())?;
    let mut store = X509StoreBuilder::new()?;
    store.add_cert(cert)?;
    let store = store.build();
    let mut extracted = Vec::new();
    Pkcs7::from_der(&signed)?.verify(
        Stack::new()?.as_ref(),
        &store,
        None,
        Some(&mut extracted),
        Pkcs7Flags::BINARY,
    )?;
    Ok(extracted)
}
pub async fn verify(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    signed: &da::SignedConfiguration,
    trust: &da::ConfigurationTrust,
) -> Result<()> {
    let operation = signed.decode()?.operation_id;
    let response: serde_json::Value = material::success(
        client
            .get(format!(
                "{base}/configuration-operations/{operation}/templates?macosVersion=26.4"
            ))
            .bearer_auth(token)
            .send()
            .await?,
    )
    .await?;
    assert_eq!(response["digest"], signed.digest);
    assert_eq!(
        response["mac"]["legacyUnavailable"],
        "mdm_profile_transport_required"
    );
    let context = NativeContext {
        version: Some(Version::parse("26.4")?),
        channel: Channel::Device,
        enrollment: Enrollment::Device,
        supervised: Some(true),
        automated_enrollment: Some(false),
        user_approved: Some(true),
        apple_silicon: Some(true),
    };
    let target = Target {
        context: &context,
        access_rights: &[],
    };
    let bytes = response["mac"]["mobileconfig"].as_str().unwrap().as_bytes();
    let first = rewrap(bytes)?;
    let mut profile = plist::Value::from_reader(std::io::Cursor::new(first))?;
    profile
        .as_dictionary_mut()
        .unwrap()
        .insert("PayloadDisplayName".into(), "Managed by another MDM".into());
    let mut changed = Vec::new();
    profile.to_writer_xml(&mut changed)?;
    let second = rewrap(&changed)?;
    let extracted = rss_mdm_apple_mdm::da::extract(&second, &target)?;
    assert_eq!(extracted.payload, signed.payload);
    assert_eq!(extracted.signature, signed.signature);
    material::verify(&extracted, trust)?;
    profile
        .as_dictionary_mut()
        .unwrap()
        .insert("PayloadIdentifier".into(), "other.identity".into());
    changed.clear();
    profile.to_writer_xml(&mut changed)?;
    assert!(rss_mdm_apple_mdm::da::extract(&rewrap(&changed)?, &target).is_err());
    let mut changed = second.clone();
    let text = String::from_utf8(changed.clone())?;
    let corrupted = text.replace(&signed.signature, "tampered");
    changed = corrupted.into_bytes();
    let result = rss_mdm_apple_mdm::da::extract(&rewrap(&changed)?, &target);
    assert!(
        result.is_err()
            || rss_mdm_task_trust::configuration::verify(&result?, trust, now()).is_err()
    );
    let windows = rss_mdm_windows_mdm::da::templates(signed)?;
    assert_eq!(
        windows.install_uri,
        "./Device/Vendor/MSFT/Policy/ConfigOperations/ADMXInstall/RSSDeviceAccess/Policy/Configuration"
    );
    let recovered = rss_mdm_windows_mdm::da::extract(&windows.registry_value)?;
    material::verify(&recovered, trust)?;
    assert_eq!(recovered.payload, signed.payload);
    assert!(windows.policy_value.contains("&quot;"));
    assert!(rss_mdm_windows_mdm::da::extract("{\"enabled\":true}").is_err());
    Ok(())
}
