use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_agent_wire::filevault as w;
use rss_mdm_recovery_credentials::{Protection, Recipient, filevault as owner};
use sha2::{Digest, Sha256};
fn protection() -> Result<Protection> {
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{X509, X509NameBuilder},
    };
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "filevault-test")?;
    let name = name.build();
    let mut cert = X509::builder()?;
    cert.set_version(2)?;
    let serial = BigNum::from_u32(1)?.to_asn1_integer()?;
    cert.set_serial_number(&serial)?;
    cert.set_subject_name(&name)?;
    cert.set_issuer_name(&name)?;
    cert.set_pubkey(&key)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(1)?;
    cert.set_not_after(&not_after)?;
    cert.sign(&key, MessageDigest::sha256())?;
    let cert = cert.build();
    let recipient = Recipient::from_pem(&cert.to_pem()?, &key.private_key_to_pem_pkcs8()?)?;
    let id = recipient.id().to_owned();
    Ok(Protection::new(
        KeyRing::new(
            "test".into(),
            vec![("test".into(), Zeroizing::new(vec![62; 32]))],
        )?,
        id,
        vec![recipient],
    )?)
}
fn upload(p: &Protection, config: &w::Configuration, secret: &str) -> Result<w::Upload> {
    use openssl::{
        cms::{CMSOptions, CmsContentInfo},
        stack::Stack,
        symm::Cipher,
        x509::X509,
    };
    let mut recipients = Stack::new()?;
    recipients.push(X509::from_der(&p.active_recipient().certificate_der()?)?)?;
    let cms = CmsContentInfo::encrypt(
        &recipients,
        secret.as_bytes(),
        Cipher::aes_256_cbc(),
        CMSOptions::BINARY,
    )?
    .to_der()?;
    Ok(w::Upload {
        operation_id: Uuid::new_v4(),
        custody_id: config.custody_id.context("custody")?,
        custody_epoch: config.custody_epoch,
        configuration_revision: config.revision,
        expected_revision: config.material_revision,
        recipient_id: p.active_recipient().id().into(),
        cms_digest: format!("{:x}", Sha256::digest(&cms)),
        cms: STANDARD.encode(cms),
    })
}
#[tokio::test]
#[ignore = "MODULE=recovery-credentials.http: independent FileVault CMS custody, exact replay and source retirement"]
async fn agent_cms_custody_is_independent_and_shared_after_explicit_link() -> Result<()> {
    let mut authority = authority::Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
        let tenant=Uuid::parse_str(case_tenant())?;let protection=protection()?;
        let device=case::name("filevault-agent");
        let (registration,_)=inventory::seed_source(device,"agent","agent.builtin","fixture")?;
        let a=owner::Source{tenant,device:device.into(),registration,generation:1};
        let mut tx=begin(&authority.pool).await?;
        ensure!(!owner::configuration(&mut tx,&a,&protection).await?.enabled);
        let configure=owner::Configure{operation_id:Uuid::new_v4(),registration,generation:1,expected_revision:0,enabled:true,recipient_id:protection.active_recipient().id().into()};
        let config=owner::configure(&mut tx,&a,&configure,&protection).await?;
        let request=upload(&protection,&config,"ABCD-EFGH-IJKL-MNOP-QRST-UVWX")?;
        let first=owner::receive(&mut tx,&a,&request,&protection).await?;
        ensure!(first.matches(&request));tx.commit().await?;
        // Reopen as after an ACK loss. No MDM source or execution run was needed.
        let mut tx=begin(&authority.pool).await?;
        ensure!(owner::receive(&mut tx,&a,&request,&protection).await?==first);
        let config=owner::configuration(&mut tx,&a,&protection).await?;
        let second=upload(&protection,&config,"ABCD-EFGH-IJKL-MNOP-QRST-UVWX")?;
        ensure!(request.cms_digest!=second.cms_digest);
        let same=owner::receive(&mut tx,&a,&second,&protection).await?;
        ensure!((same.material,same.version)==(first.material,first.version));
        let validity:String=sqlx::query_scalar("SELECT validity FROM mdm_recovery.versions WHERE tenant_id=$1 AND entry=$2 AND version=$3")
            .bind(tenant).bind(first.material).bind(first.version).fetch_one(&mut *tx).await?;
        ensure!(validity=="unverified");tx.commit().await?;
        let mdm=case::name("filevault-mdm");let (mreg,_)=inventory::seed_source(mdm,"mdm","mdm.apple","fixture")?;
        let b=owner::Source{tenant,device:mdm.into(),registration:mreg,generation:1};
        let mut tx=begin(&authority.pool).await?;
        let bconfig=owner::configure(&mut tx,&b,&owner::Configure{operation_id:Uuid::new_v4(),registration:mreg,generation:1,expected_revision:0,enabled:true,recipient_id:protection.active_recipient().id().into()},&protection).await?;
        let breq=upload(&protection,&bconfig,"ABCD-EFGH-IJKL-MNOP-QRST-UVWX")?;
        owner::receive(&mut tx,&b,&breq,&protection).await?;
        owner::merge(&mut tx,&protection,&a,&b).await?;
        let ac=owner::configuration(&mut tx,&a,&protection).await?;let bc=owner::configuration(&mut tx,&b,&protection).await?;
        ensure!(ac.custody_id==bc.custody_id);
        let copies:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_recovery.entries e JOIN mdm_recovery.versions v ON(v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=$1 AND e.subject->>'kind'='filevault' AND NOT e.retired AND v.sealed IS NOT NULL")
            .bind(tenant).fetch_one(&mut *tx).await?;ensure!(copies==1);
        owner::retire_source(&mut tx,case_tenant(),mreg).await?;
        let current=owner::configuration(&mut tx,&a,&protection).await?;ensure!(current.enabled);
        let fresh=upload(&protection,&current,"BCDE-FGHI-JKLM-NOPQ-RSTU-VWXY")?;
        owner::receive(&mut tx,&a,&fresh,&protection).await?;
        tx.commit().await?;
        let mut tx=begin(&authority.pool).await?;
        let mut forged=fresh.clone();forged.operation_id=Uuid::new_v4();forged.custody_epoch+=1;
        ensure!(owner::receive(&mut tx,&a,&forged,&protection).await.is_err());tx.rollback().await?;
        Ok(())
    }).await
}
