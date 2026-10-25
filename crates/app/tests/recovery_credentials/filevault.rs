use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_agent_wire::filevault as w;
use rss_mdm_recovery_credentials::{Protection, Recipient, filevault as owner};
use sha2::{Digest, Sha256};
fn protection() -> Result<Protection> {
    protection_with_expiry(false)
}
fn protection_with_expiry(expired: bool) -> Result<Protection> {
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
    let not_before = if expired {
        Asn1Time::from_unix(0)?
    } else {
        Asn1Time::days_from_now(0)?
    };
    cert.set_not_before(&not_before)?;
    let not_after = if expired {
        Asn1Time::from_unix(1)?
    } else {
        Asn1Time::days_from_now(1)?
    };
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
        let replacement=super::filevault::protection()?;
        ensure!(owner::configure(&mut tx,&a,&configure,&replacement).await?==config,"committed configuration must replay without its former active recipient");
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
        let association=Uuid::new_v4();
        sqlx::query("INSERT INTO mdm_devices.associations(tenant_id,id,version,state,evidence,hardware,confirmed_by,confirmed_at) VALUES($1,$2,1,'confirmed','test proof','{}','test administrator',1)")
            .bind(tenant).bind(association).execute(&mut *tx).await?;
        for (source,channel) in [(&a,"agent"),(&b,"mdm")] {
            sqlx::query("INSERT INTO mdm_devices.members(tenant_id,association_id,device,channel,registration_id,generation) VALUES($1,$2,$3,$4,$5,$6)")
                .bind(tenant).bind(association).bind(&source.device).bind(channel).bind(source.registration).bind(source.generation).execute(&mut *tx).await?;
        }
        owner::merge(&mut tx,&protection,&a,&b,association,1).await?;
        let ac=owner::configuration(&mut tx,&a,&protection).await?;let bc=owner::configuration(&mut tx,&b,&protection).await?;
        ensure!(ac.custody_id==bc.custody_id);
        let shared=owner::source_binding(&mut tx,&b,false).await?.context("shared custody")?;
        ensure!(shared.device==a.device);
        let resolved=owner::material_coordinates(&mut tx,tenant,&shared,first.material,first.version).await?;
        ensure!(resolved.material==first.material,"MDM reconcile must resolve Agent-origin material through custody");
        sqlx::query("SAVEPOINT relation_lifetime").execute(&mut *tx).await?;
        sqlx::query("UPDATE mdm_devices.associations SET state='revoked',version=version+1,revoked_at=1,revoked_by='test',reason='wrong association' WHERE tenant_id=$1 AND id=$2")
            .bind(tenant).bind(association).execute(&mut *tx).await?;
        ensure!(!owner::configuration(&mut tx,&b,&protection).await?.enabled,"revoked association cannot keep a sharing grant");
        ensure!(owner::configuration(&mut tx,&a,&protection).await?.enabled,"independent owner remains usable");
        let accessible:bool=sqlx::query_scalar("SELECT mdm_recovery.filevault_accessible($1,$2)")
            .bind(serde_json::to_value(&shared.subject)?).bind(&b.device).fetch_one(&mut *tx).await?;
        ensure!(!accessible,"metadata/disclosure cannot use a revoked sharing grant");
        sqlx::query("ROLLBACK TO SAVEPOINT relation_lifetime").execute(&mut *tx).await?;
        owner::retire_source(&mut tx,case_tenant(),registration).await?;
        ensure!(owner::configuration(&mut tx,&b,&protection).await?.enabled,"primary ingress retirement preserves the authorized survivor");
        sqlx::query("ROLLBACK TO SAVEPOINT relation_lifetime").execute(&mut *tx).await?;

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

#[tokio::test]
#[ignore = "MODULE=recovery-credentials.http: reserve capacity before native rotation, receive final reserved key at the boundary"]
async fn reserved_native_prk_remains_receivable_at_capacity() -> Result<()> {
    let mut authority = authority::Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
        let protection=protection()?;let tenant=Uuid::parse_str(case_tenant())?;
        let device=case::name("filevault-capacity");let (registration,_)=inventory::seed_source(device,"mdm","mdm.apple","fixture")?;
        let source=owner::Source{tenant,device:device.into(),registration,generation:1};
        let mut tx=begin(&authority.pool).await?;
        let binding=owner::source_binding(&mut tx,&source,true).await?.context("custody")?;
        let first_op=Uuid::new_v4();let first=storage::reserve_in(&mut tx,tenant,&binding,first_op,0).await?;
        sqlx::query("UPDATE mdm_recovery.versions SET pending=false WHERE tenant_id=$1 AND entry=$2").bind(tenant).bind(first.material).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_recovery.versions(tenant_id,entry,version,operation,validity,created_at,pending) SELECT $1,$2,n,gen_random_uuid(),'unverified',1,false FROM generate_series(2,4095) n")
            .bind(tenant).bind(first.material).execute(&mut *tx).await?;
        sqlx::query("UPDATE mdm_recovery.entries SET revision=4095 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(first.material).execute(&mut *tx).await?;
        let operation=Uuid::new_v4();let reserved=storage::reserve_in(&mut tx,tenant,&binding,operation,4095).await?;
        ensure!(reserved.version==4096);
        let config=owner::configuration(&mut tx,&source,&protection).await?;
        let input=upload(&protection,&config,"ABCD-EFGH-IJKL-MNOP-QRST-UVWX")?;
        let cms=STANDARD.decode(&input.cms)?;
        let accepted=owner::receive_reserved_cms(&mut tx,&protection,&reserved,operation,protection.active_recipient().id(),&cms).await?;
        ensure!(accepted.version==4096);
        ensure!(storage::reserve_in(&mut tx,tenant,&binding,operation,4095).await?.version==4096);
        ensure!(storage::reserve_in(&mut tx,tenant,&binding,Uuid::new_v4(),4096).await.is_err());
        tx.commit().await?;Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=recovery-credentials.http: expired recipient cannot block revoking CMS collection authority"]
async fn expired_recipient_can_be_disabled_without_reviving_upload_authority() -> Result<()> {
    let mut authority = authority::Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
        let tenant=Uuid::parse_str(case_tenant())?;
        let protection=protection_with_expiry(true)?;
        let device=case::name("filevault-expired");
        let (registration,_)=inventory::seed_source(device,"agent","agent.builtin","fixture")?;
        let source=owner::Source{tenant,device:device.into(),registration,generation:1};
        let mut tx=begin(&authority.pool).await?;
        // Minimal legal precondition: an existing authorization whose recipient has expired.
        let binding=owner::source_binding(&mut tx,&source,true).await?.context("custody")?;
        let Subject::Filevault{custody,..}=binding.subject else {anyhow::bail!("FileVault custody")};
        sqlx::query("UPDATE mdm_recovery.filevault_custodies SET enabled=true,revision=1,recipient=$3 WHERE tenant_id=$1 AND id=$2")
            .bind(tenant).bind(custody).bind(protection.active_recipient().id()).execute(&mut *tx).await?;
        let config=owner::configuration(&mut tx,&source,&protection).await?;
        let input=upload(&protection,&config,"ABCD-EFGH-IJKL-MNOP-QRST-UVWX")?;
        let accepted=owner::receive(&mut tx,&source,&input,&protection).await?;
        let mut change=owner::Configure{operation_id:Uuid::new_v4(),registration,generation:1,expected_revision:1,enabled:true,recipient_id:protection.active_recipient().id().into()};
        ensure!(matches!(owner::configure(&mut tx,&source,&change,&protection).await,Err(rss_mdm_recovery_credentials::Error::Conflict)),"expired certificate cannot authorize new collection");
        change.operation_id=Uuid::new_v4();change.enabled=false;
        let disabled=owner::configure(&mut tx,&source,&change,&protection).await?;
        ensure!(!disabled.enabled && disabled.recipient_certificate.is_none() && disabled.revision==2);
        tx.commit().await?;
        let mut tx=begin(&authority.pool).await?;
        ensure!(owner::configure(&mut tx,&source,&change,&protection).await?==disabled);
        let mut fresh=input.clone();fresh.operation_id=Uuid::new_v4();
        ensure!(matches!(owner::receive(&mut tx,&source,&fresh,&protection).await,Err(rss_mdm_recovery_credentials::Error::Forbidden)),"new writes must be revoked");
        ensure!(owner::receive(&mut tx,&source,&input,&protection).await?==accepted,"historical receipt does not restore write authority");
        tx.rollback().await?;
        Ok(())
    }).await
}
