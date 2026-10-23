use super::*;
use anyhow::{Result, ensure};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
async fn line<S: tokio::io::AsyncRead + Unpin>(reader: &mut BufReader<S>) -> Result<String> {
    let mut value = String::new();
    let size = reader.read_line(&mut value).await?;
    ensure!(size > 0 && size <= 8192 && value.ends_with("\r\n"));
    Ok(value)
}
#[tokio::test]
#[ignore = "MODULE=installation.smtp_transport: real TLS SMTP AUTH, STARTTLS reset and lost DATA acknowledgement"]
async fn real_tls_authentication_and_unknown_submission_are_distinct() -> Result<()> {
    use base64::Engine;
    for (starttls, acknowledge) in [(false, true), (true, true), (true, false)] {
        let root = crate::windows::test_support::root()?;
        let mut server_config = crate::test_support::tls::server(&root, "windows-tls.pk8", None)?;
        server_config.alpn_protocols.clear();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let marker = Arc::new(AtomicBool::new(false));
        let observed = marker.clone();
        let operation = Uuid::new_v4();
        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await?;
            if starttls {
                tcp.write_all(b"220 fixture SMTP\r\n").await?;
                let mut plain = BufReader::new(tcp);
                ensure!(line(&mut plain).await? == "EHLO rss-mdm.invalid\r\n");
                plain
                    .get_mut()
                    .write_all(b"250-fixture\r\n250 STARTTLS\r\n")
                    .await?;
                ensure!(line(&mut plain).await? == "STARTTLS\r\n");
                plain.get_mut().write_all(b"220 ready for TLS\r\n").await?;
                tcp = plain.into_inner();
            }
            let tls = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
                .accept(tcp)
                .await?;
            let mut reader = BufReader::new(tls);
            if !starttls {
                reader.get_mut().write_all(b"220 fixture SMTP\r\n").await?;
            }
            ensure!(line(&mut reader).await? == "EHLO rss-mdm.invalid\r\n");
            reader
                .get_mut()
                .write_all(b"250-fixture\r\n250 AUTH PLAIN\r\n")
                .await?;
            let auth = line(&mut reader).await?;
            let value = auth
                .strip_prefix("AUTH PLAIN ")
                .and_then(|v| v.strip_suffix("\r\n"))
                .ok_or_else(|| anyhow::anyhow!("missing protected AUTH"))?;
            ensure!(
                base64::engine::general_purpose::STANDARD.decode(value)?
                    == b"\0fixture-user\0fixture-password"
            );
            reader.get_mut().write_all(b"235 authenticated\r\n").await?;
            ensure!(line(&mut reader).await? == "MAIL FROM:<sender@example.test>\r\n");
            reader
                .get_mut()
                .write_all(b"250 sender accepted\r\n")
                .await?;
            ensure!(line(&mut reader).await? == "RCPT TO:<recipient@example.test>\r\n");
            ensure!(!observed.load(Ordering::SeqCst));
            reader
                .get_mut()
                .write_all(b"250 recipient accepted\r\n")
                .await?;
            ensure!(line(&mut reader).await? == "DATA\r\n");
            ensure!(observed.load(Ordering::SeqCst));
            reader.get_mut().write_all(b"354 send message\r\n").await?;
            let mut body = String::new();
            loop {
                let text = line(&mut reader).await?;
                if text == ".\r\n" {
                    break;
                }
                body.push_str(&text);
                ensure!(body.len() <= 16384);
            }
            ensure!(
                body.contains(&format!("Message-ID: <{operation}@rss-mdm.invalid>\r\n"))
                    && body.starts_with("Date: ")
                    && body.contains("RSS MDM SMTP qualification")
            );
            if acknowledge {
                reader.get_mut().write_all(b"250 queued\r\n").await?;
                reader.get_mut().flush().await?;
            }
            Ok::<(), anyhow::Error>(())
        });
        let endpoint = transport::Endpoint {
            hostname: "localhost".into(),
            address,
            tls: if starttls {
                transport::Tls::Starttls
            } else {
                transport::Tls::Implicit
            },
            ca_pem: std::fs::read(root.join("ca.crt"))?,
        };
        let credentials = transport::Credentials {
            username: "fixture-user".to_owned().into(),
            password: "fixture-password".to_owned().into(),
        };
        let result = transport::test(
            &endpoint,
            &credentials,
            "sender@example.test",
            "recipient@example.test",
            operation,
            crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?,
            || async {
                marker.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        server.await??;
        ensure!(marker.load(Ordering::SeqCst));
        if acknowledge {
            ensure!(result.is_ok(), "SMTP fixture rejected");
        } else {
            ensure!(matches!(result, Err(rss_mdm_mail_service::Error::Unknown)));
        }
    }
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=installation.smtp: original operation, encrypted credentials and unknown DATA receipt survive replay"]
async fn unknown_submission_is_not_requeued_and_materials_rewrap() -> Result<()> {
    runtime_role_cannot_insert_provider_success().await?;
    let tenant = crate::test_support::runtime::case_tenant();
    let mut c = PgConnection::connect_with(
        &std::env::var("MDM_OWNER_URL")?
            .parse::<sqlx::postgres::PgConnectOptions>()?
            .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
            .ssl_root_cert(std::env::var("PG_CA_FILE")?),
    )
    .await?;
    let mut tx = c.begin().await?;
    scope(&mut tx, Uuid::parse_str(tenant)?).await?;
    let key = rss_mdm_native_protection::Protector::new(&[41; 32])?;
    let next =
        rss_mdm_native_protection::Protector::with_fingerprint(&[42; 32], &[&[41; 32]], &[41; 32])?;
    let id = Uuid::new_v4();
    let input = store::Request {
        expected_revision: 0,
        profile: "fixture".into(),
        sender: "sender@example.test".into(),
        recipient: "recipient@example.test".into(),
        username: "fixture-user".to_owned().into(),
        password: "fixture-password".to_owned().into(),
    };
    ensure!(
        store::prepare(&mut tx, tenant, id, "administrator", &input, &key)
            .await?
            .revision
            == 1
    );
    ensure!(
        store::prepare(&mut tx, tenant, id, "another-administrator", &input, &key)
            .await
            .is_err()
    );
    let endpoint = transport::Endpoint {
        hostname: "localhost".into(),
        address: "127.0.0.1:465".parse()?,
        tls: transport::Tls::Implicit,
        ca_pem: std::fs::read(crate::windows::test_support::root()?.join("ca.crt"))?,
    };
    let material = store::pending(&mut tx, tenant, id, &key, &endpoint).await?;
    ensure!(material.credentials.username.as_str() == "fixture-user");
    let mut changed = endpoint.clone();
    changed.address = "127.0.0.1:587".parse()?;
    ensure!(
        store::pending(&mut tx, tenant, id, &key, &changed)
            .await
            .is_err()
    );
    store::submitting(&mut tx, tenant, id).await?;
    store::finish(&mut tx, tenant, id, store::Outcome::Unavailable).await?;
    ensure!(store::operation(&mut tx, tenant, id).await?.state == store::State::Unknown);
    ensure!(store::submitting(&mut tx, tenant, id).await.is_err());
    ensure!(store::rewrap(&mut tx, tenant, &next).await? == 1);
    ensure!(store::rewrap(&mut tx, tenant, &next).await? == 0);
    ensure!(
        store::pending(&mut tx, tenant, id, &next, &endpoint)
            .await?
            .credentials
            .password
            .as_str()
            == "fixture-password"
    );
    ensure!(
        store::prepare(&mut tx, tenant, id, "administrator", &input, &next)
            .await?
            .state
            == store::State::Unknown
    );
    tx.rollback().await?;
    c.close().await?;
    Ok(())
}

async fn runtime_role_cannot_insert_provider_success() -> Result<()> {
    let mut c =
        PgConnection::connect_with(&crate::device::test_support::options("mdm_access")?).await?;
    for kind in ["smtp", "wns"] {
        let mut tx = c.begin().await?;
        let tenant = Uuid::new_v4();
        scope(&mut tx, tenant).await?;
        let insert = if kind == "smtp" {
            sqlx::query("INSERT INTO mdm_mail.heads VALUES($1,0,NULL)")
                .bind(tenant)
                .execute(&mut *tx)
                .await?;
            "INSERT INTO mdm_mail.versions(tenant_id,revision,operation_id,fingerprint_key,fingerprint,profile,sender,recipient,credentials,state,accepted_at) VALUES($1,1,$2,'fake',decode(repeat('00',32),'hex'),'fake','a@example.test','b@example.test',decode('00','hex'),'accepted',1)"
        } else {
            sqlx::query("INSERT INTO mdm_wns.heads VALUES($1,0,NULL)")
                .bind(tenant)
                .execute(&mut *tx)
                .await?;
            "INSERT INTO mdm_wns.versions(tenant_id,revision,operation_id,actor,fingerprint_key,fingerprint,pfn,sid_digest,configuration,material,qualified_at,selected) VALUES($1,1,$2,'fake','fake',decode(repeat('00',32),'hex'),'fake',decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'),decode('00','hex'),1,true)"
        };
        let error = sqlx::query(insert)
            .bind(tenant)
            .bind(Uuid::new_v4())
            .execute(&mut *tx)
            .await
            .unwrap_err();
        ensure!(error.as_database_error().and_then(|e| e.code()).as_deref() == Some("42501"));
        tx.rollback().await?;
    }
    c.close().await?;
    Ok(())
}
