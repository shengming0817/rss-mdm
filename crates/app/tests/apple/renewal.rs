//! Real step-ca signing and mTLS proof replace the active credential atomically.
use super::*;
use sqlx::{Connection, Row};
impl Fixture {
    pub async fn renewal_cycle(
        &mut self,
        old: &lifecycle::Peer,
        old_device: &scep_client::Device,
    ) -> Result<(lifecycle::Peer, scep_client::Device)> {
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let row=sqlx::query("SELECT s.certificate,s.enrollment::text,s.registration::text,s.not_before,s.not_after,r.generation,c.id::text AS credential,p.epoch::text FROM mdm_apple.scep_attempts s JOIN mdm_access.registrations r ON (r.tenant_id,r.id)=(s.tenant_id,s.registration) JOIN mdm_access.credentials c ON (c.tenant_id,c.registration)=(r.tenant_id,r.id) JOIN mdm_access.report_sources p ON (p.tenant_id,p.registration)=(r.tenant_id,r.id) WHERE s.tenant_id=$1::uuid AND r.device=$2 AND s.state='bound' AND c.state='active'").bind(case_tenant()).bind(case_device()).fetch_one(&mut pg).await?;
        let enrollment = Uuid::parse_str(&row.try_get::<String, _>("enrollment")?)?;
        let before: i64 = row.try_get("not_before")?;
        let after: i64 = row.try_get("not_after")?;
        let now = self.app.clock.unix_seconds()?;
        let old_leaf = self.app.apple()?.channel.trust_fixture().verify(
            &[tokio_rustls::rustls::pki_types::CertificateDer::from(
                row.try_get::<Vec<u8>, _>("certificate")?,
            )],
            self.app.clock.unix_seconds()?,
        )?;
        let old_principal = self
            .app
            .devices
            .management_principal(
                &crate::device::ChannelMount::new(
                    self.app.identity.tenant,
                    rss_mdm_inventory::ReportSource::MdmApple,
                )
                .credential(old_leaf.fingerprint()),
            )
            .await?;
        ensure!(!rss_mdm_apple_channel::renewal::due(before, after, now));
        ensure!(!rss_mdm_apple_channel::renewal::due(before, after, after));
        // Move only the scheduling clock into the renewal window. Certificates and TLS remain real.
        let due = after - ((after - before) / 3).min(7 * 86400) + 1;
        for _ in 0..2 {
            rss_mdm_apple_channel::renewal::maintain(
                &self.app.apple()?.channel,
                &self.app.access.apple_store(),
                &self.app.audit_store,
                case_tenant(),
                due,
            )
            .await?;
        }
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND renewal_of IS NOT NULL AND state='prepared'").bind(case_tenant()).fetch_one(&mut pg).await?;
        ensure!(count == 1, "renewal scheduling duplicated an issuance");
        let expired: String = sqlx::query_scalar("SELECT id::text FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND renewal_of IS NOT NULL AND state='prepared'").bind(case_tenant()).fetch_one(&mut pg).await?;
        sqlx::query("UPDATE mdm_apple.scep_attempts SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1::uuid").bind(&expired).execute(&mut pg).await?;
        rss_mdm_apple_channel::renewal::maintain(
            &self.app.apple()?.channel,
            &self.app.access.apple_store(),
            &self.app.audit_store,
            case_tenant(),
            due,
        )
        .await?;
        let state: String =
            sqlx::query_scalar("SELECT state FROM mdm_apple.attempts WHERE id=$1::uuid")
                .bind(&expired)
                .fetch_one(&mut pg)
                .await?;
        ensure!(
            state == "superseded",
            "expired renewal request remained deliverable"
        );
        let (command, body) = old.next("InstallProfile").await?;
        let payload = body["Payload"].as_data().unwrap();
        use x509_cert::der::{Decode, asn1::OctetString};
        let cms = cms::content_info::ContentInfo::from_der(payload)?
            .content
            .decode_as::<cms::signed_data::SignedData>()?;
        let content = cms
            .encap_content_info
            .econtent
            .unwrap()
            .decode_as::<OctetString>()?;
        let profile = protocol::decode(content.as_bytes())?;
        ensure!(profile["PayloadUUID"].as_string() == Some(enrollment.to_string().as_str()));
        let scep = profile["PayloadContent"].as_array().unwrap()[0]
            .as_dictionary()
            .unwrap();
        let attempt = Uuid::parse_str(scep["PayloadUUID"].as_string().unwrap())?;
        ensure!(attempt == command);
        let secret = scep["PayloadContent"].as_dictionary().unwrap()["Challenge"]
            .as_string()
            .unwrap();
        old.manage("NotNow", Some(command), None).await?;
        sqlx::query("UPDATE mdm_apple.attempts SET next_attempt=clock_timestamp()-interval '1 second' WHERE id=$1::uuid").bind(command.to_string()).execute(&mut pg).await?;
        let (retry, request) = old.next("InstallProfile").await?;
        ensure!(
            retry == command && request == body,
            "renewal NotNow changed its request"
        );
        let reused =
            scep_client::Device::with_key(enrollment, attempt, secret, Some(&old_device.key))?;
        let request = reused.request(
            &self.root.join("apple-issuer.pem"),
            &Uuid::new_v4().to_string(),
            self.app.clock.unix_seconds()?,
        )?;
        ensure!(
            reused
                .enroll(
                    &self.client()?,
                    &self.app.apple()?.config.scep_url,
                    &request
                )
                .await
                .is_err(),
            "renewal reused active key"
        );
        let device = scep_client::Device::new(enrollment, attempt, secret)?;
        let request = device.request(
            &self.root.join("apple-issuer.pem"),
            &Uuid::new_v4().to_string(),
            self.app.clock.unix_seconds()?,
        )?;
        self.lose_notify
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let der = device
            .enroll(
                &self.client()?,
                &self.app.apple()?.config.scep_url,
                &request,
            )
            .await?;
        self.lose_notify
            .store(false, std::sync::atomic::Ordering::SeqCst);
        ensure!(
            device
                .enroll(
                    &self.client()?,
                    &self.app.apple()?.config.scep_url,
                    &request
                )
                .await
                .is_err(),
            "renewal challenge reused"
        );
        let peer = lifecycle::Peer {
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(15))
                .identity(device.identity(&der)?)
                .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
                    self.root.join("ca.crt"),
                )?)?)
                .build()?,
            origin: old.origin.clone(),
            topic: old.topic.clone(),
            oracle: oracle::Oracle::new(&der)?,
        };
        let wrong = peer
            .send(
                "/checkin",
                protocol::dictionary([
                    ("MessageType", "Authenticate".into()),
                    ("UDID", "wrong-device".into()),
                    ("Topic", peer.topic.clone().into()),
                ]),
            )
            .await?;
        ensure!(wrong.0 == StatusCode::UNAUTHORIZED);
        let pending: bool = sqlx::query_scalar(
            "SELECT fingerprint IS NULL FROM mdm_apple.scep_attempts WHERE id=$1::uuid",
        )
        .bind(attempt.to_string())
        .fetch_one(&mut pg)
        .await?;
        ensure!(pending, "lost notify or wrong UDID activated candidate");
        // New certificate's first authenticated check-in is the commit point, even after lost notify.
        let accepted = peer
            .send(
                "/checkin",
                protocol::dictionary([
                    ("MessageType", "Authenticate".into()),
                    (
                        "UDID",
                        crate::test_support::case::name("rss-t2-apple").into(),
                    ),
                    ("Topic", peer.topic.clone().into()),
                ]),
            )
            .await?;
        ensure!(
            accepted.0 == StatusCode::OK,
            "renewal activation {}",
            accepted.0
        );
        let audit =
            rss_mdm_audit_integration::RequestAudit::new(case_tenant().into(), "apple_management");
        let stale = self
            .app
            .execution
            .apple_management(
                self.app.apple()?.channel.clone(),
                &old_principal,
                &protocol::xml(protocol::dictionary([
                    ("Status", "Idle".into()),
                    (
                        "UDID",
                        crate::test_support::case::name("rss-t2-apple").into(),
                    ),
                ]))?,
                &audit,
            )
            .await;
        audit.finalize(None);
        ensure!(
            matches!(stale, Err(rss_mdm_execution_service::Error::Unauthorized)),
            "pre-authenticated old principal survived credential switch"
        );
        peer.token().await?;
        peer.manage("Acknowledged", Some(command), None).await?;
        let refused = old
            .send(
                "/mdm",
                protocol::dictionary([
                    ("Status", "Idle".into()),
                    (
                        "UDID",
                        crate::test_support::case::name("rss-t2-apple").into(),
                    ),
                ]),
            )
            .await?;
        ensure!(
            refused.0 == StatusCode::UNAUTHORIZED,
            "old credential survived renewal"
        );
        let replacement=sqlx::query("SELECT r.generation,c.id::text AS credential,p.epoch::text FROM mdm_access.registrations r JOIN mdm_access.credentials c ON (c.tenant_id,c.registration)=(r.tenant_id,r.id) JOIN mdm_access.report_sources p ON (p.tenant_id,p.registration)=(r.tenant_id,r.id) WHERE r.id=$1::uuid AND c.state='active'").bind(row.try_get::<String,_>("registration")?).fetch_one(&mut pg).await?;
        ensure!(
            replacement.try_get::<i64, _>("generation")? == row.try_get::<i64, _>("generation")?
                && replacement.try_get::<String, _>("epoch")?
                    == row.try_get::<String, _>("epoch")?
                && replacement.try_get::<String, _>("credential")?
                    != row.try_get::<String, _>("credential")?
        );
        let checked = self.app.apple()?.channel.trust_fixture().verify(
            &[tokio_rustls::rustls::pki_types::CertificateDer::from(
                der.clone(),
            )],
            self.app.clock.unix_seconds()?,
        )?;
        ensure!(
            self.app
                .apple()?
                .channel
                .trust_fixture()
                .verify(
                    &[tokio_rustls::rustls::pki_types::CertificateDer::from(der)],
                    checked.not_after() + 1
                )
                .is_err()
        );
        pg.close().await?;
        Ok((peer, device))
    }
}

#[tokio::test]
#[ignore = "MODULE=apple.renewal: native protocol and durable state"]
async fn certificate_renewal_preserves_registration() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_scep_peer().await?;
    f.renewal_cycle(&peer, &device).await?;
    drop(device);
    f.close().await
}
