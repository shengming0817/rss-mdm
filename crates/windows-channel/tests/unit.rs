use super::*;
use anyhow::ensure;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_windows_mdm::syncml::{self, Command};
#[tokio::test]
async fn invalid_csr_has_certificate_request_fault() -> anyhow::Result<()> {
    let error = certificate::Csr::verify(b"invalid-csr").err().unwrap();
    let response = fault(None, error.into());
    let bytes = axum::body::to_bytes(response.into_body(), 8192).await?;
    let message = soap::decode(&bytes, Operation::Fault, &CodecLimits::default())?;
    ensure!(matches!(
        message.body,
        Body::Fault(soap::FaultKind::CertificateRequest)
    ));
    Ok(())
}
#[test]
fn digest_uses_binary_nonce_and_challenge_round_trips() {
    let nonce = [0u8; 32];
    assert_ne!(
        protection::digest("server", "password", &nonce),
        protection::digest("server", "password", STANDARD.encode(nonce).as_bytes())
    );
    let mut message = syncml::decode(
        include_bytes!("../../windows-mdm/tests/fixtures/status-details.xml"),
        &CodecLimits::default(),
    )
    .unwrap();
    let Command::Status(status) = &mut message.commands[0] else {
        panic!()
    };
    status.challenge = Some(syncml::Challenge {
        media_type: "syncml:auth-md5".into(),
        nonce: Some(Secret(STANDARD.encode(nonce))),
    });
    let bytes = syncml::encode(&message, &CodecLimits::default()).unwrap();
    let bad = String::from_utf8(bytes)
        .unwrap()
        .replace(&STANDARD.encode(nonce), "bad!");
    assert!(syncml::decode(bad.as_bytes(), &CodecLimits::default()).is_err());
}

#[test]
fn template_settlement_keeps_final_and_nonfinal_budget_semantics() {
    use crate::template_collection::{Settlement, settlement};
    let limit = CodecLimits::default().session_messages;
    for message in [limit - 1, limit, limit + 1] {
        assert_eq!(
            settlement(true, true, message),
            Settlement::Seal("complete")
        );
        assert_eq!(
            settlement(false, true, message),
            if message < limit {
                Settlement::Pending
            } else {
                Settlement::Seal("message_budget")
            }
        );
        for complete in [false, true] {
            assert_eq!(
                settlement(complete, false, message),
                if message < limit {
                    Settlement::Pending
                } else {
                    Settlement::Abandon
                }
            );
        }
    }
}
