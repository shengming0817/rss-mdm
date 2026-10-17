//! User GUIDs are scoped protocol coordinates under one device certificate, never accounts.
use super::*;
use lifecycle::Peer;
use sqlx::Connection;
impl Peer {
    pub(super) async fn user_token(&self, user: Uuid, value: u8) -> Result<()> {
        let response = self
            .send(
                "/checkin",
                protocol::dictionary([
                    ("MessageType", "TokenUpdate".into()),
                    (
                        "UDID",
                        crate::test_support::case::name("rss-t2-apple").into(),
                    ),
                    ("UserID", user.to_string().into()),
                    ("Topic", self.topic.clone().into()),
                    ("Token", plist::Value::Data(vec![value; 32])),
                    ("PushMagic", "user-magic".into()),
                ]),
            )
            .await?;
        ensure!(response.0 == StatusCode::OK, "user token {}", response.0);
        Ok(())
    }
    pub(super) async fn user_manage(
        &self,
        user: Uuid,
        status: &str,
        id: Option<Uuid>,
        extra: Option<(&str, plist::Value)>,
    ) -> Result<(StatusCode, Vec<u8>)> {
        let mut body = protocol::dictionary([
            (
                "UDID",
                crate::test_support::case::name("rss-t2-apple").into(),
            ),
            ("UserID", user.to_string().into()),
            ("Status", status.into()),
        ]);
        if let Some(id) = id {
            body.insert("CommandUUID".into(), id.to_string().into());
        }
        if let Some((key, value)) = extra {
            body.insert(key.into(), value);
        }
        self.send("/mdm", body).await
    }
}
#[tokio::test]
#[ignore = "MODULE=apple.users: Bootstrap Token escrow over real mTLS and PG"]
async fn bootstrap_escrow_requires_evidence_and_clears_secrets() -> Result<()> {
    let mut f = Fixture::start().await?;
    f.grant_native_actions(&["device_control"]).await?;
    let (peer, device) = f.ready_local_peer().await?;
    let get = protocol::dictionary([
        ("MessageType", "GetBootstrapToken".into()),
        (
            "UDID",
            crate::test_support::case::name("rss-t2-apple").into(),
        ),
    ]);
    ensure!(peer.send("/checkin", get.clone()).await?.0 == StatusCode::NOT_IMPLEMENTED);
    f.native_context().await?;
    let empty = peer.send("/checkin", get.clone()).await?;
    ensure!(
        empty.0 == StatusCode::OK && !protocol::decode(&empty.1)?.contains_key("BootstrapToken")
    );
    let secret = vec![97u8; 64];
    let mut set = protocol::dictionary([
        ("MessageType", "SetBootstrapToken".into()),
        (
            "UDID",
            crate::test_support::case::name("rss-t2-apple").into(),
        ),
        ("BootstrapToken", plist::Value::Data(secret.clone())),
    ]);
    ensure!(peer.send("/checkin", set.clone()).await?.0 == StatusCode::OK);
    let response = peer.send("/checkin", get.clone()).await?;
    ensure!(
        response.0 == StatusCode::OK
            && protocol::decode(&response.1)?["BootstrapToken"].as_data()
                == Some(secret.as_slice())
    );
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let sealed: Vec<u8> = sqlx::query_scalar(
        "SELECT bootstrap FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND state='active'",
    )
    .bind(case_tenant())
    .fetch_one(&mut pg)
    .await?;
    ensure!(
        !sealed
            .windows(secret.len())
            .any(|bytes| bytes == secret.as_slice())
    );
    set.insert("BootstrapToken".into(), plist::Value::Data(vec![]));
    ensure!(peer.send("/checkin", set).await?.0 == StatusCode::OK);
    let response = peer.send("/checkin", get).await?;
    ensure!(
        response.0 == StatusCode::OK
            && !protocol::decode(&response.1)?.contains_key("BootstrapToken")
    );
    let stored: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT bootstrap FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND state='active'",
    )
    .bind(case_tenant())
    .fetch_one(&mut pg)
    .await?;
    ensure!(stored.is_none());
    pg.close().await?;
    drop(device);
    f.close().await
}
