use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ring::signature::{Ed25519KeyPair, KeyPair};
use rss_mdm_agent_wire::vault::*;
use rss_mdm_audit_integration::{AuditIntent, RequestAudit};
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_vault_sync::{Error, Service};
fn key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(Uuid::new_v4().as_bytes().repeat(2).as_slice()).unwrap()
}
fn device(k: &Ed25519KeyPair) -> Device {
    Device {
        id: Uuid::new_v4(),
        public_key: B64.encode(k.public_key().as_ref()),
    }
}
fn audit(c: &Context) -> RequestAudit {
    RequestAudit::new(DA, c.tenant.to_string(), "vault_test", AuditIntent::Routine)
}
async fn user(c: &Context) -> Result<AuthorizedPrincipal> {
    use rss_identity_core::account::{LoginKey, Password, PasswordKdf};
    let id = Uuid::new_v4();
    let login = format!("vault-{id}");
    let password = "vault-test-only-password-123";
    let hash = PasswordKdf::new()
        .hash(Password::new(password.into())?)
        .await?;
    let mut tx = c.seed().await?;
    sqlx::query(
        "INSERT INTO identity_authority.guard(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING",
    )
    .bind(c.tenant.to_string())
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO identity_authority.accounts(tenant_id,principal_id) VALUES($1::uuid,$2)",
    )
    .bind(c.tenant.to_string())
    .bind(id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO identity_authority.local_credentials(tenant_id,principal_id,login_key,password_hash) VALUES($1::uuid,$2,$3,$4)").bind(c.tenant.to_string()).bind(id).bind(&login).bind(hash.as_str()).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO identity_authority.memberships(tenant_id,principal_id) VALUES($1::uuid,$2)",
    )
    .bind(c.tenant.to_string())
    .bind(id)
    .execute(&mut *tx)
    .await?;
    let grants: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_da.authorization_rules WHERE tenant_id=$1::uuid",
    )
    .bind(c.tenant.to_string())
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(grants, 0);
    tx.commit().await?;
    let issued = c
        .authority
        .login_local_bearer(
            c.tenant,
            LoginKey::parse(&login)?,
            Password::new(password.into())?,
            rss_identity_postgres::AttemptSource::parse("vault-test")?,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                Duration::from_secs(10),
            ),
        )
        .await?;
    Ok(c.sessions
        .authenticate(
            &c.authorization,
            rss_mdm_authorization_service::credential::RequestCredential::Bearer(
                rss_identity_core::session::BearerSecret::parse(issued.secret().expose().into())?,
            ),
        )
        .await?)
}
async fn signed(
    c: &Context,
    s: &Service,
    p: &AuthorizedPrincipal,
    d: &Device,
    k: &Ed25519KeyPair,
    recovery: Option<&Ed25519KeyPair>,
    action: Action,
) -> Result<Execute> {
    let h = s
        .prepare(
            p,
            &audit(c),
            Prepare {
                operation: Uuid::new_v4(),
                device: d.id,
                action,
            },
        )
        .await?;
    let bytes = h.signing_bytes()?;
    Ok(Execute {
        signature: B64.encode(k.sign(&bytes).as_ref()),
        recovery_signature: recovery.map(|k| B64.encode(k.sign(&bytes).as_ref())),
        challenge: h,
    })
}
async fn run(
    c: &Context,
    s: &Service,
    p: &AuthorizedPrincipal,
    d: &Device,
    k: &Ed25519KeyPair,
    action: Action,
) -> Result<Response> {
    let r = signed(c, s, p, d, k, None, action).await?;
    Ok(s.execute(p, &audit(c), r).await?)
}
#[tokio::test]
#[ignore = "T2: real user sessions, sync SQL, replay and restore fencing"]
async fn user_sync_atomicity_and_recovery() -> Result<()> {
    let c = Context::open().await?;
    let s = Service::new(
        c.tenant,
        Uuid::parse_str(&c.inputs.installation.instance_id)?,
        c.proof_audit.clone(),
        rss_mdm_query::cursor::CursorCodec::new(&[8; 32])?,
    );
    let p = user(&c).await?;
    let other = user(&c).await?;
    let recovery = key();
    let k1 = key();
    let d1 = device(&k1);
    let k2 = key();
    let d2 = device(&k2);
    let init = signed(
        &c,
        &s,
        &p,
        &d1,
        &k1,
        Some(&recovery),
        Action::Initialize {
            vault: Uuid::new_v4(),
            recovery_key: B64.encode(recovery.public_key().as_ref()),
            root_envelope: B64.encode([7; 48]),
            device: d1.clone(),
        },
    )
    .await?;
    let mut wrong = init.clone();
    wrong.recovery_signature = None;
    assert_eq!(
        s.execute(&p, &audit(&c), wrong).await.err(),
        Some(Error::Denied)
    );
    assert_eq!(
        s.execute(&other, &audit(&c), init.clone()).await.err(),
        Some(Error::Denied)
    );
    s.execute(&p, &audit(&c), init.clone()).await?;
    s.execute(&p, &audit(&c), init).await?;
    let join = signed(
        &c,
        &s,
        &p,
        &d2,
        &k2,
        Some(&recovery),
        Action::Join { device: d2.clone() },
    )
    .await?;
    s.execute(&p, &audit(&c), join.clone()).await?;
    let ids = (0..5).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
    for chunk in ids.chunks(4) {
        run(
            &c,
            &s,
            &p,
            &d1,
            &k1,
            Action::Write {
                items: chunk
                    .iter()
                    .map(|id| Mutation {
                        id: *id,
                        expected_revision: 0,
                        ciphertext: Some(B64.encode([2; 40])),
                    })
                    .collect(),
            },
        )
        .await?;
    }
    let page = run(
        &c,
        &s,
        &p,
        &d1,
        &k1,
        Action::Read {
            after: 0,
            cursor: None,
        },
    )
    .await?;
    let (cursor, revision) = match page {
        Response::Changes {
            entries,
            next_cursor,
            revision,
            ..
        } => {
            assert_eq!(entries.len(), 4);
            (next_cursor.unwrap(), revision)
        }
        _ => panic!("changes"),
    };
    let before = match run(
        &c,
        &s,
        &p,
        &d1,
        &k1,
        Action::Read {
            after: 0,
            cursor: Some(cursor.clone()),
        },
    )
    .await?
    {
        Response::Changes { entries, .. } => {
            assert_eq!(entries.len(), 1);
            entries[0].revision
        }
        _ => panic!("page"),
    };
    assert!(before <= revision);
    let item_revision = if ids.len() > 4 { 1 } else { revision };
    let update = Action::Write {
        items: vec![Mutation {
            id: ids[0],
            expected_revision: item_revision,
            ciphertext: Some(B64.encode([3; 40])),
        }],
    };
    let a = signed(&c, &s, &p, &d1, &k1, None, update.clone()).await?;
    let mut backup = c.operator.acquire().await?;
    sqlx::query(
        "CREATE TEMP TABLE vault_saved_challenges AS SELECT * FROM rss_da.vault_challenges",
    )
    .execute(&mut *backup)
    .await?;
    sqlx::query("CREATE TEMP TABLE vault_saved_receipts AS SELECT * FROM rss_da.vault_receipts")
        .execute(&mut *backup)
        .await?;
    let b = signed(&c, &s, &p, &d2, &k2, None, update).await?;
    let aa = audit(&c);
    let ab = audit(&c);
    let (a_result, b_result) = tokio::join!(s.execute(&p, &aa, a.clone()), s.execute(&p, &ab, b));
    assert_ne!(a_result.is_ok(), b_result.is_ok());
    if a_result.is_ok() {
        s.execute(&p, &audit(&c), a.clone()).await?;
    }
    let stale = signed(
        &c,
        &s,
        &p,
        &d1,
        &k1,
        None,
        Action::Read {
            after: 0,
            cursor: Some(cursor),
        },
    )
    .await?;
    assert_eq!(
        s.execute(&p, &audit(&c), stale).await.err(),
        Some(Error::Cursor)
    );
    let batch = signed(
        &c,
        &s,
        &p,
        &d1,
        &k1,
        None,
        Action::Write {
            items: vec![
                Mutation {
                    id: Uuid::new_v4(),
                    expected_revision: 0,
                    ciphertext: Some(B64.encode([4; 40])),
                },
                Mutation {
                    id: ids[0],
                    expected_revision: 99,
                    ciphertext: None,
                },
            ],
        },
    )
    .await;
    let batch = batch?;
    assert_eq!(
        s.execute(&p, &audit(&c), batch).await.err(),
        Some(Error::Conflict)
    );
    run(
        &c,
        &s,
        &p,
        &d1,
        &k1,
        Action::Write {
            items: vec![Mutation {
                id: ids[1],
                expected_revision: 1,
                ciphertext: None,
            }],
        },
    )
    .await?;
    let resurrect = signed(
        &c,
        &s,
        &p,
        &d2,
        &k2,
        None,
        Action::Write {
            items: vec![Mutation {
                id: ids[1],
                expected_revision: 1,
                ciphertext: Some(B64.encode([9; 40])),
            }],
        },
    )
    .await?;
    assert_eq!(
        s.execute(&p, &audit(&c), resurrect).await.err(),
        Some(Error::Conflict)
    );
    run(&c, &s, &p, &d1, &k1, Action::Remove { device: d2.id }).await?;
    assert_eq!(
        s.execute(&p, &audit(&c), join).await.err(),
        Some(Error::Denied)
    );
    // Restore fencing must reject even a previously successful, receipted request.
    let mut conn = backup;
    sqlx::query("DELETE FROM rss_da.vault_challenges")
        .execute(&mut *conn)
        .await?;
    sqlx::query("INSERT INTO rss_da.vault_challenges SELECT * FROM vault_saved_challenges")
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM rss_da.vault_receipts")
        .execute(&mut *conn)
        .await?;
    sqlx::query("INSERT INTO rss_da.vault_receipts SELECT * FROM vault_saved_receipts")
        .execute(&mut *conn)
        .await?;
    let epoch = Uuid::new_v4();
    rss_mdm_vault_sync::restore_incarnation(&mut conn, epoch).await?;
    assert_eq!(
        s.execute(&p, &audit(&c), a).await.err(),
        Some(Error::Denied)
    );
    let d3 = device(&k2);
    let join = signed(
        &c,
        &s,
        &p,
        &d3,
        &k2,
        Some(&recovery),
        Action::Join { device: d3.clone() },
    )
    .await?;
    s.execute(&p, &audit(&c), join).await?;
    run(
        &c,
        &s,
        &p,
        &d3,
        &k2,
        Action::Read {
            after: 0,
            cursor: None,
        },
    )
    .await?;
    drop(conn);
    c.close().await;
    Ok(())
}
