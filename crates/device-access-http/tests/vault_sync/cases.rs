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
async fn user(c: &Context) -> Result<(AuthorizedPrincipal, String)> {
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
    let secret = issued.secret().expose().to_owned();
    let actor = c
        .sessions
        .authenticate(
            &c.authorization,
            rss_mdm_authorization_service::credential::RequestCredential::Bearer(
                rss_identity_core::session::BearerSecret::parse(issued.secret().expose().into())?,
            ),
        )
        .await?;
    Ok((actor, secret))
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
    let c = Box::pin(Context::open()).await?;
    let s = Service::new(
        c.tenant,
        Uuid::parse_str(&c.inputs.installation.instance_id)?,
        c.proof_audit.clone(),
        rss_mdm_query::cursor::CursorCodec::new(&[8; 32])?,
    );
    let (p, session_secret) = Box::pin(user(&c)).await?;
    let (other, _) = Box::pin(user(&c)).await?;
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
            root_envelope: B64.encode([7; 60]),
            device: d1.clone(),
        },
    )
    .await?;
    // Even valid recovery/device signatures cannot select a different tenant.
    let mut cross_tenant = init.clone();
    cross_tenant.challenge.tenant = Uuid::new_v4();
    let payload = cross_tenant.challenge.signing_bytes()?;
    cross_tenant.signature = B64.encode(k1.sign(&payload).as_ref());
    cross_tenant.recovery_signature = Some(B64.encode(recovery.sign(&payload).as_ref()));
    assert_eq!(
        s.execute(&p, &audit(&c), cross_tenant).await.err(),
        Some(Error::Denied)
    );
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
        Action::Join {
            device: d2.clone(),
            reset_devices: false,
        },
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
    let b = signed(&c, &s, &p, &d2, &k2, None, update).await?;
    let mut backup = c.operator.acquire().await?;
    sqlx::query("CREATE TEMP TABLE vault_saved_challenges AS SELECT * FROM rss_da.vault_nonces")
        .execute(&mut *backup)
        .await?;
    sqlx::query("CREATE TEMP TABLE vault_saved_receipts AS SELECT * FROM rss_da.vault_receipts")
        .execute(&mut *backup)
        .await?;
    let aa = audit(&c);
    let ab = audit(&c);
    let (a_result, b_result) =
        tokio::join!(s.execute(&p, &aa, a.clone()), s.execute(&p, &ab, b.clone()));
    assert_ne!(a_result.is_ok(), b_result.is_ok());
    let committed = if a_result.is_ok() {
        a.clone()
    } else {
        b.clone()
    };
    s.execute(&p, &audit(&c), committed.clone()).await?;
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
    let rejected_id = Uuid::new_v4();
    let owner = format!("{}:{}", p.instance_id(), p.principal_id());
    let before_revision: i64 = sqlx::query_scalar(
        "SELECT revision FROM rss_da.vaults WHERE tenant_id=$1::uuid AND owner=$2",
    )
    .bind(c.tenant.to_string())
    .bind(&owner)
    .fetch_one(&c.operator)
    .await?;
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
                    id: rejected_id,
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
    let rejected_operation = batch.challenge.request.operation;
    assert_eq!(
        s.execute(&p, &audit(&c), batch).await.err(),
        Some(Error::Conflict)
    );
    let unchanged:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT revision FROM rss_da.vaults WHERE tenant_id=$1::uuid AND owner=$2),(SELECT count(*) FROM rss_da.vault_entries WHERE tenant_id=$1::uuid AND owner=$2 AND id=$3),(SELECT count(*) FROM rss_da.vault_receipts WHERE tenant_id=$1::uuid AND owner=$2 AND operation=$4)").bind(c.tenant.to_string()).bind(&owner).bind(rejected_id).bind(rejected_operation).fetch_one(&c.operator).await?;
    assert_eq!(unchanged, (before_revision, 0, 0));
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
    // A revoked endpoint still has an account session, but unsigned Join
    // challenges must not reserve storage or block a legitimate control operation.
    let count_before: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_da.vault_nonces")
        .fetch_one(&c.operator)
        .await?;
    for _ in 0..32 {
        let d = device(&k2);
        s.prepare(
            &p,
            &audit(&c),
            Prepare {
                operation: Uuid::new_v4(),
                device: d.id,
                action: Action::Join {
                    device: d,
                    reset_devices: false,
                },
            },
        )
        .await?;
    }
    let count_after: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_da.vault_nonces")
        .fetch_one(&c.operator)
        .await?;
    assert_eq!(count_before, count_after);
    let restored_device = device(&k2);
    let legitimate = signed(
        &c,
        &s,
        &p,
        &restored_device,
        &k2,
        Some(&recovery),
        Action::Join {
            device: restored_device.clone(),
            reset_devices: false,
        },
    )
    .await?;
    s.execute(&p, &audit(&c), legitimate).await?;
    run(
        &c,
        &s,
        &p,
        &d1,
        &k1,
        Action::Remove {
            device: restored_device.id,
        },
    )
    .await?;
    assert!(
        s.prepare(
            &p,
            &audit(&c),
            Prepare {
                operation: Uuid::new_v4(),
                device: d2.id,
                action: Action::Devices
            }
        )
        .await
        .is_err()
    );
    // Restore fencing must reject even a previously successful, receipted request.
    let mut conn = backup;
    sqlx::query("DELETE FROM rss_da.vault_nonces")
        .execute(&mut *conn)
        .await?;
    sqlx::query("INSERT INTO rss_da.vault_nonces SELECT * FROM vault_saved_challenges")
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
        s.execute(&p, &audit(&c), committed).await.err(),
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
        Action::Join {
            device: d3.clone(),
            reset_devices: false,
        },
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
    // Audit append failure must roll back device admission and challenge consumption.
    let failing_device = device(&k1);
    let failing = signed(
        &c,
        &s,
        &p,
        &failing_device,
        &k1,
        Some(&recovery),
        Action::Join {
            device: failing_device.clone(),
            reset_devices: false,
        },
    )
    .await?;
    sqlx::raw_sql("CREATE FUNCTION public.reject_vault_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'vault audit rollback probe'; END $$; CREATE TRIGGER vault_audit_probe BEFORE INSERT ON rss_audit.records FOR EACH ROW EXECUTE FUNCTION public.reject_vault_audit();").execute(&mut *conn).await?;
    let failed = s.execute(&p, &audit(&c), failing.clone()).await;
    sqlx::raw_sql("DROP TRIGGER vault_audit_probe ON rss_audit.records; DROP FUNCTION public.reject_vault_audit();").execute(&mut *conn).await?;
    assert!(matches!(failed, Err(Error::Audit(_))));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_da.vault_devices WHERE id=$1")
        .bind(failing_device.id)
        .fetch_one(&mut *conn)
        .await?;
    assert_eq!(n, 0);
    s.execute(&p, &audit(&c), failing).await?;
    // Failed Audit writes retain their safe classification instead of becoming
    // ordinary storage failures; the HTTP adapter projects this to completion.
    let probe = signed(&c, &s, &p, &d3, &k2, None, Action::Devices).await?;
    let mut forged = probe.clone();
    forged.challenge.expires_at += 1;
    let bytes = forged.challenge.signing_bytes()?;
    forged.signature = B64.encode(k2.sign(&bytes).as_ref());
    assert_eq!(
        s.execute(&p, &audit(&c), forged).await.err(),
        Some(Error::Denied)
    );
    s.execute(&p, &audit(&c), probe.clone()).await?;
    assert_eq!(
        s.execute(&p, &audit(&c), probe).await.err(),
        Some(Error::Denied)
    );
    // Unknown commit is recovered through the same current device and operation.
    let unknown = signed(
        &c,
        &s,
        &p,
        &d3,
        &k2,
        None,
        Action::Write {
            items: vec![Mutation {
                id: Uuid::new_v4(),
                expected_revision: 0,
                ciphertext: Some(B64.encode([6; 40])),
            }],
        },
    )
    .await?;
    c.identity_runtime.inject_next_transaction_fault(
        rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
    );
    assert_eq!(
        s.execute(&p, &audit(&c), unknown.clone()).await.err(),
        Some(Error::CommitUnknown)
    );
    run(
        &c,
        &s,
        &p,
        &d3,
        &k2,
        Action::Operation {
            operation: unknown.challenge.request.operation,
        },
    )
    .await?;
    s.execute(&p, &audit(&c), unknown).await?;
    // Quota exhaustion must never disable device removal or recovery-code admission.
    let owner = format!("{}:{}", p.instance_id(), p.principal_id());
    sqlx::query("INSERT INTO rss_da.vault_receipts(tenant_id,owner,operation,incarnation,device,control,digest,document) SELECT $1::uuid,$2,gen_random_uuid(),$3,$4,false,'fixture','{}'::jsonb FROM generate_series(1,100000)").bind(c.tenant.to_string()).bind(&owner).bind(epoch).bind(d3.id).execute(&mut *conn).await?;
    run(&c, &s, &p, &d3, &k2, Action::Remove { device: d3.id }).await?;
    sqlx::query("INSERT INTO rss_da.vault_devices(tenant_id,owner,id,incarnation,public_key,active) SELECT $1::uuid,$2,gen_random_uuid(),$3,$4,true FROM generate_series(1,32)").bind(c.tenant.to_string()).bind(&owner).bind(epoch).bind(&d3.public_key).execute(&mut *conn).await?;
    let d4 = device(&k2);
    let ordinary = signed(
        &c,
        &s,
        &p,
        &d4,
        &k2,
        Some(&recovery),
        Action::Join {
            device: d4.clone(),
            reset_devices: false,
        },
    )
    .await?;
    assert_eq!(
        s.execute(&p, &audit(&c), ordinary).await.err(),
        Some(Error::Capacity)
    );
    let reset = signed(
        &c,
        &s,
        &p,
        &d4,
        &k2,
        Some(&recovery),
        Action::Join {
            device: d4.clone(),
            reset_devices: true,
        },
    )
    .await?;
    let response = s.execute(&p, &audit(&c), reset).await?;
    let Response::Receipt { receipt } = response else {
        panic!("receipt")
    };
    assert_ne!(receipt.incarnation, epoch);
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM rss_da.vault_devices WHERE tenant_id=$1::uuid AND owner=$2 AND active").bind(c.tenant.to_string()).bind(&owner).fetch_one(&mut *conn).await?;
    assert_eq!(count, 1);
    run(
        &c,
        &s,
        &p,
        &d4,
        &k2,
        Action::Read {
            after: 0,
            cursor: None,
        },
    )
    .await?;
    // Removing required privileges must fail startup admission before serving traffic.
    sqlx::query("REVOKE DELETE ON rss_da.vault_nonces FROM da_identity_runtime")
        .execute(&mut *conn)
        .await?;
    assert!(rss_mdm_vault_sync::verify_catalog(&mut conn).await.is_err());
    sqlx::query("GRANT DELETE ON rss_da.vault_nonces TO da_identity_runtime")
        .execute(&mut *conn)
        .await?;
    rss_mdm_vault_sync::verify_catalog(&mut conn).await?;
    let stale = signed(&c, &s, &p, &d4, &k2, None, Action::Devices).await?;
    let deadline = || {
        rss_transactional_messaging::policy::OperationDeadline::from_remaining(Duration::from_secs(
            10,
        ))
    };
    let session = c
        .authority
        .inspect_bearer(
            c.tenant,
            rss_identity_core::session::BearerSecret::parse(session_secret)?,
            deadline(),
        )
        .await?;
    c.authority
        .revoke_current_session(session, deadline())
        .await?;
    assert_eq!(
        s.execute(&p, &audit(&c), stale).await.err(),
        Some(Error::Denied)
    );
    drop(conn);
    c.close().await;
    Ok(())
}
