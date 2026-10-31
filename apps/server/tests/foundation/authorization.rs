//! Current product authority and the actual authorization/Audit source transaction.
use super::support::*;
use anyhow::Result;
use rss_mdm_authorization_service::{self as access, Change, Permission, Rule, Scope, Subject};
use uuid::Uuid;

#[tokio::test]
#[ignore = "T2: actual Identity and product PostgreSQL authority"]
async fn same_session_reloads_current_grants_and_durable_authority_expires() -> Result<()> {
    let context = Context::open("shared").await?;
    let manager = context.account(&[Permission::AuthorizationWrite]).await?;
    let reader = context.account(&[Permission::ResourceRead]).await?;
    let proof = context.authenticate(&reader).await?;
    proof.require(Permission::ResourceRead, None)?;
    let authority = access::OperationAuthority::tenant(
        proof.authorization()?,
        &proof,
        Permission::ResourceRead,
    )?;
    let mut connection = context.operator.acquire().await?;
    let now: i64 = sqlx::query_scalar("SELECT extract(epoch FROM clock_timestamp())::bigint")
        .fetch_one(&mut *connection)
        .await?;
    assert!(
        authority
            .valid(&mut connection, Permission::ResourceRead, now)
            .await?
    );
    let manager = context.authenticate(&manager).await?;
    access::store::change_rule(
        &context.audit,
        &manager,
        reader.rule,
        Change::<Rule> {
            operation_id: Uuid::new_v4(),
            expected_revision: 1,
            value: None,
        },
        &context.request(&manager)?,
    )
    .await?;
    let reloaded = context.authenticate(&reader).await?;
    assert!(matches!(
        reloaded.require(Permission::ResourceRead, None),
        Err(access::Error::Forbidden)
    ));
    assert!(
        !authority
            .valid(&mut connection, Permission::ResourceRead, now)
            .await?
    );
    let other = rss_request_context::TenantId::parse(&Uuid::new_v4().to_string())?;
    assert!(
        access::session::SessionAuthority::new(context.authority.clone(), other)
            .authenticate(&context.access(), reader.credential()?)
            .await
            .is_err()
    );
    drop(connection);
    context.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: actual source transaction and SQL audit failure"]
async fn authorization_receipt_and_final_fact_share_commit_and_rollback() -> Result<()> {
    let context = Context::open("transaction").await?;
    let manager = context.account(&[Permission::AuthorizationWrite]).await?;
    let proof = context.authenticate(&manager).await?;
    let id = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let rule = Rule {
        subject: Subject::User {
            user: manager.user.clone(),
        },
        grants: vec![access::Grant {
            operation: Permission::ResourceRead,
            scope: Scope::Tenant,
        }],
    };
    let change = Change {
        operation_id: operation,
        expected_revision: 0,
        value: Some(rule),
    };
    let audit = context.request(&proof)?;
    let receipt =
        access::store::change_rule(&context.audit, &proof, id, change.clone(), &audit).await?;
    assert_eq!(receipt.revision, 1);
    let event = format!(
        "authorization_write:{}:{operation}",
        manager.user.principal_id
    );
    assert_eq!(context.audit_count(&event).await?, 1);
    let stored: (i64, i64) = sqlx::query_as("SELECT (SELECT revision FROM mdm_access.authorization_rules WHERE tenant_id=$1::uuid AND id=$2),(SELECT count(*) FROM mdm_access.authorization_operations WHERE tenant_id=$1::uuid AND operation_id=$3)")
        .bind(context.tenant.to_string()).bind(id).bind(operation).fetch_one(&context.operator).await?;
    assert_eq!(stored, (1, 1));
    let replay = access::store::change_rule(
        &context.audit,
        &proof,
        id,
        change.clone(),
        &context.request(&proof)?,
    )
    .await?;
    assert_eq!(
        serde_json::to_value(replay)?,
        serde_json::to_value(receipt)?
    );
    assert_eq!(context.audit_count(&event).await?, 1);
    let mut conflicting = change;
    conflicting.value = None;
    assert!(matches!(
        access::store::change_rule(
            &context.audit,
            &proof,
            id,
            conflicting,
            &context.request(&proof)?
        )
        .await,
        Err(access::Error::Conflict)
    ));
    context.disable_audit().await?;
    let failed_id = Uuid::new_v4();
    let failed_operation = Uuid::new_v4();
    let failed = access::store::change_rule(
        &context.audit,
        &proof,
        failed_id,
        Change {
            operation_id: failed_operation,
            expected_revision: 0,
            value: Some(Rule {
                subject: Subject::User {
                    user: manager.user.clone(),
                },
                grants: vec![access::Grant {
                    operation: Permission::ResourceRead,
                    scope: Scope::Tenant,
                }],
            }),
        },
        &context.request(&proof)?,
    )
    .await;
    assert!(
        failed.is_err(),
        "the audited change must fail after SQL permission withdrawal"
    );
    let counts: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM mdm_access.authorization_rules WHERE tenant_id=$1::uuid AND id=$2),(SELECT count(*) FROM mdm_access.authorization_operations WHERE tenant_id=$1::uuid AND operation_id=$3)")
        .bind(context.tenant.to_string()).bind(failed_id).bind(failed_operation).fetch_one(&context.operator).await?;
    assert_eq!(counts, (0, 0));
    assert_eq!(
        context
            .audit_count(&format!(
                "authorization_write:{}:{failed_operation}",
                manager.user.principal_id
            ))
            .await?,
        0
    );
    context.close().await;
    Ok(())
}
