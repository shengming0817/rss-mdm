//! The installation-owned first-use claim is permanent and binding-specific.
use super::support::*;
use crate::administration::tenants::{self, Delete, Get, Query, Reason, Update};
use anyhow::Result;
use rss_request_context::TenantId;
use uuid::Uuid;

#[tokio::test]
#[ignore = "T2: actual registry transaction and SECURITY DEFINER use claim"]
async fn tenant_use_fence_blocks_delete_and_wrong_binding_does_not_claim() -> Result<()> {
    let inputs = Inputs::load()?;
    let operator = inputs.pool("shared", "postgres").await?;
    let used = TenantId::parse(&Uuid::new_v4().to_string())?;
    let unused = TenantId::parse(&Uuid::new_v4().to_string())?;
    seed_tenant(&operator, used).await?;
    seed_tenant(&operator, unused).await?;
    let operation = Uuid::new_v4();
    let update = || Update {
        database: inputs.database("shared", "mdm_owner"),
        installation: inputs.installation(),
        tenant_id: used.to_string(),
        expected_revision: 1,
        operation_id: operation,
        name: Some("Updated foundation tenant".into()),
        notes: None,
    };
    let receipt = tenants::update(update()).await?;
    let replay = tenants::update(update()).await?;
    assert_eq!(receipt, replay);
    let stored = tenants::query_operation(Query {
        database: inputs.database("shared", "mdm_owner"),
        installation: inputs.installation(),
        operation_id: operation,
    })
    .await?;
    assert_eq!(stored, Some(receipt));
    let mut conflict = update();
    conflict.notes = Some("different body".into());
    assert!(tenants::update(conflict).await.is_err());
    let mut wrong = inputs.installation();
    wrong.lineage = [9; 16];
    assert!(
        tenants::claim_database_use(
            &inputs.database("shared", "mdm_access"),
            &wrong,
            &unused.to_string(),
            1
        )
        .await
        .is_err()
    );
    let unused_state = tenants::get(Get {
        database: inputs.database("shared", "mdm_owner"),
        installation: inputs.installation(),
        tenant_id: unused.to_string(),
    })
    .await?;
    assert!(
        unused_state.deletable,
        "failed claim must not mark the tenant used"
    );
    tenants::delete(Delete {
        database: inputs.database("shared", "mdm_owner"),
        installation: inputs.installation(),
        tenant_id: unused.to_string(),
        expected_revision: 1,
        operation_id: Uuid::new_v4(),
    })
    .await?;
    let deleted = tenants::get(Get {
        database: inputs.database("shared", "mdm_owner"),
        installation: inputs.installation(),
        tenant_id: unused.to_string(),
    })
    .await
    .unwrap_err();
    assert_eq!(
        deleted.reason,
        Reason::NotFound,
        "the unused control tenant must actually be deleted"
    );
    tenants::claim_database_use(
        &inputs.database("shared", "mdm_access"),
        &inputs.installation(),
        &used.to_string(),
        1,
    )
    .await?;
    let error = tenants::delete(Delete {
        database: inputs.database("shared", "mdm_owner"),
        installation: inputs.installation(),
        tenant_id: used.to_string(),
        expected_revision: 2,
        operation_id: Uuid::new_v4(),
    })
    .await
    .unwrap_err();
    assert_eq!(error.reason, Reason::InUse);
    let remaining = tenants::get(Get {
        database: inputs.database("shared", "mdm_owner"),
        installation: inputs.installation(),
        tenant_id: used.to_string(),
    })
    .await?;
    assert_eq!(remaining.name.as_deref(), Some("Updated foundation tenant"));
    assert!(!remaining.deletable);
    operator.close().await;
    Ok(())
}
