use crate::device::test_support::{admin, case_a as case_tenant, options};
use crate::enrollment::test_support::create;
use crate::{Database, enrollment::Password};
use anyhow::ensure;
use uuid::Uuid;
#[tokio::test]
#[ignore = "make t2 MODULE=enrollment.recovery"]
async fn immutable_receipts_and_authorization_coordinates() -> anyhow::Result<()> {
    let proof = admin(case_tenant(), "admin-a").await?;
    let other = admin(case_tenant(), "other-a").await?;
    let store = Database::connect(options("mdm_access")?).await?;
    let password = Password::new(crate::enrollment::random())?;
    let key = Uuid::new_v4();
    let receipt = create(
        &store,
        &proof,
        "windows-device",
        &password,
        Uuid::new_v4(),
        key,
    )
    .await?;
    ensure!(
        create(
            &store,
            &proof,
            "windows-device",
            &password,
            Uuid::new_v4(),
            key
        )
        .await?
            == receipt
    );
    ensure!(
        create(&store, &proof, "different", &password, Uuid::new_v4(), key)
            .await
            .is_err()
    );
    ensure!(
        crate::enrollment::store::enrollment_target(
            &store.registration(),
            &other,
            receipt.enrollment_id
        )
        .await
        .is_err()
    );
    ensure!(
        crate::enrollment::store::enrollment_authorization(
            &store.registration(),
            crate::test_support::case::peer(),
            receipt.enrollment_id,
            &password
        )
        .await
        .is_err()
    );
    ensure!(
        crate::enrollment::store::enrollment_authorization(
            &store.registration(),
            case_tenant(),
            receipt.enrollment_id,
            &Password::new(crate::enrollment::random())?
        )
        .await
        .is_err()
    );
    let _auth = crate::enrollment::store::enrollment_authorization(
        &store.registration(),
        case_tenant(),
        receipt.enrollment_id,
        &password,
    )
    .await?;
    store.close().await;
    Ok(())
}
