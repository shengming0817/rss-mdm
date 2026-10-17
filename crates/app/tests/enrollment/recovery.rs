use crate::device::test_support::{admin, case_a as case_tenant, options};
use crate::enrollment::test_support::create;
use crate::{Database, enrollment::Password};
use anyhow::ensure;
use rss_mdm_registration_service::Error;
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
    ensure!(matches!(
        create(&store, &proof, "different", &password, Uuid::new_v4(), key)
            .await
            .unwrap_err()
            .downcast_ref::<Error>(),
        Some(Error::Conflict)
    ));
    ensure!(matches!(
        crate::enrollment::store::enrollment_target(
            &store.registration(),
            &other,
            receipt.enrollment_id
        )
        .await,
        Err(Error::Forbidden)
    ));
    ensure!(matches!(
        crate::enrollment::store::enrollment_authorization(
            &store.registration(),
            crate::test_support::case::peer(),
            receipt.enrollment_id,
            &password
        )
        .await,
        Err(Error::Forbidden)
    ));
    ensure!(matches!(
        crate::enrollment::store::enrollment_authorization(
            &store.registration(),
            case_tenant(),
            receipt.enrollment_id,
            &Password::new(crate::enrollment::random())?
        )
        .await,
        Err(Error::Unauthorized)
    ));
    let auth = crate::enrollment::store::enrollment_authorization(
        &store.registration(),
        case_tenant(),
        receipt.enrollment_id,
        &password,
    )
    .await?;
    ensure!(
        auth.device == "windows-device"
            && auth.source == rss_mdm_inventory::ReportSource::MdmWindows
            && auth.windows_profile == Some(crate::enrollment::WindowsProfile::Full)
    );
    store.close().await;
    Ok(())
}
