//! Legal metadata rows exercise the public owner and its actual SQL bindings through HTTP.
use super::*;
use crate::command_runtime_t2_support::seed_transaction;
pub(super) async fn seed(
    c: &Context,
    p: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
    cases: &mut Vec<(String, String, Value)>,
) -> Result<()> {
    let mut tx = seed_transaction(c).await?;
    let tenant = Uuid::parse_str(&c.tenant.to_string())?;
    for i in 0..2 {
        let id = Uuid::from_u128(7000 + i);
        let name = if i == 1 {
            "DirectoryTarget"
        } else {
            "Sentinel"
        };
        let value = json!({"key":format!("directory{i}"),"displayName":name,"source":{"kind":"identity_local"},"pointer":"/department","valueType":"string","maxLength":128,"maxItems":null,"minimum":null,"maximum":null,"enabled":true,"sensitive":false,"visibility":"profiles_read","displayUse":"profile","required":false,"useExistingObservation":false});
        sqlx::query("INSERT INTO mdm_user_profiles.definitions VALUES($1,$2,1,1,$3)")
            .bind(tenant)
            .bind(id)
            .bind(value)
            .execute(&mut *tx)
            .await?;
        let targets = if i == 1 {
            json!([{"platform":"windows","architecture":"x86_64"},{"platform":"macos","architecture":"aarch64"}])
        } else {
            json!([{"platform":"macos","architecture":"x86_64"}])
        };
        sqlx::query("INSERT INTO mdm_access.agent_configurations(tenant_id,id,operation_id,creator,instance,secret_digest,signature,request_digest,document,quantity,state,expires_at) VALUES($1,$2,$3,$4,$5,repeat('a',64),repeat('a',86),repeat('b',64),$6,3,'available',clock_timestamp()+interval '1 hour')")
            .bind(tenant).bind(id).bind(Uuid::new_v4()).bind(name).bind(p.instance_id()).bind(json!({"targets":targets,"quantity":{"kind":"finite","count":3}})).execute(&mut *tx).await?;
        let source = format!("directory-source-{i}");
        let document = format!("[{{\"name\":\"{name}\",\"version\":\"2.0\"}}]");
        use sha2::{Digest, Sha256};
        sqlx::query("INSERT INTO mdm_software_snapshots.current VALUES($1,$2,1,$3,$4,$5,1,1)")
            .bind(tenant)
            .bind(&source)
            .bind(&document)
            .bind(Sha256::digest(document.as_bytes()).to_vec())
            .bind(json!({"name":"/name","version":"/version"}))
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO mdm_software_snapshots.entries VALUES($1,$2,$3,1,$4,NULL,$5,'2.0')",
        )
        .bind(tenant)
        .bind(&source)
        .bind(id)
        .bind((document.len() - 2) as i64)
        .bind(name)
        .execute(&mut *tx)
        .await?;
        if i == 1 {
            for (path,filter,expected) in [
                ("/api/v1/user-attribute-definitions".into(),"displayName==DirectoryTarget;value.source.kind==identity_local;enabled==true".into(),json!(id)),
                ("/api/v1/agent-configurations".into(),"createdBy==DirectoryTarget;remaining=gt=0;platform==windows;architecture==x86_64".into(),json!(id)),
                ("/api/v1/software/source-snapshots".into(),format!("source=={source};entryCount==1;extraction.name=='/name'"),json!(source)),
                (format!("/api/v1/software/source-snapshots/{source}/entries"),"name==DirectoryTarget;version==2.0".into(),json!(id)),
            ] {cases.push((path,filter,expected));}
        }
    }
    let organization: Uuid =
        sqlx::query_scalar("SELECT id FROM mdm_apple.organizations WHERE tenant_id=$1 LIMIT 1")
            .bind(tenant)
            .fetch_one(&mut *tx)
            .await?;
    sqlx::query("INSERT INTO mdm_apple.account_configuration VALUES($1,$2,'directory.example.test',$3,$4,'unconfigured',true,2)").bind(tenant).bind(organization).bind(Uuid::new_v4()).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    for (account, serial) in [
        ("sentinel@example.test", "DIRECTORY-SENTINEL"),
        ("directory@example.test", "DIRECTORY-TARGET"),
    ] {
        sqlx::query("INSERT INTO mdm_apple.account_bindings VALUES($1,$2,$3,$4,$5,$6,true,2)")
            .bind(tenant)
            .bind(organization)
            .bind(account)
            .bind(Uuid::new_v4())
            .bind(Uuid::new_v4())
            .bind(Uuid::parse_str(p.instance_id())?)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO mdm_apple.ade_devices(tenant_id,organization,serial,operation_date,deleted,seen_run,observed_at) VALUES($1,$2,$3,clock_timestamp(),false,$4,20)").bind(tenant).bind(organization).bind(serial).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    }
    cases.extend([
        ("/api/v1/apple/organizations".into(),"ade.orgId==directory-test;ade.enabled==false;accountEnrollment.signingKeyConfigured==false".into(),json!(organization)),
        (format!("/api/v1/apple/organizations/{organization}/accounts"),"account==directory@example.test;enabled==true;revision==2".into(),json!("directory@example.test")),
        (format!("/api/v1/apple/organizations/{organization}/ade/devices"),"serial==DIRECTORY-TARGET;deleted==false;observedAt=gt=10".into(),json!("DIRECTORY-TARGET")),
        ("/api/v1/software/sources".into(),"id==private;state==enabled".into(),json!("private")),
        ("/api/v1/software/resources/z-directory-software/versions".into(),"version==1;resource==z-directory-software".into(),json!("1")),
        ("/api/v1/asset-fields".into(),"key==device.name;nullable==false".into(),json!("device.name")),
    ]);
    tx.commit().await?;
    Ok(())
}
