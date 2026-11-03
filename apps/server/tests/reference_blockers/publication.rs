//! Legal retained publication material; use the real release owner to withdraw it.
use super::*;
use rss_mdm_software_release as rel;
pub(super) async fn withdrawn(c: &Context, resource: &r::Version) -> Result<()> {
    let document = rss_mdm_software_service::publication::derive_document(
        resource,
        &[],
        "https://packages.example.test/",
    )?;
    let content = rel::Content::new(
        rel::SoftwareIdentity::new(rel::SoftwareIdentityFields {
            source: "private".into(),
            package: "Acme.App".into(),
            version: "1.2".into(),
            platform: "windows".into(),
        })?,
        rel::Digest::of(&serde_json::to_vec(&json!([
            resource.digest().bytes(),
            [],
            document
        ]))?),
        rel::Digest::from_bytes([2; 32]),
        rel::Digest::of(&serde_json::to_vec(&document)?),
        vec![rel::VariantContent::new(
            "x86_64",
            "msi",
            vec![rel::Artifact::new(
                "package",
                rel::Digest::from_bytes([2; 32]),
            )?],
        )?],
    )?;
    let at = rss_contract::Timepoint::try_from(support::now())?;
    let actor = rel::ActorId::new(c.tenant, "fixture")?;
    let id = rel::PublicationKey::new(c.tenant, "retained-publication")?;
    let publication = rel::Publication::new(
        content.clone(),
        rel::PublicationBinding {
            publication: id.clone(),
            content: content.digest(),
            target: rel::TargetId::new(c.tenant, "private")?,
            target_digest: rel::Digest::from_bytes([2; 32]),
            evidence: rel::Evidence {
                actor: actor.clone(),
                digest: content.digest(),
                at,
            },
            lifecycle: rel::Digest::from_bytes([8; 32]),
            actor: actor.clone(),
            at,
        },
    )?;
    let owner = planning::owner(c, "mdm_software_runtime").await?;
    let store = rss_mdm_software_release_postgres::ReleaseStore::new(
        owner.runtime.clone(),
        c.tenant,
        crate::authority_t2_support::deadline(),
    )
    .await?;
    store
        .create(
            &rel::RequestId::new(c.tenant, Uuid::new_v4().to_string())?,
            &publication,
            crate::authority_t2_support::deadline(),
        )
        .await?;
    let bytes = serde_json::to_vec(
        &json!({"target":"private","format":1,"resource":resource.resource().as_str(),"version":resource.label().as_str(),"resource_digest":resource.digest().bytes(),"expected_resource_revision":2,"coordinate":"Acme.App/1.2","document":document}),
    )?;
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_software_composition.subjects(tenant_id,record,resource,version,document,digest) VALUES($1::uuid,'retained-publication',$2,$3,$4,sha256($4))").bind(c.tenant.to_string()).bind(resource.resource().as_str()).bind(resource.label().as_str()).bind(bytes).execute(&mut *tx).await?;
    tx.commit().await?;
    store
        .transition(
            &id,
            &rel::Request {
                id: rel::RequestId::new(c.tenant, Uuid::new_v4().to_string())?,
                actor,
                expected_revision: publication.snapshot().revision,
                as_of: at,
                operation: rel::Operation::Withdraw,
            },
            crate::authority_t2_support::deadline(),
        )
        .await?;
    assert!(
        store
            .get(&id, crate::authority_t2_support::deadline())
            .await?
            .unwrap()
            .snapshot()
            .withdrawn
    );
    owner.runtime.close().await;
    Ok(())
}
