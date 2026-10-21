mod gc;
mod http;
mod mirror;
mod storage;
fn expire_upload(id: uuid::Uuid) -> anyhow::Result<()> {
    crate::test_support::process::pg(&format!(
        "UPDATE mdm_content.uploads SET expires=0 WHERE tenant_id='{}' AND document->'value'->'upload'->>'id'='{}'; UPDATE mdm_content.objects SET expires=0 WHERE tenant_id='{}' AND owner IN(SELECT id FROM mdm_content.uploads WHERE tenant_id='{}' AND document->'value'->'upload'->>'id'='{}'); UPDATE mdm_content.manifests SET expires=0 WHERE tenant_id='{}' AND document->'value'->'pieces' @> ANY(SELECT jsonb_build_array(jsonb_build_object('id',o.id)) FROM mdm_content.objects o JOIN mdm_content.uploads u ON u.id=o.owner WHERE u.tenant_id='{}' AND u.document->'value'->'upload'->>'id'='{}')",
        crate::test_support::runtime::case_tenant(),
        id,
        crate::test_support::runtime::case_tenant(),
        crate::test_support::runtime::case_tenant(),
        id,
        crate::test_support::runtime::case_tenant(),
        crate::test_support::runtime::case_tenant(),
        id
    ))?;
    Ok(())
}
