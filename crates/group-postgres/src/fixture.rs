//! Published static membership for downstream integration prerequisites.
use crate::{
    storage::{data, digest, stored_shape},
    *,
};
use rss_transactional_messaging_postgres::{PgError, PgTransaction};

/// Insert one current static group and its immutable published member set, without jobs or events.
pub async fn static_members_in(
    tx: &mut PgTransaction<'_>,
    id: GroupId,
    presentation: serde_json::Map<String, serde_json::Value>,
    members: Vec<String>,
    at: rss_contract::Timepoint,
) -> Result<(), PgError> {
    if members.is_empty()
        || members.len() > 1000
        || members.iter().any(|m| m.is_empty())
        || members
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != members.len()
        || !crate::presentation::valid(&presentation, 65536)
    {
        return Err(stored_shape());
    }
    let run = data(OperationId::parse(&uuid::Uuid::new_v4().to_string()))?;
    let group = Group {
        id,
        kind: GroupKind::Static,
        system_selector: None,
        asset_context: AssetContext::Endpoint,
        presentation,
        revision: data(Revision::new(2))?,
        calculation_revision: 1,
        member_version: 1,
        member_count: members.len(),
        rule_version: None,
        deleted: false,
    };
    let request = BuildRequest {
        id: run,
        group: id,
        expected: data(Revision::new(1))?,
        base_calculation: 0,
        changed_devices: None,
        rule_version: None,
        patch: Some(MemberPatch {
            add: members.clone(),
            remove: vec![],
        }),
        input_version: "static-members".into(),
        sources: vec![],
        as_of: at,
    };
    let input = data(serde_json::to_vec(&request))?;
    let hash = digest(&input);
    let receipt = data(serde_json::to_vec(&Receipt {
        operation: run,
        group: group.clone(),
        added: members.len(),
        removed: 0,
    }))?;
    crate::storage::save_group(tx, &group, true).await?;
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("INSERT INTO mdm_group.member_runs(tenant_id,id,group_id,base_revision,base_calculation,floor_revision,input_version,fingerprint,input,phase,processed_count,object_count,member_count,added,as_of,receipt) VALUES($1::uuid,$2::uuid,$3::uuid,1,0,0,'static-members',$4,$5,'published',$6,$6,$6,$6,$7,$8)")
            .bind(&tenant).bind(run.to_string()).bind(id.to_string()).bind(hash).bind(input).bind(members.len() as i64).bind(at.unix_seconds()).bind(receipt).execute(&mut *c).await?;
        sqlx::query("INSERT INTO mdm_group.member_changes(tenant_id,run_id,object_id,group_id,revision,added) SELECT $1::uuid,$2::uuid,d,$3::uuid,1,true FROM unnest($4::text[]) d")
            .bind(&tenant).bind(run.to_string()).bind(id.to_string()).bind(members).execute(&mut *c).await?;
        sqlx::query("UPDATE mdm_group.groups SET member_set=$3::uuid WHERE tenant_id=$1::uuid AND id=$2::uuid")
            .bind(tenant).bind(id.to_string()).bind(run.to_string()).execute(c).await?;
        Ok(())
    })).await
}
