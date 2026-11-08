//! Remaining execution capabilities contribute only their own assignment facts.
use super::Queries;
use crate::deployment::{
    Result,
    sources::{onboarding, software, storage},
};
use uuid::Uuid;
pub struct State {
    pub operations: Vec<Uuid>,
    pub task_admission: Option<rss_mdm_policy::pages::TaskAdmission>,
    pub diagnosis: Option<String>,
}
impl Queries {
    pub async fn assignment_state_on(
        &self,
        c: &mut sqlx::PgConnection,
        p: &rss_mdm_policy::Policy,
        target: &rss_mdm_registration_service::device::endpoints::PrimaryRegistration,
        channel: rss_mdm_inventory::Channel,
        now: i64,
    ) -> Result<State> {
        let mut state = State {
            operations: Vec::new(),
            task_admission: None,
            diagnosis: None,
        };
        let device = &target.device;
        if matches!(p.definition.action, rss_mdm_policy::Action::Software { .. }) {
            let software = software::read_on(&self.policy_reader, c, p.version).await?;
            state.task_admission = Some(
                software
                    .assignment
                    .management_state_on(&self.admission, c, self.tenant, device, now)
                    .await?,
            );
        } else if matches!(
            p.definition.action,
            rss_mdm_policy::Action::EnsureAgentInstalled { .. }
        ) {
            let frozen = storage::version_on(&self.policy_reader, c, p.version)
                .await?
                .1;
            state.task_admission = Some(
                onboarding::state_on(
                    &self.admission,
                    c,
                    self.tenant,
                    device,
                    &frozen,
                    p.version,
                    now,
                )
                .await?,
            );
        }
        {
            let tenant = self.tenant.to_string();
            let id = p.id;
            let channel_name = channel.as_str();
            state.operations=sqlx::query_scalar::<_,Uuid>("SELECT o.id FROM mdm_software_deployment.operations o WHERE o.tenant_id=$1::uuid AND o.device=$3 AND $4='mdm' AND EXISTS(SELECT 1 FROM mdm_policy.versions v WHERE v.tenant_id=o.tenant_id AND v.id=o.policy_version AND v.policy=$2) UNION SELECT r.id FROM mdm_software_deployment.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.device=$3 AND v.action_kind=ANY(CASE WHEN $4='mdm' THEN ARRAY['ensure_agent_installed'] ELSE ARRAY['software'] END) ORDER BY id").bind(tenant).bind(id).bind(device).bind(channel_name).fetch_all(&mut *c).await?;
        }
        Ok(state)
    }
}
