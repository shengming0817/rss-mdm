//! Remaining execution capabilities contribute only their own assignment facts.
use super::{Queries, records};
use crate::{
    Error, Result,
    sources::{onboarding, software, storage},
};
use uuid::Uuid;
pub struct State {
    pub operations: Vec<Uuid>,
    pub task_admission: Option<software::TaskAdmission>,
    pub diagnosis: Option<String>,
}
impl Queries {
    pub async fn lifecycle_assignments_on(
        &self,
        c: &mut sqlx::PgConnection,
        p: &rss_mdm_policy::Policy,
        after: Option<&str>,
        limit: usize,
        codec: &rss_mdm_query::cursor::CursorCodec,
        binding: &str,
    ) -> Result<records::AssignmentPage> {
        super::lifecycle::assignments_on(self, c, p, after, limit, codec, binding).await
    }
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
                | rss_mdm_policy::Action::RequestMdmEnrollment { .. }
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
        if matches!(
            p.definition.action,
            rss_mdm_policy::Action::Configuration { .. }
        ) {
            let configuration = self.configuration.assignment_on(c, p.id, target).await?;
            state.operations = configuration.operations;
            state.diagnosis = configuration.diagnosis;
        } else {
            let tenant = self.tenant.to_string();
            let id = p.id;
            let registration = target.registration_id;
            let generation = target.generation;
            let channel_name = channel.as_str();
            state.operations=sqlx::query_scalar::<_,Uuid>("SELECT o.id FROM mdm_commands.operations o WHERE o.tenant_id=$1::uuid AND o.device=$3 AND ((o.registration=$4 AND o.registration_generation=$5) OR EXISTS(SELECT 1 FROM mdm_access.registrations child WHERE child.tenant_id=o.tenant_id AND child.id=o.registration AND child.generation=o.registration_generation AND child.device=o.device AND child.channel='mdm' AND child.purpose='windows_declared' AND child.parent_id=$4 AND child.parent_generation=$5)) AND $6='mdm' AND (o.authority->>'kind'<>'agent_install' OR o.authority->>'stage'='install') AND EXISTS(SELECT 1 FROM mdm_policy.versions v WHERE v.tenant_id=o.tenant_id AND v.id=o.policy_version AND v.policy=$2) UNION SELECT r.id FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.device=$3 AND ((r.registration=$4 AND r.generation=$5) OR ($6='mdm' AND EXISTS(SELECT 1 FROM mdm_access.registrations child WHERE child.tenant_id=r.tenant_id AND child.id=r.registration AND child.generation=r.generation AND child.device=r.device AND child.channel='mdm' AND child.purpose='windows_declared' AND child.parent_id=$4 AND child.parent_generation=$5))) AND v.action_kind=ANY(CASE WHEN $6='mdm' THEN ARRAY['ensure_agent_installed'] ELSE ARRAY['software','request_mdm_enrollment'] END) ORDER BY id").bind(tenant).bind(id).bind(device).bind(registration).bind(generation).bind(channel_name).fetch_all(&mut *c).await?;
        }
        Ok(state)
    }
}
