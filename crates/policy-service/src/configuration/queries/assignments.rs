use super::*;
impl Transactions {
    pub async fn assignment_on(
        &self,
        c: &mut PgConnection,
        policy: Uuid,
        target: &rss_mdm_registration_service::device::endpoints::PrimaryRegistration,
    ) -> Result<Assignment> {
        let tenant = self.tenant.to_string();
        let device = &target.device;
        let diagnosis=sqlx::query_scalar("SELECT d.diagnosis FROM mdm_planning.configuration_claims c JOIN mdm_planning.configuration_objects d USING(tenant_id,device,user_key,platform,object_kind,object_key) WHERE c.tenant_id=$1::uuid AND c.policy=$2 AND c.device=$3 AND d.diagnosis IS NOT NULL ORDER BY d.diagnosis LIMIT 1").bind(&tenant).bind(policy).bind(device).fetch_optional(&mut *c).await?;
        let operations=sqlx::query_scalar("SELECT DISTINCT o.id FROM mdm_planning.configuration_operations o JOIN mdm_planning.configuration_claims c ON(c.tenant_id,c.operation,c.device)=(o.tenant_id,o.id,o.device) WHERE o.tenant_id=$1::uuid AND c.policy=$2 AND o.device=$3 ORDER BY o.id").bind(tenant).bind(policy).bind(device).fetch_all(c).await?;
        Ok(Assignment {
            diagnosis,
            operations,
        })
    }
}
