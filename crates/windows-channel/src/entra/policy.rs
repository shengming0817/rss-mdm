use super::*;
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    pub enabled: bool,
    pub all_users: bool,
    pub users: Vec<Uuid>,
    pub terms_version: String,
    pub terms_text: String,
    /// Explicit administrator authority for noninteractive user-credential enrollment.
    pub allow_background: bool,
}
impl Policy {
    fn validate(&self) -> Result<(), Error> {
        if self.users.len() > 256
            || self.users.iter().any(Uuid::is_nil)
            || self
                .users
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.users.len()
            || self.all_users && !self.users.is_empty()
            || self.terms_text.len() > 32768
            || self
                .terms_text
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
            || self.terms_version.len() > 128
            || self.terms_version.chars().any(char::is_control)
            || self.enabled
                && (self.terms_version.is_empty()
                    || self.terms_text.trim().is_empty()
                    || !self.all_users && self.users.is_empty())
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    pub(super) fn permits(&self, user: Uuid) -> Result<(), Error> {
        if !self.enabled || !(self.all_users || self.users.contains(&user)) {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub revision: i64,
    pub policy: Policy,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Revision {
    pub revision: i64,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Update {
    pub expected_revision: i64,
    pub operation_id: Uuid,
    pub policy: Policy,
}
pub(super) async fn settings_in(
    c: &mut PgConnection,
    tenant: &str,
    lock: bool,
) -> Result<Settings, Error> {
    // One policy row per private deployment. Advisory locking covers the absent row too.
    if lock {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2675))")
            .bind(format!("windows-entra:{tenant}"))
            .execute(&mut *c)
            .await
            .map_err(db)?;
    }
    let row = sqlx::query(
        "SELECT revision,document FROM mdm_windows.entra_policy WHERE tenant_id=$1::uuid",
    )
    .bind(tenant)
    .fetch_optional(c)
    .await
    .map_err(db)?;
    row.map(|r| {
        Ok(Settings {
            revision: r.try_get("revision").map_err(db)?,
            policy: serde_json::from_value(r.try_get("document").map_err(db)?)
                .map_err(|_| Error::Conflict)?,
        })
    })
    .unwrap_or_else(|| {
        Ok(Settings {
            revision: 0,
            policy: Policy::default(),
        })
    })
}
pub struct Management {
    store: Arc<crate::Store>,
    audit: Arc<AuditStore>,
    pub entra: Arc<Entra>,
}
impl Management {
    pub fn new(store: Arc<crate::Store>, audit: Arc<AuditStore>, entra: Arc<Entra>) -> Self {
        Self {
            store,
            audit,
            entra,
        }
    }
    pub async fn settings(&self, p: &AuthorizedPrincipal) -> Result<Settings, Error> {
        p.manage(Permission::AuthorizationRead)?;
        if p.tenant_id() != self.entra.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let mut tx = self.store.begin_read(p.tenant_id()).await?;
        let value = settings_in(&mut tx, p.tenant_id(), false).await?;
        p.check_live()?;
        Ok(value)
    }
    pub async fn update(
        &self,
        p: &AuthorizedPrincipal,
        input: &Update,
        a: &RequestAudit,
    ) -> Result<Revision, Error> {
        p.manage(Permission::AuthorizationWrite)?;
        if p.tenant_id() != self.entra.tenant.to_string()
            || input.operation_id.is_nil()
            || input.expected_revision < 0
            || input.expected_revision == i64::MAX
        {
            return Err(Error::Malformed);
        }
        input.policy.validate()?;
        p.bind_audit(a)?;
        a.operation(input.operation_id, "windows_entra_policy");
        let digest = crate::enrollment::digest(input);
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(2));
        let control = budget.control();
        let result=self.audit.write(self.entra.tenant,&control,(self,p,input,a,&digest),|(this,p,input,a,digest),tx|Box::pin(async move {
            let (this,p,input,a,digest)=(*this,*p,*input,*a,*digest);
            let (value,replayed)=tx.with_connection_context(&mut (p,input,digest),|(p,input,digest),c|Box::pin(async move {
                let (p,input,digest)=(*p,*input,*digest);
                p.manage(Permission::AuthorizationWrite)?;
                let old=settings_in(c,p.tenant_id(),true).await?;
                let op=crate::operations::Operation {actor:crate::operations::Actor::from_authorized(p),key:input.operation_id,digest};
                if let Some(value)=crate::operations::replay(c,&op).await? {return Ok((serde_json::from_str(&value).map_err(|_|Error::Conflict)?,true));}
                if old.revision!=input.expected_revision || old.policy.terms_text != input.policy.terms_text && old.policy.terms_version == input.policy.terms_version {return Err(Error::Conflict);}
                let value=Revision {revision:old.revision+1};
                sqlx::query("INSERT INTO mdm_windows.entra_policy(tenant_id,revision,document) VALUES($1::uuid,$2,$3) ON CONFLICT(tenant_id) DO UPDATE SET revision=excluded.revision,document=excluded.document")
                    .bind(p.tenant_id()).bind(value.revision).bind(serde_json::to_value(&input.policy).map_err(|_|Error::Malformed)?).execute(&mut *c).await.map_err(db)?;
                p.check_live()?;
                crate::operations::save(c,&op,&serde_json::to_string(&value).map_err(|_|Error::Malformed)?,a).await?;
                Ok::<_,Error>((value,false))
            })).await?;
            let fact=Fact::business(a,&format!("windows-entra-policy:{}",input.operation_id),digest.as_bytes(),200,"success",None).map_err(Error::from)?;
            this.audit.append(tx,&fact,replayed).await.map_err(Error::from)?;
            a.mark_commit_started();
            Ok(value)
        })).await;
        crate::operations::settle(result, a)
    }
}
