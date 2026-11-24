//! Refresh server-owned catalog fields and publish changes through the asset outbox.
use super::model;
use rss_identity_core::{PrincipalId, federation::ProviderId};
use rss_identity_postgres::{
    Authority, Federation, ProfileStatus,
    personnel_facts::{PersonnelFact, PersonnelField, read_personnel_facts_on},
};
use rss_mdm_inventory::{
    FieldDefinition, Scalar, ValueType,
    personnel::{self, Attribute, DeviceUser, ProviderAttribute},
};
use rss_reconcile::{Error as ReconcileError, ErrorKind};
use rss_transactional_messaging::fence::ExecutionBinding;
use rss_transactional_messaging_postgres::PgRuntime;
use serde_json::{Value, json};
use sqlx::{PgConnection, Row};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU32,
    sync::Arc,
};
use uuid::Uuid;

mod catalog;
const PAGE: i64 = 32;
type Result<T> = std::result::Result<T, sqlx::Error>;
fn invalid(_: impl std::fmt::Debug) -> sqlx::Error {
    sqlx::Error::Protocol("invalid device personnel projection".into())
}

#[derive(Clone)]
pub(crate) struct Refresh {
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) identity: Authority,
    pub(crate) federation: Option<Federation>,
    pub(crate) platform: Value,
    pub(crate) max_age: NonZeroU32,
}

impl rss_mdm_group_service::runtime::DeviceFieldRefresh for Refresh {
    fn advance(
        &self,
        binding: ExecutionBinding,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::result::Result<(), ReconcileError>> + Send + '_>,
    > {
        Box::pin(async move {
            let owner = self.clone();
            self.runtime
                .local_tx(binding, crate::identity::deadline(), move |tx| {
                    Box::pin(async move {
                        tx.with_connection(move |c| {
                            Box::pin(async move { owner.page(c, binding).await })
                        })
                        .await
                    })
                })
                .await
                .fold(
                    Ok,
                    |_| Err(ReconcileError::new(ErrorKind::Transient)),
                    |_| Err(ReconcileError::new(ErrorKind::Transient)),
                    |_| Err(ReconcileError::new(ErrorKind::RollbackFailed)),
                    |_| Err(ReconcileError::new(ErrorKind::CommitUnknown)),
                    |_| Err(ReconcileError::new(ErrorKind::Fenced)),
                )
        })
    }
}

impl Refresh {
    async fn page(&self, c: &mut PgConnection, binding: ExecutionBinding) -> Result<()> {
        let tenant = binding.tenant().to_string();
        sqlx::query("INSERT INTO mdm_assets.personnel_cursor(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING")
            .bind(&tenant).execute(&mut *c).await?;
        let cursor = sqlx::query_scalar::<_, Option<Uuid>>("SELECT after_device FROM mdm_assets.personnel_cursor WHERE tenant_id=$1::uuid AND next_scan<=clock_timestamp() FOR UPDATE SKIP LOCKED")
            .bind(&tenant).fetch_optional(&mut *c).await?;
        let Some(after) = cursor else { return Ok(()) };
        let providers = match &self.federation {
            Some(f) => f
                .login_options(binding, crate::identity::deadline())
                .await
                .map_err(invalid)?
                .into_iter()
                .map(|opt| opt.provider_id)
                .collect(),
            None => Vec::new(),
        };
        let fields = catalog::fields(c, binding, &providers).await?;
        let devices:Vec<Uuid>=sqlx::query_scalar("SELECT device FROM (SELECT device FROM mdm_user_profiles.attributed_devices WHERE tenant_id=$1::uuid AND ($2::uuid IS NULL OR device>$2) UNION SELECT device FROM mdm_assets.personnel_history WHERE tenant_id=$1::uuid AND ($2::uuid IS NULL OR device>$2)) d ORDER BY device LIMIT $3")
            .bind(&tenant).bind(after).bind(PAGE).fetch_all(&mut *c).await?;
        let subjects = rss_mdm_device_service::personnel::device_subjects(
            &self.identity,
            binding,
            self.platform.clone(),
            &devices,
            crate::identity::deadline(),
        )
        .await
        .map_err(invalid)?;
        let ids: Vec<_> = subjects
            .iter()
            .flat_map(|row| [row.registration, row.current])
            .flatten()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let principals = ids
            .iter()
            .map(|id| PrincipalId::parse(&id.to_string()).map_err(invalid))
            .collect::<Result<Vec<_>>>()?;
        let local:Vec<(Uuid,Uuid)>=sqlx::query_as("SELECT principal,id FROM mdm_user_profiles.device_group_members WHERE instance=$1 AND principal=ANY($2) ORDER BY principal,id")
            .bind(self.identity.instance().as_uuid()).bind(&ids).fetch_all(&mut *c).await?;
        let mut groups = BTreeMap::<_, Vec<_>>::new();
        for (principal, group) in local {
            groups
                .entry(principal)
                .or_default()
                .push(Scalar::String(group.to_string()));
        }
        let mut writes = Vec::new();
        for field in fields {
            let facts = self.facts(c, binding, &field, &principals).await?;
            for row in &subjects {
                for (role, def) in &field.fields {
                    writes.push(field.observation(row, *role, def, &facts, &groups));
                }
            }
        }
        sqlx::query(include_str!("device_fields/write.sql"))
            .bind(&tenant)
            .bind(Value::Array(writes))
            .execute(&mut *c)
            .await?;
        let after = devices
            .last()
            .copied()
            .filter(|_| devices.len() == PAGE as usize);
        sqlx::query("UPDATE mdm_assets.personnel_cursor SET after_device=$2,next_scan=CASE WHEN $2::uuid IS NULL THEN clock_timestamp()+interval '30 seconds' ELSE clock_timestamp() END WHERE tenant_id=$1::uuid")
            .bind(tenant).bind(after).execute(c).await?;
        Ok(())
    }
    async fn facts(
        &self,
        c: &mut PgConnection,
        binding: ExecutionBinding,
        field: &Field,
        principals: &[PrincipalId],
    ) -> Result<BTreeMap<Uuid, PersonnelFact>> {
        let path = field
            .profile
            .as_ref()
            .and_then(|d| model::device_path(&d.pointer))
            .unwrap_or_default();
        let account_path = [String::from("emailVerified")];
        let request = match field.attribute {
            Attribute::Provider(id, which) => {
                let provider = ProviderId::parse(&id.to_string()).map_err(invalid)?;
                match which {
                    ProviderAttribute::Groups => PersonnelField::Groups(provider),
                    _ => PersonnelField::Departments(provider),
                }
            }
            Attribute::Profile(_) => PersonnelField::Profile {
                source: model::source(
                    &field
                        .profile
                        .as_ref()
                        .ok_or_else(|| invalid("definition"))?
                        .source,
                )
                .map_err(invalid)?,
                path: &path,
                max_age_seconds: self.max_age,
            },
            // Identity local profiles define emailVerified as Missing for active accounts.
            // The owner reports Unavailable for a disabled account or inactive membership.
            _ => PersonnelField::Profile {
                source: rss_identity_postgres::ProfileSource::IdentityLocal,
                path: &account_path,
                max_age_seconds: self.max_age,
            },
        };
        let page = read_personnel_facts_on(
            c,
            self.identity.instance(),
            binding.tenant(),
            principals,
            request,
        )
        .await
        .map_err(invalid)?;
        Ok(page
            .items
            .into_iter()
            .map(|fact| (fact.principal.as_uuid(), fact))
            .collect())
    }
}

struct Field {
    attribute: Attribute,
    fields: Vec<(DeviceUser, FieldDefinition)>,
    profile: Option<model::DefinitionValue>,
    after: i64,
}
impl Field {
    fn observation(
        &self,
        row: &rss_mdm_device_service::personnel::DeviceSubjects,
        role: DeviceUser,
        def: &FieldDefinition,
        facts: &BTreeMap<Uuid, PersonnelFact>,
        groups: &BTreeMap<Uuid, Vec<Scalar>>,
    ) -> Value {
        let (id, binding_revision, bound) = match role {
            DeviceUser::Registration => (row.registration, row.registration_revision, None),
            DeviceUser::Current => (row.current, row.current_revision, row.current_until),
        };
        let fact = id.and_then(|id| facts.get(&id));
        let scalar = fact
            .and_then(|fact| self.value(fact, groups))
            .filter(|v| def.value_type.validate_value(v).is_ok());
        let sourced = matches!(
            self.attribute,
            Attribute::Profile(_) | Attribute::Provider(..)
        );
        let end = if sourced {
            [bound, fact.and_then(|f| f.expires_at)]
                .into_iter()
                .flatten()
                .min()
        } else {
            bound
        };
        let source = if sourced {
            fact.map(|f| {
                json!([
                    f.snapshot_id,
                    f.observation_sequence,
                    f.source_revision,
                    f.provider_version,
                    f.collected_at_micros
                ])
            })
        } else {
            None
        };
        // No qualification window is needed for an unknown value.
        json!({"device":row.device,"field":def.key,"field_version":def.version,"subject":id,"value":scalar,
                        "valid_until":scalar.as_ref().and(end),"fingerprint":[binding_revision,source]})
    }
    fn value(&self, f: &PersonnelFact, groups: &BTreeMap<Uuid, Vec<Scalar>>) -> Option<Scalar> {
        if matches!(f.status, ProfileStatus::Unavailable) {
            return None;
        }
        let id = f.principal.as_uuid();
        Some(match self.attribute {
            Attribute::Principal => Scalar::String(id.to_string()),
            Attribute::LocalGroups => Scalar::Array(groups.get(&id).cloned().unwrap_or_default()),
            Attribute::Provider(_, which) => {
                let v = f.value.as_ref()?;
                if which == ProviderAttribute::Groups {
                    let ids = serde_json::from_value::<Vec<String>>(v.clone()).ok()?;
                    Scalar::Array(ids.into_iter().map(Scalar::String).collect())
                } else {
                    let snapshot = serde_json::from_value::<
                        rss_identity_core::department::DepartmentSnapshot,
                    >(v.clone())
                    .ok()?;
                    let nodes = snapshot
                        .nodes()
                        .iter()
                        .map(|n| (n.id().as_str(), n.parent_id()))
                        .collect::<BTreeMap<_, _>>();
                    let mut paths = BTreeSet::new();
                    for member in snapshot.memberships() {
                        let mut node = Some(member);
                        while let Some(id) = node {
                            if !paths.insert(id.as_str()) || which == ProviderAttribute::Departments
                            {
                                break;
                            }
                            node = nodes.get(id.as_str()).copied().flatten();
                        }
                    }
                    Scalar::Array(
                        paths
                            .into_iter()
                            .map(|id| Scalar::String(id.to_owned()))
                            .collect(),
                    )
                }
            }
            Attribute::Profile(_) => {
                let d = self.profile.as_ref()?;
                let v = f.value.as_ref()?;
                if f.collected_at_micros? <= self.after || !model::conforms(v, d) {
                    return None;
                }
                match d.value_type {
                    model::ValueType::String => Scalar::String(v.as_str()?.to_owned()),
                    model::ValueType::Boolean => Scalar::Boolean(v.as_bool()?),
                    model::ValueType::Integer => Scalar::Integer(v.as_f64()? as i64),
                    model::ValueType::Number => {
                        serde_json::from_value(json!({"kind":"number","value":v})).ok()?
                    }
                    _ => return None,
                }
            }
        })
    }
}
