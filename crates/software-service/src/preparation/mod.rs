//! Software rules over the caller's transaction; no Run, device admission or scheduling owner.
mod exports;
mod wire;
pub use crate::catalog::{Error, Result};
use crate::{
    catalog::{FrozenSoftware, Reader},
    publication::ExportReader,
};
use rss_mdm_agent_wire as w;
use rss_mdm_resource as r;
use rss_transactional_messaging_postgres::PgTransaction;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use uuid::Uuid;

#[derive(Clone, Copy)]
pub struct Target {
    pub platform: r::Platform,
    pub architecture: r::Architecture,
}
pub enum Delivery<'a> {
    Direct,
    Native {
        source: &'a str,
        ring: rss_mdm_software_release::Ring,
    },
}
/// Transient view of the existing immutable binding, never a second persisted model.
pub struct Selection<'a> {
    pub resource: &'a str,
    pub version: &'a str,
    pub digest: [u8; 32],
    pub admission: Uuid,
    pub variant: &'a str,
    pub uninstall: bool,
}
pub struct FreezeRequest<'a> {
    pub resource: &'a str,
    pub version: &'a str,
    pub digest: [u8; 32],
    pub admission: Uuid,
    pub uninstall: bool,
    pub targets: &'a [(Target, String)],
}
pub struct Preparation {
    catalog: Reader,
    exports: BTreeMap<String, Arc<ExportReader>>,
}
impl Preparation {
    pub fn new(catalog: Reader, exports: BTreeMap<String, Arc<ExportReader>>) -> Self {
        Self { catalog, exports }
    }
    /// Validate every explicitly selected variant against one original approval and budget.
    pub async fn freeze_in(
        &self,
        tx: &mut PgTransaction<'_>,
        request: FreezeRequest<'_>,
    ) -> Result<()> {
        let FreezeRequest {
            resource,
            version,
            digest,
            admission,
            uninstall,
            targets,
        } = request;
        if targets.is_empty() {
            return Err(Error::Conflict);
        }
        for (target, variant) in targets {
            let binding = Selection {
                resource,
                version,
                digest,
                admission,
                variant,
                uninstall,
            };
            let selected = self.resolve_in(tx, &binding, *target).await?;
            if uninstall && !definition(&selected)?.behavior.supports_removal() {
                return Err(Error::Unsupported);
            }
            let steps = self
                .closure_in(tx, &binding, *target)
                .await?
                .ok_or(Error::NotAdmitted)?;
            check_definition_budget(&steps)?;
        }
        Ok(())
    }
    /// Resolve an authored binding strictly, preserving rejection and identity mismatch errors.
    pub async fn resolve_in(
        &self,
        tx: &mut PgTransaction<'_>,
        binding: &Selection<'_>,
        target: Target,
    ) -> Result<FrozenSoftware> {
        let selected = self
            .catalog
            .resolve_admitted_in(
                tx,
                binding.resource,
                binding.version,
                target.platform,
                target.architecture,
                &r::Id::new(binding.variant).map_err(|_| Error::Input)?,
            )
            .await?;
        if selected.version().digest().bytes() != binding.digest
            || selected.admission().operation != binding.admission
        {
            return Err(Error::Conflict);
        }
        Ok(selected)
    }
    /// Missing, withdrawn or superseded approval is local execution ineligibility.
    pub async fn recheck_in(
        &self,
        tx: &mut PgTransaction<'_>,
        binding: &Selection<'_>,
        target: Target,
    ) -> Result<Option<FrozenSoftware>> {
        match self.resolve_in(tx, binding, target).await {
            Ok(selected) => Ok(Some(selected)),
            Err(Error::Missing | Error::NotAdmitted | Error::Conflict) => Ok(None),
            Err(error) => Err(error),
        }
    }
    /// All software steps are bound to the explicitly supplied execution context.
    /// The consumer must still verify live device profiles and registration authority.
    pub async fn prepare_in(
        &self,
        tx: &mut PgTransaction<'_>,
        binding: &Selection<'_>,
        target: Target,
        delivery: &Delivery<'_>,
        context: &w::SoftwareExecutionContext,
    ) -> Result<Option<Vec<w::SoftwareTaskStep>>> {
        let Some(selected) = self.closure_in(tx, binding, target).await? else {
            return Ok(None);
        };
        check_definition_budget(&selected)?;
        let platform = match target.platform {
            r::Platform::Windows => w::TaskPlatform::Windows,
            r::Platform::MacOS => w::TaskPlatform::Macos,
        };
        let tenant = Uuid::parse_str(&tx.tenant_id().to_string()).map_err(|_| Error::Input)?;
        let mut steps = Vec::new();
        for (index, selected) in selected.iter().enumerate() {
            let spec = definition(selected)?;
            let action = wire::software_action(spec);
            let export = self.export_in(tx, delivery, selected, &action).await?;
            let step = wire::software_step(spec, index, platform, context, export)
                .map_err(|_| Error::Unsupported)?;
            step.export
                .validate_for(&step, tenant, context)
                .map_err(|_| Error::Unsupported)?;
            steps.push(step);
        }
        // Wire identity measures encoded executable steps, separately from definition metadata.
        if serde_json::to_vec(&steps).map_err(|_| Error::Input)?.len() > 4_194_304 {
            return Err(Error::Unsupported);
        }
        Ok(Some(steps))
    }
    /// Exact content selection uses the same admitted target closure as task preparation.
    pub async fn artifact_in(
        &self,
        tx: &mut PgTransaction<'_>,
        binding: &Selection<'_>,
        target: Target,
        index: usize,
        key: &str,
    ) -> Result<Option<r::Artifact>> {
        let Some(steps) = self.closure_in(tx, binding, target).await? else {
            return Ok(None);
        };
        let selected = steps.get(index).ok_or(Error::Missing)?;
        let artifact = definition(selected)?
            .artifacts
            .get(key)
            .ok_or(Error::Missing)?;
        Ok(Some(artifact.artifact().map_err(|_| Error::Input)?))
    }
    async fn closure_in(
        &self,
        tx: &mut PgTransaction<'_>,
        binding: &Selection<'_>,
        target: Target,
    ) -> Result<Option<Vec<FrozenSoftware>>> {
        self.catalog.lock_in(tx).await?;
        let mut stack = vec![(
            binding.resource.to_owned(),
            binding.version.to_owned(),
            binding.digest,
            false,
            true,
            None,
        )];
        let mut active = BTreeSet::new();
        let mut done = BTreeSet::new();
        let mut ordered = Vec::new();
        while let Some((resource, version, digest, exit, root, selected)) = stack.pop() {
            let key = (resource.clone(), version.clone());
            if exit {
                active.remove(&key);
                done.insert(key);
                ordered.push(selected.ok_or(Error::Input)?);
                continue;
            }
            if done.contains(&key) {
                continue;
            }
            if !active.insert(key) || active.len() + done.len() > 256 {
                return Err(Error::Input);
            }
            let resolved = match self.catalog.version_in(tx, &resource, &version).await {
                Ok(v) => v,
                Err(Error::Missing | Error::NotAdmitted) => return Ok(None),
                Err(e) => return Err(e),
            };
            if resolved.digest().bytes() != digest {
                return Err(Error::Conflict);
            }
            let variant = if root {
                binding.variant.to_owned()
            } else {
                let mut matching = resolved.variants().iter().filter(|v| {
                    v.platform() == target.platform && v.architecture() == target.architecture
                });
                let found = matching.next().ok_or(Error::Unsupported)?;
                if matching.next().is_some() {
                    return Err(Error::Unsupported);
                }
                found.key().as_str().to_owned()
            };
            let selected = self
                .catalog
                .resolve_admitted_in(
                    tx,
                    &resource,
                    &version,
                    target.platform,
                    target.architecture,
                    &r::Id::new(&variant).map_err(|_| Error::Input)?,
                )
                .await;
            let selected = match selected {
                Ok(v) => v,
                Err(Error::Missing | Error::NotAdmitted) => return Ok(None),
                Err(e) => return Err(e),
            };
            if root && selected.admission().operation != binding.admission {
                return Ok(None);
            }
            let dependencies = if root && binding.uninstall {
                Vec::new()
            } else {
                definition(&selected)?.dependencies.clone()
            };
            stack.push((resource, version, digest, true, root, Some(selected)));
            for d in dependencies.into_iter().rev() {
                stack.push((d.resource, d.version, d.sha256, false, false, None));
            }
        }
        if ordered.is_empty() || ordered.len() > 32 {
            return Err(Error::Unsupported);
        }
        Ok(Some(ordered))
    }
}
fn definition(selected: &FrozenSoftware) -> Result<&r::SoftwareSpec> {
    let variant = selected
        .version()
        .resolve(
            selected.platform(),
            selected.architecture(),
            selected.variant(),
        )
        .map_err(|_| Error::Input)?;
    let r::Declaration::Software { definition } = variant.declaration() else {
        return Err(Error::Input);
    };
    Ok(definition.spec())
}
/// Metadata budget and checked arithmetic; executable wire bytes have a separate bound.
#[derive(Default)]
struct DefinitionBudget {
    artifacts: usize,
    bytes: usize,
}
impl DefinitionBudget {
    fn include(&mut self, artifacts: usize, bytes: usize) -> Result<()> {
        self.artifacts = self.artifacts.checked_add(artifacts).ok_or(Error::Input)?;
        self.bytes = self.bytes.checked_add(bytes).ok_or(Error::Input)?;
        if self.artifacts > 64 || self.bytes > 4_000_000 {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
}
fn check_definition_budget(steps: &[FrozenSoftware]) -> Result<()> {
    let mut budget = DefinitionBudget::default();
    for selected in steps {
        let spec = definition(selected)?;
        budget.include(
            spec.artifacts.len(),
            serde_json::to_vec(spec).map_err(|_| Error::Input)?.len(),
        )?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn definition_budget_counts_the_complete_closure_and_accepts_exact_limits() {
        let mut budget = DefinitionBudget::default();
        assert!(budget.include(32, 2_000_000).is_ok());
        assert!(budget.include(32, 2_000_000).is_ok());
        assert!(matches!(budget.include(0, 1), Err(Error::Unsupported)));
        assert!(matches!(
            DefinitionBudget::default().include(65, 0),
            Err(Error::Unsupported)
        ));
    }
    #[test]
    fn definition_budget_rejects_arithmetic_overflow() {
        let mut budget = DefinitionBudget {
            artifacts: usize::MAX,
            bytes: 0,
        };
        assert!(matches!(budget.include(1, 0), Err(Error::Input)));
        let mut budget = DefinitionBudget {
            artifacts: 0,
            bytes: usize::MAX,
        };
        assert!(matches!(budget.include(0, 1), Err(Error::Input)));
    }
}
