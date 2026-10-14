use super::*;

pub(super) fn configuration(
    version: &resource::Version,
    binding: &ExactResourceBinding,
    exit: Exit,
    verified: Option<&Verified>,
) -> Result<crate::configuration::Configuration> {
    let resource::Declaration::Configuration { artifact } =
        variant(version, binding)?.declaration()
    else {
        return Err(Error::Malformed.into());
    };
    let verified = verified
        .filter(|v| v.matches(artifact))
        .ok_or(Error::Conflict)?;
    let native = crate::configuration::Configuration::read(verified)?;
    if matches!(exit, Exit::Remove) && native.remove.is_none() {
        return Err(Error::Unsupported.into());
    }
    let expected = match binding.platform {
        Platform::Windows => rss_mdm_inventory::ReportSource::MdmWindows,
        Platform::Macos => rss_mdm_inventory::ReportSource::MdmApple,
    };
    if native.apply.source() != expected {
        return Err(Error::Malformed.into());
    }
    Ok(native)
}

pub(super) fn native_collection<'a>(
    version: &'a resource::Version,
    binding: &ExactResourceBinding,
    verified: Option<&Verified>,
) -> Result<(
    &'a resource::NativeCollectionDefinition,
    Option<rss_mdm_windows_mdm::native::collection::Plan>,
)> {
    let resource::Declaration::NativeCollection {
        artifact,
        definition,
    } = variant(version, binding)?.declaration()
    else {
        return Err(Error::Malformed.into());
    };
    if !verified.is_some_and(|v| v.matches(artifact)) {
        return Err(Error::Conflict.into());
    }
    let plan = if definition.spec().adapter == resource::NativeAdapter::WindowsRead {
        Some(windows_collection_plan(definition)?)
    } else {
        None
    };
    Ok((definition, plan))
}

/// Compile the only executable Windows collection representation.
pub(crate) fn windows_collection_plan(
    definition: &resource::NativeCollectionDefinition,
) -> Result<rss_mdm_windows_mdm::native::collection::Plan> {
    use resource::{NativeQuery, WindowsInventory as W, WindowsRead};
    use rss_mdm_windows_mdm::native::collection::{Inventory, Read};
    let reads: std::collections::BTreeMap<String, Read> = definition
        .spec()
        .mappings
        .iter()
        .map(|(field, mapping)| {
            let NativeQuery::Windows(read) = &mapping.query else {
                return Err(Error::Malformed);
            };
            let read = match read {
                WindowsRead::EnrollmentId => Read::EnrollmentId,
                WindowsRead::EnrollmentType => Read::EnrollmentType,
                WindowsRead::Scalar { uri } => Read::Scalar { uri: uri.clone() },
                WindowsRead::Inventory { inventory } => Read::Inventory {
                    inventory: match inventory {
                        W::Win32 => Inventory::Win32,
                        W::Store => Inventory::Store,
                        W::NonStore => Inventory::NonStore,
                        W::System => Inventory::System,
                        W::Network => Inventory::Network,
                        W::InstalledUpdates => Inventory::InstalledUpdates,
                        W::InstallableUpdates => Inventory::InstallableUpdates,
                        W::FailedUpdates => Inventory::FailedUpdates,
                        W::PendingRebootUpdates => Inventory::PendingRebootUpdates,
                    },
                },
            };
            Ok((field.clone(), read))
        })
        .collect::<std::result::Result<_, Error>>()?;
    rss_mdm_windows_mdm::native::collection::Plan::try_from(reads)
        .map_err(|_| Error::Unsupported.into())
}
