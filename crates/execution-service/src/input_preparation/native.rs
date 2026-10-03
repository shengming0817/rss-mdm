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
    Vec<rss_mdm_windows_mdm::native::Request>,
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
    let queries = if definition.spec().adapter == resource::NativeAdapter::WindowsCsp {
        definition
            .spec()
            .mappings
            .values()
            .map(|mapping| {
                rss_mdm_windows_mdm::native::Request::from_uri(
                    &mapping.query,
                    rss_mdm_windows_mdm::native::Verb::Get,
                    None,
                    rss_mdm_windows_mdm::native::Scope::Device,
                )
                .map_err(|_| Error::Unsupported)
            })
            .collect::<std::result::Result<_, _>>()?
    } else {
        Vec::new()
    };
    Ok((definition, queries))
}
