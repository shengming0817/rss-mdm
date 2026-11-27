//! Named, separately authorized command consumers. Each domain is installed for exactly one login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lane {
    pub role: &'static str,
    pub domain: &'static str,
    pub owner: &'static str,
}
pub(crate) const DEVICE: Lane = Lane {
    role: "mdm_dispatch_device",
    domain: "mdm.commands.v1",
    owner: "device",
};
pub(crate) const POLICY: Lane = Lane {
    role: "mdm_dispatch_policy",
    domain: "mdm.policy.configuration.v1",
    owner: "policy",
};
pub(crate) const SCRIPT: Lane = Lane {
    role: "mdm_dispatch_script",
    domain: "mdm.script.v1",
    owner: "script",
};
pub(crate) const INVENTORY: Lane = Lane {
    role: "mdm_dispatch_inventory",
    domain: "mdm.collection.v1",
    owner: "inventory",
};
pub(crate) const SOFTWARE: Lane = Lane {
    role: "mdm_dispatch_software",
    domain: "mdm.software.deployment.v1",
    owner: "software",
};
pub(crate) const INSTALLATION: Lane = Lane {
    role: "mdm_dispatch_installation",
    domain: "mdm.registration.installation.v1",
    owner: "installation",
};
pub(crate) const ENROLLMENT: Lane = Lane {
    role: "mdm_dispatch_enrollment",
    domain: "mdm.registration.enrollment.v1",
    owner: "enrollment",
};
pub(crate) const ACCESS: Lane = Lane {
    role: "mdm_dispatch_device_access",
    domain: "mdm.registration.access.v1",
    owner: "device_access",
};
pub(crate) const CREDENTIALS: Lane = Lane {
    role: "mdm_dispatch_mdm_credentials",
    domain: "mdm.recovery.credentials.v1",
    owner: "mdm_credentials",
};
pub(crate) const DA_CREDENTIALS: Lane = Lane {
    role: "mdm_dispatch_da_credentials",
    domain: "da.recovery.credentials.v1",
    owner: "da_credentials",
};
pub(crate) const NATIVE_CREDENTIALS: Lane = Lane {
    role: "mdm_dispatch_native_credentials",
    domain: "mdm.recovery.native.v1",
    owner: "native_credentials",
};
pub(crate) const LANES: &[Lane] = &[
    DEVICE,
    POLICY,
    SCRIPT,
    INVENTORY,
    SOFTWARE,
    INSTALLATION,
    ENROLLMENT,
    ACCESS,
    CREDENTIALS,
    DA_CREDENTIALS,
    NATIVE_CREDENTIALS,
];

/// The installer, admission budget and host all use this exact physical-pool inventory.
pub(crate) fn enabled(device_access: bool, recovery: bool) -> impl Iterator<Item = Lane> {
    LANES.iter().copied().filter(move |lane| match *lane {
        ACCESS => device_access,
        DA_CREDENTIALS => device_access && recovery,
        CREDENTIALS | NATIVE_CREDENTIALS => recovery,
        _ => true,
    })
}
