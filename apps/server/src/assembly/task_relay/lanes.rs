//! Named, separately authorized command consumers. Each domain is installed for exactly one login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lane {
    pub role: &'static str,
    pub domain: &'static str,
    pub owner: &'static str,
}
include!(concat!(env!("OUT_DIR"), "/command_lanes.rs"));

/// The installer, admission budget and host all use this exact physical-pool inventory.
pub(crate) fn enabled(device_access: bool, recovery: bool) -> impl Iterator<Item = Lane> {
    LANES.iter().copied().filter(move |lane| match *lane {
        ACCESS => device_access,
        DA_CREDENTIALS => device_access && recovery,
        CREDENTIALS | NATIVE_CREDENTIALS => recovery,
        _ => true,
    })
}
