pub(crate) use rss_mdm_work_page::relay::lanes::*;

/// The installer, admission budget and host all use this exact physical-pool inventory.
pub(crate) fn enabled(device_access: bool, recovery: bool) -> impl Iterator<Item = Lane> {
    LANES.iter().copied().filter(move |lane| match *lane {
        ACCESS => device_access,
        DA_CREDENTIALS => device_access && recovery,
        CREDENTIALS | NATIVE_CREDENTIALS => recovery,
        _ => true,
    })
}

pub(crate) fn render_sql(template: &str) -> String {
    let roles: Vec<_> = LANES.iter().map(|lane| lane.role).collect();
    let bindings: Vec<_> = LANES
        .iter()
        .map(|lane| format!("{}={}", lane.role, lane.domain))
        .collect();
    template
        .replace("{command_roles}", &roles.join(","))
        .replace("{command_bindings}", &bindings.join(","))
}
