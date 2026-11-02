pub(crate) fn open(
    config: &rss_mdm_recovery_credentials::configuration::Config,
) -> Result<std::sync::Arc<rss_mdm_recovery_credentials::Protection>, crate::Error> {
    config
        .open()
        .map_err(|_| crate::Error::Configuration(crate::ConfigIssue::RecoveryCredentials))
}
