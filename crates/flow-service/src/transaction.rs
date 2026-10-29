//! Remaining publication/host construction budget.
pub fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
        std::time::Duration::from_secs(6),
    )
}
