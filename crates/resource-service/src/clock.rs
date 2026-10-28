//! Host-provided wall clock; authentication continues to use database time.
pub trait Clock: Send + Sync {
    fn unix_seconds(&self) -> Option<i64>;
}
