//! One invocation's captured journal horizon; persistent projection generation stays live.
use crate::storage::Clock;
use rss_observation_postgres::PgSource;
use rss_projection::{BatchLimit, Error, ErrorKind, Event, Position, Source, SourceScope};
use std::sync::Arc;
pub struct Window {
    pub source: Arc<PgSource<Clock>>,
    pub through: Option<Position>,
}
impl Source for Window {
    async fn high_water<T: rss_projection::Timer>(
        &self,
        scope: &SourceScope,
        control: &rss_projection::Control<'_, T>,
    ) -> Result<Option<Position>, Error> {
        control.check()?;
        if scope != self.source.scope() {
            return Err(Error::new(ErrorKind::ScopeMismatch));
        }
        Ok(self.through)
    }
    async fn read<T: rss_projection::Timer>(
        &self,
        scope: &SourceScope,
        after: Option<Position>,
        limit: BatchLimit,
        control: &rss_projection::Control<'_, T>,
    ) -> Result<Vec<Event>, Error> {
        self.high_water(scope, control).await?;
        if self.through.is_none() || after >= self.through {
            return Ok(vec![]);
        }
        let mut events = self.source.read(scope, after, limit, control).await?;
        events.retain(|event| Some(event.position()) <= self.through);
        control.check()?;
        Ok(events)
    }
}
