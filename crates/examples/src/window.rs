//! One invocation's captured journal horizon; persistent projection generation stays live.
use crate::storage::Clock;
use rss_observation_postgres::PgSource;
use rss_projection::{Error, ErrorKind, PageBudget, Position, ReadPage, Source, SourceScope};
use std::sync::Arc;
pub struct Window {
    pub source: Arc<PgSource<Clock, rss_observation_postgres::LocalPages>>,
    pub through: Option<Position>,
}
impl Source for Window {
    type Item = <PgSource<Clock, rss_observation_postgres::LocalPages> as Source>::Item;
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
        limit: PageBudget,
        control: &rss_projection::Control<'_, T>,
    ) -> Result<ReadPage<Self::Item>, Error> {
        self.high_water(scope, control).await?;
        if self.through.is_none() || after >= self.through {
            return Ok(ReadPage::Events(vec![]));
        }
        let mut events = self.source.read(scope, after, limit, control).await?;
        match &mut events {
            ReadPage::Events(items) => {
                items.retain(|item| Some(item.as_ref().position()) <= self.through)
            }
            ReadPage::Blocked { position, .. } if Some(*position) > self.through => {
                return Ok(ReadPage::Events(vec![]));
            }
            _ => {}
        }
        control.check()?;
        Ok(events)
    }
}
