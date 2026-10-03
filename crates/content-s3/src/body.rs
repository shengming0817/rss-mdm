use crate::{Budget, Content, Error, Result};
use aws_sdk_s3::primitives::ByteStream;
use bytes::Bytes;
use futures::{StreamExt, stream::BoxStream};
use http_body::{Body, Frame, SizeHint};
use sha2::{Digest, Sha256};
use std::{
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
};
use tokio::sync::OwnedSemaphorePermit;

/// Input streams carry safe errors and owned bytes. An entire object is never collected.
pub type ByteStreamInput = BoxStream<'static, Result<Bytes>>;
/// Read failures are stream errors; early EOF is never successful completion.
pub type ByteStreamOutput = BoxStream<'static, Result<Bytes>>;

async fn cutoff(budget: &Budget) -> Result<tokio::time::Instant> {
    // Cooperate even with streams that always return Ready (including empty frames).
    tokio::task::yield_now().await;
    let now = budget.clock.now();
    if now >= budget.deadline.instant() {
        return Err(Error::Budget);
    }
    Ok(budget
        .deadline
        .instant()
        .min(
            now.checked_add(budget.idle)
                .unwrap_or(budget.deadline.instant()),
        )
        .into())
}

pub(crate) async fn next(stream: &mut ByteStreamInput, budget: &Budget) -> Result<Option<Bytes>> {
    let cutoff = cutoff(budget).await?;
    tokio::time::timeout_at(cutoff, stream.next())
        .await
        .map_err(|_| Error::Budget)?
        .transpose()
}

/// Delay the final frame until EOF, exact length and SHA256 are confirmed locally.
/// This prevents an HTTP content-length boundary from silently hiding trailing input.
struct InputBody {
    stream: Mutex<ByteStreamInput>,
    length: u64,
}
impl Body for InputBody {
    type Data = Bytes;
    type Error = Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>>>> {
        match self.stream.get_mut() {
            Ok(stream) => {
                let result = stream.as_mut().poll_next(cx);
                if let Poll::Ready(Some(Ok(bytes))) = &result {
                    self.length = self.length.saturating_sub(bytes.len() as u64);
                }
                result.map(|item| item.map(|result| result.map(Frame::data)))
            }
            Err(_) => Poll::Ready(Some(Err(Error::Integrity))),
        }
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.length)
    }
}
pub(crate) fn upload(source: ByteStreamInput, content: Content, budget: Budget) -> ByteStream {
    let state = (source, Sha256::new(), 0u64, false, budget);
    let checked = futures::stream::unfold(
        state,
        move |(mut source, mut hash, mut count, done, budget)| async move {
            if done {
                return None;
            }
            let result = async {
                let Some(bytes) = next(&mut source, &budget).await? else {
                    if count != content.length
                        || <[u8; 32]>::from(hash.clone().finalize()) != content.sha256
                    {
                        return Err(Error::Integrity);
                    }
                    return Ok(None);
                };
                count = count
                    .checked_add(bytes.len() as u64)
                    .ok_or(Error::Integrity)?;
                if count > content.length {
                    return Err(Error::Integrity);
                }
                hash.update(&bytes);
                if count == content.length {
                    // Consume zero-size frames too; the absolute budget prevents empty-frame spinning.
                    loop {
                        match next(&mut source, &budget).await? {
                            Some(extra) if extra.is_empty() => continue,
                            Some(_) => return Err(Error::Integrity),
                            None => break,
                        }
                    }
                    if <[u8; 32]>::from(hash.clone().finalize()) != content.sha256 {
                        return Err(Error::Integrity);
                    }
                }
                Ok(Some(bytes))
            }
            .await;
            match result {
                Ok(None) => None,
                Ok(Some(bytes)) => Some((
                    Ok(bytes),
                    (source, hash, count, count == content.length, budget),
                )),
                Err(error) => Some((Err(error), (source, hash, count, true, budget))),
            }
        },
    );
    ByteStream::from_body_1_x(InputBody {
        stream: Mutex::new(Box::pin(checked.fuse())),
        length: content.length,
    })
}
pub(crate) fn download(
    body: ByteStream,
    length: u64,
    digest: Option<[u8; 32]>,
    budget: Budget,
    permit: Option<OwnedSemaphorePermit>,
) -> ByteStreamOutput {
    let state = (body, Sha256::new(), 0u64, false, permit, budget);
    Box::pin(futures::stream::unfold(
        state,
        move |(mut body, mut hash, mut count, done, permit, budget)| async move {
            if done {
                return None;
            }
            let result = match async {
                let cutoff = cutoff(&budget).await?;
                tokio::time::timeout_at(cutoff, body.next())
                    .await
                    .map_err(|_| Error::Budget)
            }
            .await
            {
                Err(error) => Err(error),
                Ok(Some(Err(_))) => Err(Error::Transient),
                Ok(Some(Ok(bytes))) => {
                    count = count.saturating_add(bytes.len() as u64);
                    if count > length {
                        Err(Error::Integrity)
                    } else {
                        hash.update(&bytes);
                        Ok(Some(bytes))
                    }
                }
                Ok(None) => {
                    if count != length
                        || digest.is_some_and(|expected| {
                            <[u8; 32]>::from(hash.clone().finalize()) != expected
                        })
                    {
                        Err(Error::Integrity)
                    } else {
                        Ok(None)
                    }
                }
            };
            match result {
                Ok(None) => None,
                Ok(Some(bytes)) => Some((Ok(bytes), (body, hash, count, false, permit, budget))),
                Err(error) => Some((Err(error), (body, hash, count, true, permit, budget))),
            }
        },
    ))
}

pub(crate) async fn empty_input(
    source: &mut ByteStreamInput,
    content: Content,
    budget: &Budget,
) -> Result<()> {
    if content.length != 0 {
        return Ok(());
    }
    if content.sha256 != <[u8; 32]>::from(Sha256::digest([])) {
        return Err(Error::Integrity);
    }
    while let Some(bytes) = next(source, budget).await? {
        if !bytes.is_empty() {
            return Err(Error::Integrity);
        }
    }
    Ok(())
}
