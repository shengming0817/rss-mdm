use crate::Error;
pub(crate) fn range(header: Option<&str>, length: u64) -> Result<(u64, u64), Error> {
    let Some(header) = header else {
        return Ok((0, length));
    };
    let (start, end) = header
        .strip_prefix("bytes=")
        .and_then(|s| s.split_once('-'))
        .ok_or(Error::Malformed)?;
    if length == 0 || start.contains(',') || end.contains(',') {
        return Err(Error::Malformed);
    }
    if start.is_empty() {
        let suffix = end.parse::<u64>().map_err(|_| Error::Malformed)?;
        if suffix == 0 {
            return Err(Error::Malformed);
        }
        return Ok((length.saturating_sub(suffix), length));
    }
    let start = start.parse::<u64>().map_err(|_| Error::Malformed)?;
    let end = if end.is_empty() {
        length
    } else {
        end.parse::<u64>()
            .map_err(|_| Error::Malformed)?
            .checked_add(1)
            .ok_or(Error::Malformed)?
            .min(length)
    };
    if start >= end || start >= length {
        return Err(Error::Malformed);
    }
    Ok((start, end))
}
