//! Allocation preflight for rust-cfb 0.14's eager open_internal (FAT, directory, MiniFAT).
//! Keep payload streams on disk. No third-party container parser runs before this boundary.
use super::*;
const FREE: u32 = 0xffff_ffff;
const END: u32 = 0xffff_fffe;
const FAT_BYTES: u64 = 16 * METADATA;
const DIRECTORY_SLOTS: u64 = 4096;
fn number(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}
fn sector(file: &mut File, id: u32, size: usize, count: u64) -> Result<Vec<u8>, Error> {
    if u64::from(id) >= count {
        return Err(invalid());
    }
    file.seek(SeekFrom::Start((u64::from(id) + 1) * size as u64))
        .map_err(|_| invalid())?;
    let mut bytes = vec![0; size];
    file.read_exact(&mut bytes).map_err(|_| invalid())?;
    Ok(bytes)
}
fn chain(
    fat: &[u32],
    mut id: u32,
    count: u64,
    max: u64,
    used: &mut BTreeSet<u32>,
) -> Result<Vec<u32>, Error> {
    let mut ids = Vec::new();
    while id != END {
        if ids.len() as u64 >= max || u64::from(id) >= count || !used.insert(id) {
            return Err(invalid());
        }
        ids.push(id);
        id = *fat.get(id as usize).ok_or_else(invalid)?;
    }
    Ok(ids)
}
pub(super) fn validate(
    file: &mut File,
    clock: &dyn Clock,
    deadline: Deadline,
) -> Result<(), Error> {
    file.rewind().map_err(|_| invalid())?;
    let mut header = [0; 512];
    file.read_exact(&mut header).map_err(|_| invalid())?;
    if header[..8] != [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] {
        return Err(invalid());
    }
    let size = match (&header[26..28], &header[30..32]) {
        ([3, 0], [9, 0]) => 512,
        ([4, 0], [12, 0]) => 4096,
        _ => return Err(invalid()),
    };
    let length = file.metadata().map_err(|_| invalid())?.len();
    let count = length
        .div_ceil(size as u64)
        .checked_sub(1)
        .ok_or_else(invalid)?;
    // rust-cfb pads FAT to the physical sector count, even with a short declared FAT.
    if count == 0 || count > FAT_BYTES / 4 {
        return Err(invalid());
    }
    let mut used = BTreeSet::new();
    let mut fat_ids = Vec::new();
    let mut entries = header[76..].to_vec();
    let mut next = number(&header, 68);
    let mut difat_bytes = 0;
    loop {
        check(clock, deadline)?;
        for bytes in entries.chunks_exact(4) {
            let id = number(bytes, 0);
            if id == FREE {
                continue;
            }
            if u64::from(id) >= count || !used.insert(id) {
                return Err(invalid());
            }
            fat_ids.push(id);
            if fat_ids.len() as u64 * size as u64 > FAT_BYTES {
                return Err(invalid());
            }
        }
        if matches!(next, END | FREE) {
            break;
        }
        difat_bytes += size as u64;
        if difat_bytes > METADATA || !used.insert(next) {
            return Err(invalid());
        }
        entries = sector(file, next, size, count)?;
        next = number(&entries, size - 4);
        entries.truncate(size - 4);
    }
    if fat_ids.len() != number(&header, 44) as usize {
        return Err(invalid());
    }
    let mut fat = Vec::new();
    for id in fat_ids {
        check(clock, deadline)?;
        fat.extend(
            sector(file, id, size, count)?
                .chunks_exact(4)
                .map(|b| number(b, 0)),
        );
    }
    if (fat.len() as u64) < count {
        return Err(invalid());
    }
    let directory = chain(
        &fat,
        number(&header, 48),
        count,
        DIRECTORY_SLOTS * 128 / size as u64,
        &mut used,
    )?;
    let first = *directory.first().ok_or_else(invalid)?;
    let root = sector(file, first, size, count)?;
    let mini_length = u64::from_le_bytes(root[120..128].try_into().map_err(|_| invalid())?);
    if mini_length > 16 * METADATA {
        return Err(invalid());
    }
    chain(
        &fat,
        number(&root, 116),
        count,
        (16 * METADATA) / size as u64,
        &mut used,
    )?;
    chain(
        &fat,
        number(&header, 60),
        count,
        METADATA / size as u64,
        &mut used,
    )?;
    check(clock, deadline)?;
    file.rewind().map_err(|_| invalid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    struct RuntimeTimer;
    impl Clock for RuntimeTimer {
        fn now(&self) -> std::time::Instant {
            std::time::Instant::now()
        }
    }
    fn validate(bytes: &[u8]) -> (Result<(), Error>, u64) {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        let deadline =
            Deadline::from_timeout(&RuntimeTimer, std::time::Duration::from_secs(60)).unwrap();
        let result = super::validate(&mut file, &RuntimeTimer, deadline);
        (result, file.stream_position().unwrap())
    }
    fn put(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn header(bytes: &mut [u8], major: u8, shift: u8) {
        bytes[..8].copy_from_slice(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
        bytes[26] = major;
        bytes[30] = shift;
        put(bytes, 68, END);
        bytes[76..512].fill(0xff);
    }
    fn layout(directories: usize, mini: usize) -> Vec<u8> {
        let mut fats = 1;
        while (fats + directories + mini).div_ceil(128) != fats {
            fats = (fats + directories + mini).div_ceil(128);
        }
        let count = fats + directories + mini;
        let mut bytes = vec![0; (count + 1) * 512];
        header(&mut bytes, 3, 9);
        put(&mut bytes, 44, fats as u32);
        put(&mut bytes, 48, fats as u32);
        put(&mut bytes, 60, (fats + directories) as u32);
        put(&mut bytes, 64, mini as u32);
        for i in 0..fats {
            put(&mut bytes, 76 + i * 4, i as u32);
        }
        bytes[512..(fats + 1) * 512].fill(0xff);
        for i in 0..fats {
            put(&mut bytes, 512 + i * 4, 0xffff_fffd);
        }
        for (start, len) in [(fats, directories), (fats + directories, mini)] {
            for i in 0..len {
                put(
                    &mut bytes,
                    512 + (start + i) * 4,
                    if i + 1 == len {
                        END
                    } else {
                        (start + i + 1) as u32
                    },
                );
            }
        }
        put(&mut bytes, (fats + 1) * 512 + 116, END);
        bytes
    }
    #[test]
    fn duplicate_fat_references_stop_before_reading_fat() {
        let mut bytes = vec![0; 3 * 4096];
        header(&mut bytes, 4, 12);
        put(&mut bytes, 44, 1024);
        put(&mut bytes, 68, 0);
        put(&mut bytes, 72, 1);
        put(&mut bytes, 76, 1);
        for i in 0..1023 {
            put(&mut bytes, 4096 + i * 4, 1);
        }
        put(&mut bytes, 8192 - 4, END);
        let (result, position) = validate(&bytes);
        assert!(result.is_err());
        assert_eq!(position, 8192, "no attacker-selected FAT sector read");
    }
    #[test]
    fn directory_and_minifat_chains_are_bounded_before_container_open() {
        assert!(validate(&layout(1, 1)).0.is_ok());
        assert!(validate(&layout(1025, 1)).0.is_err());
        assert!(validate(&layout(1, 2049)).0.is_err());
        let mut cyclic = layout(2, 1);
        put(&mut cyclic, 512 + 2 * 4, 2);
        assert!(validate(&cyclic).0.is_err());
    }
    #[test]
    fn sparse_extent_cannot_force_implicit_fat_padding() {
        let mut file = tempfile::tempfile().unwrap();
        let mut bytes = vec![0; 512];
        header(&mut bytes, 3, 9);
        file.write_all(&bytes).unwrap();
        file.set_len((FAT_BYTES / 4 + 2) * 512).unwrap();
        let deadline =
            Deadline::from_timeout(&RuntimeTimer, std::time::Duration::from_secs(60)).unwrap();
        assert!(super::validate(&mut file, &RuntimeTimer, deadline).is_err());
        assert_eq!(file.stream_position().unwrap(), 512);
    }
}
