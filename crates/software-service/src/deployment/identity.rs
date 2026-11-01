/// Windows PublisherId uses the first 64 SHA256 bits of the UTF-16LE publisher DN.
pub fn family(name: &str, publisher: &str) -> String {
    use sha2::{Digest, Sha256};
    let bytes: Vec<u8> = publisher
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let digest = Sha256::digest(bytes);
    let alphabet = b"0123456789abcdefghjkmnpqrstvwxyz";
    let mut encoded = String::new();
    for i in 0..13 {
        let mut value = 0u8;
        for j in 0..5 {
            let bit = i * 5 + j;
            value = (value << 1)
                | if bit < 64 {
                    (digest[bit / 8] >> (7 - bit % 8)) & 1
                } else {
                    0
                };
        }
        encoded.push(alphabet[usize::from(value)] as char);
    }
    format!("{name}_{encoded}")
}
