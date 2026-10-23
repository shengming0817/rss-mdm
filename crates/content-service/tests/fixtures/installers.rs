//! Minimal native containers for format/HTTP tests. They are not installable product releases.
use std::io::{Cursor, Write};
pub fn exe(version: &str) -> Vec<u8> {
    exe_machine(version, 0x8664)
}
pub fn exe_machine(version: &str, machine: u16) -> Vec<u8> {
    let mut bytes = vec![0; 128 * 1024 + 3];
    fn u16_at(bytes: &mut [u8], at: usize, v: u16) {
        bytes[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn u32_at(bytes: &mut [u8], at: usize, v: u32) {
        bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    bytes[..2].copy_from_slice(b"MZ");
    u32_at(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    u16_at(&mut bytes, 0x84, machine);
    u16_at(&mut bytes, 0x86, 1);
    u16_at(&mut bytes, 0x94, 240);
    u16_at(&mut bytes, 0x96, 0x22);
    let opt = 0x98;
    u16_at(&mut bytes, opt, 0x20b);
    u32_at(&mut bytes, opt + 16, 0x1000);
    u32_at(&mut bytes, opt + 32, 4096);
    u32_at(&mut bytes, opt + 36, 512);
    u32_at(&mut bytes, opt + 56, 8192);
    u32_at(&mut bytes, opt + 60, 512);
    u16_at(&mut bytes, opt + 68, 3);
    u32_at(&mut bytes, opt + 108, 16);
    let section = opt + 240;
    bytes[section..section + 5].copy_from_slice(b".text");
    u32_at(&mut bytes, section + 8, 1);
    u32_at(&mut bytes, section + 12, 4096);
    u32_at(&mut bytes, section + 16, 512);
    u32_at(&mut bytes, section + 20, 512);
    u32_at(&mut bytes, section + 36, 0x60000020);
    bytes[512] = 0xc3;
    bytes.extend_from_slice(version.as_bytes());
    bytes
}
pub fn msi(version: Option<&str>, arm: bool) -> Vec<u8> {
    let mut package =
        msi::Package::create(msi::PackageType::Installer, Cursor::new(Vec::new())).unwrap();
    package
        .summary_info_mut()
        .set_arch(if arm { "Arm64" } else { "x64" });
    package
        .create_table(
            "Property",
            vec![
                msi::Column::build("Property").primary_key().string(72),
                msi::Column::build("Value").string(255),
            ],
        )
        .unwrap();
    if let Some(version) = version {
        package
            .insert_rows(msi::Insert::into("Property").row(vec![
                msi::Value::from("ProductVersion"),
                msi::Value::from(version),
            ]))
            .unwrap();
    }
    package.into_inner().unwrap().into_inner()
}
pub fn pkg(version: &str) -> Vec<u8> {
    let info = format!(r#"<?xml version="1.0"?><pkg-info identifier="com.rss.agent.pkg" version="{version}" format-version="2" auth="root"><bundle id="com.rss.agent"/></pkg-info>"#).into_bytes();
    let toc = format!(
        r#"<?xml version="1.0"?><xar><toc><file id="1"><name>PackageInfo</name><type>file</type><data><offset>0</offset><length>{}</length><size>{}</size><encoding style="application/octet-stream"/></data></file></toc></xar>"#,
        info.len(),
        info.len()
    );
    let mut writer = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    writer.write_all(toc.as_bytes()).unwrap();
    let compressed = writer.finish().unwrap();
    let mut bytes = b"xar!".to_vec();
    bytes.extend(28u16.to_be_bytes());
    bytes.extend(1u16.to_be_bytes());
    bytes.extend((compressed.len() as u64).to_be_bytes());
    bytes.extend((toc.len() as u64).to_be_bytes());
    bytes.extend(0u32.to_be_bytes());
    bytes.extend(compressed);
    bytes.extend(info);
    bytes
}
pub fn msix(version: &str, arm: bool) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("AppxManifest.xml", zip::write::SimpleFileOptions::default())
        .unwrap();
    write!(zip,r#"<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="RSS.Agent" Publisher="CN=RSS" Version="{version}" ProcessorArchitecture="{}"/><Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0"/></Dependencies></Package>"#,if arm {"arm64"}else{"x64"}).unwrap();
    zip.finish().unwrap().into_inner()
}

/// Genuine Apple tool containers; they contain only the documented text payload.
pub fn pkgbuild() -> Vec<u8> {
    include_bytes!("pkgbuild.pkg").to_vec()
}
pub fn productbuild() -> Vec<u8> {
    include_bytes!("productbuild.pkg").to_vec()
}
