use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn installation_secret_replay_never_regenerates_missing_or_damaged_material() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("installation");
    let journal = Journal::open(&root).unwrap();
    let original = protected(&journal, "ledger.key", 32, true).unwrap();
    assert_eq!(
        original.as_slice(),
        protected(&journal, "ledger.key", 32, false)
            .unwrap()
            .as_slice()
    );
    let path = journal.path("ledger.key").unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(matches!(
        protected(&journal, "ledger.key", 32, false),
        Err(Error::Corrupt)
    ));
    assert!(!path.exists());
    std::fs::write(&path, b"damaged").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        protected(&journal, "ledger.key", 32, false),
        Err(Error::Corrupt)
    ));
    assert_eq!(std::fs::read(path).unwrap(), b"damaged");
}

#[test]
fn journal_excludes_concurrent_installers_and_rejects_secret_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("installation");
    let journal = Journal::open(&root).unwrap();
    assert!(matches!(Journal::open(&root), Err(Error::Busy)));
    let path = journal.secret("original", &[7; 32]).unwrap();
    assert!(matches!(
        journal.secret("original", &[8; 32]),
        Err(Error::Conflict)
    ));
    assert_eq!(std::fs::read(path).unwrap(), [7; 32]);
    assert!(journal.secret("../outside", b"value").is_err());
}
