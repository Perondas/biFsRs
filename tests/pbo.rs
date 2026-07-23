use bi_fs_rs::pbo::handle::PBOHandle;
use bi_fs_rs::sign::version::BISignVersion;
use std::path::{Path, PathBuf};

mod common;
use common::write_pbo;

#[test]
fn opens_pbo_and_lists_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.pbo");
    write_pbo(
        &path,
        Some("test\\prefix"),
        &[
            ("init.sqf", b"hint 'hello';"),
            ("data\\model.p3d", b"\x00\x01\x02\x03"),
        ],
    );

    let pbo = PBOHandle::open_file(&path).unwrap();

    assert_eq!(pbo.files.len(), 2);
    assert_eq!(pbo.files[0].filename.to_string(), "init.sqf");
    assert_eq!(pbo.files[0].size, 13);
    assert_eq!(pbo.files[1].filename.to_string(), "data\\model.p3d");
    assert_eq!(pbo.files[1].size, 4);
}

#[test]
fn reads_file_content_at_correct_offset() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.pbo");
    write_pbo(
        &path,
        None,
        &[
            ("first.sqf", b"first content"),
            ("second.sqf", b"second content"),
        ],
    );

    let mut pbo = PBOHandle::open_file(&path).unwrap();

    assert_eq!(pbo.get_file_content("first.sqf").unwrap(), b"first content");
    assert_eq!(
        pbo.get_file_content("second.sqf").unwrap(),
        b"second content"
    );
}

#[test]
fn missing_file_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.pbo");
    write_pbo(&path, None, &[("init.sqf", b"hint 'hello';")]);

    let mut pbo = PBOHandle::open_file(&path).unwrap();

    assert!(pbo.get_file_content("does_not_exist.sqf").is_err());
}

#[test]
fn rejects_file_without_version_header() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("garbage.pbo");
    std::fs::write(&path, b"this is not a pbo file at all").unwrap();

    assert!(PBOHandle::open_file(&path).is_err());
}

#[test]
fn content_change_alters_file_hash_but_not_name_hash() {
    let (_dir, mut pbo_a) = open_pbo(None, &[("init.sqf", b"original")]);
    let (_dir2, mut pbo_b) = open_pbo(None, &[("init.sqf", b"tampered")]);

    let hash_a = pbo_a.generate_hash(BISignVersion::V3, 512).unwrap();
    let hash_b = pbo_b.generate_hash(BISignVersion::V3, 512).unwrap();

    // hash2 covers checksum, filenames and prefix: identical here
    assert_eq!(hash_a.1, hash_b.1);
    // hash3 covers the file contents: must differ
    assert_ne!(hash_a.2, hash_b.2);
}

#[test]
fn prefix_changes_hash() {
    let (_dir, mut pbo_a) = open_pbo(Some("prefix_a"), &[("init.sqf", b"content")]);
    let (_dir2, mut pbo_b) = open_pbo(Some("prefix_b"), &[("init.sqf", b"content")]);

    let hash_a = pbo_a.generate_hash(BISignVersion::V3, 512).unwrap();
    let hash_b = pbo_b.generate_hash(BISignVersion::V3, 512).unwrap();

    assert_ne!(hash_a.1, hash_b.1);
    assert_ne!(hash_a.2, hash_b.2);
}

fn open_pbo(prefix: Option<&str>, files: &[(&str, &[u8])]) -> (tempfile::TempDir, PBOHandle) {
    let dir = tempfile::tempdir().unwrap();
    let path: PathBuf = dir.path().join("test.pbo");
    write_pbo(Path::new(&path), prefix, files);
    let pbo = PBOHandle::open_file(&path).unwrap();
    (dir, pbo)
}
