use bi_fs_rs::keys::authority::Authority;
use bi_fs_rs::keys::private_key::BIPrivateKey;
use bi_fs_rs::keys::public_key::BIPublicKey;
use bi_fs_rs::pbo::handle::PBOHandle;
use bi_fs_rs::sign::signature::BiSignature;
use bi_fs_rs::sign::version::BISignVersion;
use std::io::Cursor;

mod common;
use common::write_pbo;

// Small key so key generation stays fast in debug builds; the signing code
// is key-size agnostic.
const KEY_LENGTH: u32 = 512;

fn test_key() -> BIPrivateKey {
    BIPrivateKey::new(Authority::try_new("test_authority").unwrap(), KEY_LENGTH).unwrap()
}

fn open_pbo(files: &[(&str, &[u8])]) -> (tempfile::TempDir, PBOHandle) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.pbo");
    write_pbo(&path, Some("test\\prefix"), files);
    let pbo = PBOHandle::open_file(&path).unwrap();
    (dir, pbo)
}

#[test]
fn sign_and_verify_round_trip() {
    let (_dir, mut pbo) = open_pbo(&[
        ("init.sqf", b"hint 'hello';"),
        ("data.bin", b"\x00\x01\x02\x03"),
    ]);

    let key = test_key();
    let signature = key.sign_pbo(&mut pbo, BISignVersion::V3).unwrap();
    let public_key: BIPublicKey = key.into();

    assert!(public_key.verify_signature(&mut pbo, &signature).unwrap());
}

#[test]
fn verify_fails_for_tampered_pbo() {
    let (_dir, mut pbo) = open_pbo(&[("init.sqf", b"hint 'hello';")]);
    let (_dir2, mut tampered) = open_pbo(&[("init.sqf", b"hint 'evil!';")]);

    let key = test_key();
    let signature = key.sign_pbo(&mut pbo, BISignVersion::V3).unwrap();
    let public_key: BIPublicKey = key.into();

    assert!(!public_key.verify_signature(&mut tampered, &signature).unwrap());
}

#[test]
fn verify_fails_with_wrong_key() {
    let (_dir, mut pbo) = open_pbo(&[("init.sqf", b"hint 'hello';")]);

    let signature = test_key().sign_pbo(&mut pbo, BISignVersion::V3).unwrap();
    let other_public_key: BIPublicKey = test_key().into();

    assert!(!other_public_key.verify_signature(&mut pbo, &signature).unwrap());
}

#[test]
fn sign_and_verify_pbo_without_hashable_files() {
    // No file matches the V3 extension list, exercising the "nothing" hash path
    let (_dir, mut pbo) = open_pbo(&[("texture.paa", b"\x00\x01\x02\x03")]);

    let key = test_key();
    let signature = key.sign_pbo(&mut pbo, BISignVersion::V3).unwrap();
    let public_key: BIPublicKey = key.into();

    assert!(public_key.verify_signature(&mut pbo, &signature).unwrap());
}

#[test]
fn signature_binary_round_trip() {
    let (_dir, mut pbo) = open_pbo(&[("init.sqf", b"hint 'hello';")]);
    let signature = test_key().sign_pbo(&mut pbo, BISignVersion::V3).unwrap();

    let mut cursor = Cursor::new(Vec::new());
    signature.to_writer(&mut cursor).unwrap();
    cursor.set_position(0);
    let read_back = BiSignature::from_reader(&mut cursor).unwrap();

    assert_eq!(read_back, signature);
}

#[test]
fn private_key_binary_round_trip() {
    let key = test_key();

    let mut cursor = Cursor::new(Vec::new());
    key.to_writer(&mut cursor).unwrap();
    cursor.set_position(0);
    let read_back = BIPrivateKey::from_reader(&mut cursor).unwrap();

    assert_eq!(read_back.authority, key.authority);

    // Re-serializing the read-back key must reproduce the exact same bytes
    let mut second = Cursor::new(Vec::new());
    read_back.to_writer(&mut second).unwrap();
    assert_eq!(second.into_inner(), cursor.into_inner());
}

#[test]
fn read_back_private_key_produces_valid_signatures() {
    let (_dir, mut pbo) = open_pbo(&[("init.sqf", b"hint 'hello';")]);
    let key = test_key();

    let mut cursor = Cursor::new(Vec::new());
    key.to_writer(&mut cursor).unwrap();
    cursor.set_position(0);
    let read_back = BIPrivateKey::from_reader(&mut cursor).unwrap();

    let signature = read_back.sign_pbo(&mut pbo, BISignVersion::V3).unwrap();
    let public_key: BIPublicKey = key.into();

    assert!(public_key.verify_signature(&mut pbo, &signature).unwrap());
}

#[test]
fn public_key_binary_round_trip() {
    let (_dir, mut pbo) = open_pbo(&[("init.sqf", b"hint 'hello';")]);
    let key = test_key();
    let signature = key.sign_pbo(&mut pbo, BISignVersion::V3).unwrap();
    let public_key: BIPublicKey = key.into();

    let mut cursor = Cursor::new(Vec::new());
    public_key.to_writer(&mut cursor).unwrap();
    cursor.set_position(0);
    let read_back = BIPublicKey::from_reader(&mut cursor).unwrap();

    assert_eq!(read_back.authority, public_key.authority);
    assert!(read_back.verify_signature(&mut pbo, &signature).unwrap());
}

#[test]
fn v2_signature_round_trip() {
    let (_dir, mut pbo) = open_pbo(&[("texture.paa", b"\x00\x01\x02\x03")]);

    let key = test_key();
    let signature = key.sign_pbo(&mut pbo, BISignVersion::V2).unwrap();
    let public_key: BIPublicKey = key.into();

    assert!(public_key.verify_signature(&mut pbo, &signature).unwrap());
}
