use crate::keys::authority::Authority;
use crate::pbo::handle::PBOHandle;
use crate::pbo::hashing::hash::PBOHash;
use crate::sign::signature::BiSignature;
use anyhow::{Context, Error, Result};
use binrw::{BinRead, BinWrite, NullString};
use rsa::{traits::PublicKeyParts, BigUint, RsaPublicKey};
use std::io::{Read, Seek, Write};

#[derive(Debug)]
pub struct BIPublicKey {
    pub authority: Authority,
    key: RsaPublicKey,
    length: u32,
}

impl BIPublicKey {
    pub fn from_reader<R: Read + Seek>(reader: &mut R) -> Result<BIPublicKey> {
        let key = BinaryBiPublicKey::read(reader).context("Failed to read public key")?;
        key.try_into()
    }

    pub fn to_writer<W: Write + Seek>(&self, writer: &mut W) -> Result<()> {
        let binary: BinaryBiPublicKey = self.into();
        binary.write(writer).context("Failed to write public key")
    }

    pub(crate) fn from_parts(authority: Authority, key: RsaPublicKey, length: u32) -> Self {
        BIPublicKey {
            authority,
            key,
            length,
        }
    }

    pub fn verify_signature(&self, pbo: &mut PBOHandle, sig: &BiSignature) -> Result<bool> {
        let PBOHash(hash1, hash2, hash3) = pbo.generate_hash(sig.version, self.length)?;

        let n = self.key.n();
        let e = self.key.e();

        let h1 = sig.sig1.modpow(e, n);
        let h2 = sig.sig2.modpow(e, n);
        let h3 = sig.sig3.modpow(e, n);

        Ok(h1 == hash1 && h2 == hash2 && h3 == hash3)
    }
}

#[derive(BinRead, Debug, BinWrite)]
#[br(little, assert(body_len == key_length / 8 + 20))]
#[bw(little)]
#[allow(dead_code)]
struct BinaryBiPublicKey {
    authority: NullString,
    // The length of the body in bytes
    body_len: u32,
    // I am unsure what this magic is, but it is always the same
    #[br(magic = b"\x06\x02\x00\x00\x00\x24\x00\x00", assert(sig_type == *b"RSA1"))]
    #[bw(magic = b"\x06\x02\x00\x00\x00\x24\x00\x00")]
    sig_type: [u8; 4],
    // In bit
    key_length: u32,
    #[br(count = 4)]
    #[bw(pad_size_to = 4)]
    exponent: Vec<u8>,
    #[br(count = key_length / 8)]
    #[bw(pad_size_to = key_length / 8)]
    key: Vec<u8>,
}

impl TryFrom<BinaryBiPublicKey> for BIPublicKey {
    type Error = Error;

    fn try_from(value: BinaryBiPublicKey) -> Result<Self> {
        Ok(BIPublicKey {
            authority: Authority::try_new(value.authority.to_string())?,
            key: RsaPublicKey::new(
                BigUint::from_bytes_le(&value.key),
                BigUint::from_bytes_le(&value.exponent),
            )?,
            length: value.key_length,
        })
    }
}

impl From<&BIPublicKey> for BinaryBiPublicKey {
    fn from(value: &BIPublicKey) -> Self {
        BinaryBiPublicKey {
            authority: NullString::from(value.authority.clone().into_inner()),
            body_len: 20 + value.key.n().to_bytes_le().len() as u32,
            sig_type: *b"RSA1",
            key_length: value.key.n().to_bytes_le().len() as u32 * 8,
            exponent: value.key.e().to_bytes_le(),
            key: value.key.n().to_bytes_le(),
        }
    }
}
