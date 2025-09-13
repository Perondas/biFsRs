use crate::keys::authority::Authority;
use crate::keys::public_key::BIPublicKey;
use crate::{
    pbo::handle::PBOHandle,
    sign::{signature::BiSignature, version::BISignVersion},
};
use anyhow::{Context, Error, Result};
use binrw::{BinRead, BinWrite, NullString};
use rand::rngs::OsRng;
use rsa::{
    traits::{PrivateKeyParts, PublicKeyParts},
    BigUint, RsaPrivateKey,
};
use std::io::{Read, Seek, Write};
use crate::pbo::hashing::hash::PBOHash;

#[derive(Debug, Clone)]
pub struct BIPrivateKey {
    pub authority: Authority,
    key: RsaPrivateKey,
    length: u32,
}

impl BIPrivateKey {
    pub fn from_reader<R: Read + Seek>(reader: &mut R) -> Result<BIPrivateKey> {
        let key = BinaryBiPrivateKey::read(reader).context("Failed to read private key")?;
        key.try_into()
    }

    pub fn to_writer<W: Write + Seek>(&self, writer: &mut W) -> Result<()> {
        let binary: BinaryBiPrivateKey = self.into();
        binary.write(writer).context("Failed to write private key")
    }

    pub fn sign_pbo(&self, handle: &mut PBOHandle, version: BISignVersion) -> Result<BiSignature> {
        let PBOHash(hash1, hash2, hash3) = handle.generate_hash(version, self.length)?;

        let d = self.key.d();
        let n = self.key.n();

        let sig1 = hash1.modpow(d, n);
        let sig2 = hash2.modpow(d, n);
        let sig3 = hash3.modpow(d, n);

        Ok(BiSignature {
            authority: self.authority.clone(),
            version,
            length: self.length,
            exponent: self.key.e().clone(),
            n: self.key.n().clone(),
            sig1,
            sig2,
            sig3,
        })
    }

    pub fn new(authority: Authority, length: u32) -> Result<Self, Error> {
        let mut rng = OsRng::default();

        let mut key = RsaPrivateKey::new(&mut rng, length as usize)?;

        key.precompute()?;

        Ok(BIPrivateKey {
            authority,
            key,
            length,
        })
    }
}

#[derive(BinRead, BinWrite, Debug)]
#[br(little, assert(body_len == key_length / 16 * 9 + 20))]
#[bw(little)]
#[allow(dead_code)]
struct BinaryBiPrivateKey {
    authority: NullString,
    // The length of the body in bytes
    body_len: u32,
    // I am unsure what this magic is, but it is always the same
    #[br(magic = b"\x07\x02\x00\x00\x00\x24\x00\x00", assert(sig_type == *b"RSA2"))]
    #[bw(magic = b"\x07\x02\x00\x00\x00\x24\x00\x00")]
    sig_type: [u8; 4],
    // In bit
    key_length: u32,
    #[br(count = 4)]
    #[bw(pad_size_to = 4)]
    exponent: Vec<u8>,
    #[br(count = key_length / 8)]
    #[bw(pad_size_to = key_length / 8)]
    n: Vec<u8>,
    #[br(count = key_length / 16)]
    #[bw(pad_size_to = key_length / 16)]
    p: Vec<u8>,
    #[br(count = key_length / 16)]
    #[bw(pad_size_to = key_length / 16)]
    q: Vec<u8>,
    #[br(count = key_length / 16)]
    #[bw(pad_size_to = key_length / 16)]
    dp: Vec<u8>,
    #[br(count = key_length / 16)]
    #[bw(pad_size_to = key_length / 16)]
    dq: Vec<u8>,
    #[br(count = key_length / 16)]
    #[bw(pad_size_to = key_length / 16)]
    qinv: Vec<u8>,
    #[br(count = key_length / 8)]
    #[bw(pad_size_to = key_length / 8)]
    d: Vec<u8>,
}

impl TryFrom<BinaryBiPrivateKey> for BIPrivateKey {
    type Error = Error;

    fn try_from(value: BinaryBiPrivateKey) -> Result<Self, Self::Error> {
        let mut key = RsaPrivateKey::from_components(
            BigUint::from_bytes_le(&value.n),
            BigUint::from_bytes_le(&value.exponent),
            BigUint::from_bytes_le(&value.d),
            vec![
                BigUint::from_bytes_le(&value.p),
                BigUint::from_bytes_le(&value.q),
            ],
        )?;

        key.precompute()?;

        Ok(BIPrivateKey {
            authority: Authority::try_new(value.authority.to_string())?,
            key,
            length: value.key_length,
        })
    }
}

impl From<&BIPrivateKey> for BinaryBiPrivateKey {
    fn from(value: &BIPrivateKey) -> Self {
        println!("Converting BIPrivateKey to BinaryBi, {:#?}", value.key.e());

        let x = BinaryBiPrivateKey {
            authority: NullString::from(value.authority.clone().into_inner()),
            body_len: value.length / 16 * 9 + 20,
            sig_type: *b"RSA2",
            key_length: value.length,
            exponent: value.key.e().to_bytes_le(),
            n: value.key.n().to_bytes_le(),
            p: value.key.primes()[0].to_bytes_le(),
            q: value.key.primes()[1].to_bytes_le(),
            dp: value.key.dp().unwrap().to_bytes_le(),
            dq: value.key.dq().unwrap().to_bytes_le(),
            qinv: value.key.qinv().unwrap().to_signed_bytes_le(),
            d: value.key.d().to_bytes_le(),
        };

        //println!("BinaryBiPrivateKey: {:#?}", x);

        x
    }
}

impl From<BIPrivateKey> for BIPublicKey {
    fn from(value: BIPrivateKey) -> Self {
        BIPublicKey::from_parts(value.authority, value.key.to_public_key(), value.length)
    }
}
