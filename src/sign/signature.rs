use crate::keys::authority::Authority;
use crate::sign::version::BISignVersion;
use anyhow::{Context, Result};
use binrw::{BinRead, BinWrite, NullString};
use rsa::BigUint;
use std::io::{Read, Seek, Write};

#[derive(Debug, PartialEq)]
pub struct BiSignature {
    pub(crate) version: BISignVersion,
    pub(crate) authority: Authority,
    pub(crate) length: u32,
    pub(crate) exponent: BigUint,
    pub(crate) n: BigUint,
    pub(crate) sig1: BigUint,
    pub(crate) sig2: BigUint,
    pub(crate) sig3: BigUint,
}

impl BiSignature {
    pub fn from_reader<R: Read + Seek>(reader: &mut R) -> Result<Self> {
        let binary = BinaryBiSignature::read(reader).context("Failed to read signature")?;
        binary.try_into()
    }

    pub fn to_writer<W: Write + Seek>(&self, writer: &mut W) -> Result<()> {
        let binary: BinaryBiSignature = self.into();
        binary.write(writer).context("Failed to write signature")?;
        Ok(())
    }
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
struct BinaryBiSignature {
    authority: NullString,
    body_len: u32,
    #[brw(magic = b"\x06\x02\x00\x00\x00\x24\x00\x00")]
    #[br(assert(sig_type == *b"RSA1"))]
    sig_type: [u8; 4],
    key_length: u32,
    #[br(count = body_len - 4 * 4 - (key_length / 8))]
    #[bw(pad_size_to = body_len - 4 * 4 - (key_length / 8))]
    exponent: Vec<u8>,
    #[br(count = key_length / 8)]
    n: Vec<u8>,
    // body_len ends here
    #[br(assert(sig1_len == key_length / 8))]
    sig1_len: u32,
    #[br(count = sig1_len)]
    #[bw(pad_size_to = *sig1_len)]
    sig1: Vec<u8>,
    sign_version: BISignVersion,
    #[br(assert(sig2_len == key_length / 8))]
    sig2_len: u32,
    #[br(count = sig2_len)]
    #[bw(pad_size_to = *sig2_len)]
    sig2: Vec<u8>,
    #[br(assert(sig3_len == key_length / 8))]
    sig3_len: u32,
    #[br(count = sig3_len)]
    #[bw(pad_size_to = *sig3_len)]
    sig3: Vec<u8>,
}

impl TryFrom<BinaryBiSignature> for BiSignature {
    type Error = anyhow::Error;

    fn try_from(binary: BinaryBiSignature) -> Result<Self, Self::Error> {
        Ok(Self {
            authority: Authority::try_new(binary.authority.to_string())?,
            length: binary.key_length,
            exponent: BigUint::from_bytes_le(&binary.exponent),
            n: BigUint::from_bytes_le(&binary.n),
            sig1: BigUint::from_bytes_le(&binary.sig1),
            sig2: BigUint::from_bytes_le(&binary.sig2),
            sig3: BigUint::from_bytes_le(&binary.sig3),
            version: binary.sign_version,
        })
    }
}

impl From<&BiSignature> for BinaryBiSignature {
    fn from(value: &BiSignature) -> Self {
        Self {
            authority: NullString::from(value.authority.clone().into_inner()),
            body_len: 20 + value.n.to_bytes_le().len() as u32,
            sig_type: *b"RSA1",
            key_length: value.length,
            exponent: value.exponent.to_bytes_le(),
            n: value.n.to_bytes_le(),
            sig1_len: value.sig1.to_bytes_le().len() as u32,
            sig1: value.sig1.to_bytes_le(),
            sign_version: value.version,
            sig2_len: value.sig2.to_bytes_le().len() as u32,
            sig2: value.sig2.to_bytes_le(),
            sig3_len: value.sig3.to_bytes_le().len() as u32,
            sig3: value.sig3.to_bytes_le(),
        }
    }
}
