use crate::pbo::mime::Mime;
use binrw::{BinRead, NullString};

// We allow dead code as its part of the binary file format
#[allow(dead_code)]
#[derive(Debug, BinRead)]
#[brw(little)]
pub(crate) struct BinaryHeader {
    pub(crate) filename: NullString,
    pub(crate) mime: Mime,
    pub(crate) original: u32,
    pub(crate) reserved: u32,
    pub(crate) timestamp: u32,
    pub(crate) size: u32,
}
