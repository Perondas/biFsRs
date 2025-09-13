use crate::pbo::mime::Mime;
use binrw::{BinRead, NullString};

// We allow dead code as its part of the binary file format
#[allow(dead_code)]
#[derive(Debug, BinRead)]
#[brw(little)]
pub struct BinaryHeader {
    pub filename: NullString,
    pub(crate) mime: Mime,
    pub(crate) original: u32,
    pub(crate) reserved: u32,
    pub(crate) timestamp: u32,
    pub size: u32,
}
