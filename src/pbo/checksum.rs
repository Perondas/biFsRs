use binrw::BinRead;

#[derive(Debug, BinRead, Clone)]
#[brw(little)]
pub struct Checksum {
    pub data: [u8; 20],
}
