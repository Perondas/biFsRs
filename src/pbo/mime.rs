use binrw::{BinRead, BinWrite};

#[derive(Clone, Default, Debug, PartialEq, Eq, BinRead, BinWrite)]
#[brw(little)]
pub enum Mime {
    /// The version of the PBO
    /// Always the first header
    #[brw(magic = 0x5665_7273u32)]
    Vers,
    /// A compressed entry
    #[brw(magic = 0x4370_7273u32)]
    Cprs,
    /// A compressed entry used by VBS
    #[brw(magic = 0x456e_6372u32)]
    Enco,
    #[default]
    #[brw(magic = 0x0000_0000u32)]
    /// A blank entry, use to denote the end of the properties section
    Blank,
}
