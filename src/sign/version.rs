use binrw::{BinRead, BinWrite};
use std::path::PathBuf;

/// Version of BI's signature
#[derive(PartialEq, Eq, Copy, Clone, Debug, Default, BinRead, BinWrite)]
pub enum BISignVersion {
    #[brw(magic = 2u32)]
    V2,
    #[default]
    #[brw(magic = 3u32)]
    V3,
}

const V2_FILES: [&str; 13] = [
    "fxy", "jpg", "lip", "ogg", "p3d", "paa", "pac", "png", "rtm", "rvmat", "tga", "wrp", "wss",
];
const V3_FILES: [&str; 11] = [
    "bikb", "cfg", "ext", "fsm", "h", "hpp", "inc", "sqf", "sqfc", "sqm", "sqs",
];

impl BISignVersion {
    pub fn should_hash_file(&self, name: &str) -> bool {
        let path = PathBuf::from(name);
        let ext = path
            .extension()
            .unwrap_or_default()
            .to_string_lossy();

        match self {
            Self::V2 => V2_FILES.contains(&&*ext),
            Self::V3 => V3_FILES.contains(&&*ext),
        }
    }

    /// Get the nothing string for the version
    pub const fn nothing(&self) -> &str {
        match self {
            Self::V2 => "nothing",
            Self::V3 => "gnihton",
        }
    }
}
