use crate::pbo::{checksum::Checksum, header::BinaryHeader, mime::Mime};
use anyhow::{ensure, Result};
use binrw::{BinRead, NullString};
use std::{
    collections::HashMap,
    io::{Seek, SeekFrom::Current},
    path::Path,
};


#[derive(Debug)]
#[allow(dead_code)]
pub struct PBOHandle {
    pub(crate) properties: HashMap<String, String>,
    pub(crate) version_header: BinaryHeader,
    pub(crate) files: Vec<BinaryHeader>,
    pub checksum: Checksum,
    pub(crate) handle: std::fs::File,
    pub(crate) blob_start: u64,
}

impl PBOHandle {
    pub fn open_file(path: &Path) -> Result<Self> {
        let mut handle = std::fs::File::open(path)?;
        let mut properties = HashMap::new();
        let mut files = Vec::new();

        // Get the version header
        let version_header = BinaryHeader::read(&mut handle)?;

        ensure!(
            version_header.mime == Mime::Vers,
            "First header must be a version header"
        );

        // Get the properties
        loop {
            let key = NullString::read(&mut handle)?.to_string();
            if key.is_empty() {
                break;
            }
            let value = NullString::read(&mut handle)?.to_string();
            properties.insert(key, value);
        }

        // Get the headers
        loop {
            let header = BinaryHeader::read(&mut handle)?;
            if header.filename.is_empty() {
                break;
            }
            files.push(header);
        }

        // Skip past the blob + 1
        let blob_start = handle.stream_position()?;
        let blob_size = i64::from(files.iter().map(|f| f.size).sum::<u32>());

        handle.seek(Current(blob_size + 1))?;

        // Get the checksum
        let checksum = Checksum::read(&mut handle)?;

        // We should be at the end of the file
        ensure!(
            handle.stream_position()? == handle.metadata()?.len(),
            "File is not at the end"
        );

        Ok(Self {
            properties,
            version_header,
            files,
            checksum,
            handle,
            blob_start,
        })
    }
}
