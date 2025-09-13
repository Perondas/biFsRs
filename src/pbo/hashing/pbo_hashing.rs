use std::io::{Read, Seek};
use std::io::SeekFrom::Current;
use rsa::signature::digest::Digest;
use sha1::Sha1;
use crate::pbo::handle::PBOHandle;
use crate::pbo::hashing::hash::{pad_hash, PBOHash};
use crate::pbo::header::BinaryHeader;
use crate::sign::version::BISignVersion;

impl PBOHandle {
    pub fn generate_hash(&mut self, version: BISignVersion, length: u32) -> anyhow::Result<PBOHash> {
        let hash1 = self.checksum.data;

        // Seek to the start of the blob
        self.handle
            .seek(std::io::SeekFrom::Start(self.blob_start))?;

        // Read file and hash them
        let mut file_hasher = sha1::Sha1::new();
        let mut nothing = true;
        for header in &self.files {
            if header.size != 0 && version.should_hash_file(&header.filename.to_string()) {
                let mut file = vec![0; header.size as usize];
                self.handle.read_exact(&mut file)?;
                file_hasher.update(&file);
                nothing = false;
            } else {
                self.handle.seek(Current(i64::from(header.size)))?;
            }
        }

        if nothing {
            file_hasher.update(version.nothing());
        }

        let file_hash = file_hasher.finalize().to_vec();

        let mut hasher = Sha1::new();
        hasher.update(self.checksum.data);
        hasher.update(hash_filenames(&self.files));

        if let Some(prefix) = self.properties.get("prefix") {
            hasher.update(prefix.as_bytes());
            if !prefix.ends_with('\\') {
                hasher.update(b"\\");
            }
        }

        let hash2 = hasher.finalize().to_vec();

        let mut hasher = Sha1::new();
        hasher.update(file_hash);
        hasher.update(hash_filenames(&self.files));
        if let Some(prefix) = self.properties.get("prefix") {
            hasher.update(prefix.as_bytes());
            if !prefix.ends_with('\\') {
                hasher.update(b"\\");
            }
        }
        let hash3 = hasher.finalize().to_vec();

        Ok(PBOHash(
            pad_hash(&hash1, (length / 8) as usize),
            pad_hash(&hash2, (length / 8) as usize),
            pad_hash(&hash3, (length / 8) as usize),
        ))
    }
}

fn hash_filenames(headers: &[BinaryHeader]) -> Vec<u8> {
    let mut header_hasher = Sha1::new();
    for header in headers {
        if header.size != 0 {
            header_hasher.update(
                header
                    .filename
                    .to_string()
                    .replace('/', "\\")
                    .to_lowercase(),
            );
        }
    }
    header_hasher.finalize().to_vec()
}
