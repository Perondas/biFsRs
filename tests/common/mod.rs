use std::path::Path;

/// Builds a minimal uncompressed PBO on disk in the layout `PBOHandle::open_file` expects:
/// version header, properties, file headers, blank terminator header, padding byte,
/// file blobs, and a 20-byte checksum.
pub fn write_pbo(path: &Path, prefix: Option<&str>, files: &[(&str, &[u8])]) {
    let mut buf: Vec<u8> = Vec::new();

    // Version header: empty filename, Vers mime, four zeroed u32 fields
    buf.push(0);
    buf.extend(b"sreV");
    buf.extend([0u8; 16]);

    // Properties, terminated by an empty key
    if let Some(prefix) = prefix {
        buf.extend(b"prefix\0");
        buf.extend(prefix.as_bytes());
        buf.push(0);
    }
    buf.push(0);

    // One header per file: name, Blank mime, original size, reserved, timestamp, size
    for (name, data) in files {
        let size = (data.len() as u32).to_le_bytes();
        buf.extend(name.as_bytes());
        buf.push(0);
        buf.extend([0u8; 4]);
        buf.extend(size);
        buf.extend([0u8; 8]);
        buf.extend(size);
    }

    // Blank terminator header
    buf.push(0);
    buf.extend([0u8; 20]);

    // Padding byte before the blob
    buf.push(0);

    // File blobs in header order
    for (_, data) in files {
        buf.extend(*data);
    }

    // 20-byte checksum; not validated on read, only fed into the signature hash
    buf.extend([0xAB; 20]);

    std::fs::write(path, buf).unwrap();
}
