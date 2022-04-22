use data_encoding::HEXUPPER;
use ring::digest::{Context, Digest, SHA256};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::Path;

pub (crate) fn sha256_digest<R: Read>(mut reader: R) -> Result<Digest, std::io::Error> {
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 1024];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }

    Ok(context.finish())
}

/// Find sha256 sum of the file
pub (crate) fn checksum(path:&Path) -> String {
    let input = File::open(path).expect("Unable to open file for read");
    let reader = BufReader::new(input);
    let digest = sha256_digest(reader).expect("Error calculating checksum");
    HEXUPPER.encode(digest.as_ref())
}
