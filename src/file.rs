use std::fs::File;
use std::io;
use std::io::{BufReader, BufWriter, Cursor};
use std::io::prelude::*;
use std::path::Path;

use byteorder::{BigEndian, ByteOrder, ReadBytesExt};

use super::crypto::{Crypto, Salt};
use super::util::io_error;

const MAGIC: &[u8] = b"KELSI";
const BLOCK_SIZE: usize = 128 * 1024;

// +----+---------+
// |    |  MAGIC  |
// | H  +---------+
// | E  | VERSION |
// | A  +---------+
// | D  |   SALT  |
// +----+---------+
const VERSION_1: u8 = 0x01;

// +----+---------+
// |    |  MAGIC  |
// |    +---------+
// | H  | VERSION |
// | E  +---------+
// | A  |   SALT  |
// | D  +---------+
// |    |   SIZE  |
// +----+---------+
const VERSION_2: u8 = 0x02;

#[derive(Clone)]
pub struct FileCrypt<'a> {
    secret: &'a [u8],
    buffer: Vec<u8>,
}

impl<'a> FileCrypt<'a> {
    pub fn new(secret: &'a [u8]) -> FileCrypt {
        let size = BLOCK_SIZE + Crypto::tag_len();

        FileCrypt {
            secret,
            buffer: vec![0u8; size],
        }
    }

    pub fn encrypt(&mut self, src: &Path, dest: &Path) -> io::Result<()> {
        let salt = Salt::new()?;
        let mut crypto = Crypto::new(self.secret, &salt)?;

        let src_f = File::open(src)?;
        let mut size = src_f.metadata()?.len() as usize;
        let mut reader = BufReader::new(src_f);

        let dest_f = File::create(dest)?;
        let mut writer = BufWriter::new(dest_f);

        // write header metadata
        writer.write_all(MAGIC)?;
        writer.write_all(&[VERSION_2])?;
        writer.write_all(salt.get_bytes())?;

        // write placeholder size data
        let size_start = MAGIC.len() + 1 + Salt::len();
        let size_len = 8 + Crypto::tag_len();
        let dest_size = size_start + size_len + crypto_data_size(size);

        BigEndian::write_u64(&mut self.buffer, dest_size as u64);
        let len = crypto.encrypt(&mut self.buffer, 8)?;
        writer.write_all(&self.buffer[..len])?;

        loop {
            match reader.read_exact(&mut self.buffer[..BLOCK_SIZE]) {
                Ok(()) => {
                    let len = crypto.encrypt(&mut self.buffer, BLOCK_SIZE)?;
                    writer.write_all(&self.buffer[..len])?;
                    size -= BLOCK_SIZE;
                }
                Err(e) => if e.kind() == io::ErrorKind::UnexpectedEof {
                    if size != 0 {
                        let len = crypto.encrypt(&mut self.buffer, size)?;
                        writer.write_all(&self.buffer[..len])?;
                    }
                    break;
                } else {
                    return Err(e);
                },
            }
        }

        Ok(())
    }

    pub fn decrypt(&mut self, src: &Path, dest: &Path) -> io::Result<()> {
        let src_f = File::open(src)?;
        let mut size = src_f.metadata()?.len() as usize;
        let mut reader = BufReader::new(src_f);

        let dest_f = File::create(dest)?;
        let mut writer = BufWriter::new(dest_f);

        reader.read_exact(&mut self.buffer[..MAGIC.len()])?;
        if &self.buffer[..MAGIC.len()] != MAGIC {
            return Err(io_error("magic not match"));
        }

        let mut version = [0u8];
        reader.read_exact(&mut version)?;
        if version[0] != VERSION_1 && version[0] != VERSION_2 {
            return Err(io_error(&format!("version '{}' not support", version[0])));
        }

        reader.read_exact(&mut self.buffer[..Salt::len()])?;
        let salt = Salt::from_bytes(&self.buffer[..Salt::len()])?;
        let mut crypto = Crypto::new(self.secret, &salt)?;

        if version[0] == VERSION_2 {
            let size_len = 8 + Crypto::tag_len();
            reader.read_exact(&mut self.buffer[..size_len])?;
            crypto.decrypt(&mut self.buffer[..size_len])?;

            let mut rdr = Cursor::new(&self.buffer[..8]);
            let len = rdr.read_u64::<BigEndian>()?;
            if len != size as u64 {
                return Err(io_error(&format!(
                    "file size not match, {} != {}",
                    size, len
                )));
            }
        }

        let header_len = match version[0] {
            VERSION_1 => MAGIC.len() + 1 + Salt::len(),
            VERSION_2 => MAGIC.len() + 1 + Salt::len() + 8 + Crypto::tag_len(),
            _ => unreachable!(),
        };
        size -= header_len;

        loop {
            match reader.read_exact(&mut self.buffer) {
                Ok(()) => {
                    let len = crypto.decrypt(&mut self.buffer)?;
                    writer.write_all(&self.buffer[..len])?;
                    size -= self.buffer.len();
                }
                Err(e) => if e.kind() == io::ErrorKind::UnexpectedEof {
                    if size != 0 {
                        let len = crypto.decrypt(&mut self.buffer[..size])?;
                        writer.write_all(&self.buffer[..len])?;
                    }

                    break;
                } else {
                    return Err(e);
                },
            }
        }

        Ok(())
    }
}

// calc crypto in_size data out size
fn crypto_data_size(in_size: usize) -> usize {
    let nblock = if in_size == 0 {
        0
    } else {
        (in_size - 1) / BLOCK_SIZE + 1
    };

    let tag_size = nblock * Crypto::tag_len();

    in_size + tag_size
}
