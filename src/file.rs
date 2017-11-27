use std::io;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::fs::File;
use std::path::Path;

use super::v1;
use super::util::io_error;
use super::crypto::{Crypto, Salt};

// +----+---------+
// |    |  MAGIC  |
// | H  +---------+
// | E  | VERSION |
// | A  +---------+
// | D  |   SALT  |
// +----+---------+
//
const BLOCK_SIZE: usize = 128 * 1024;

#[derive(Clone)]
pub struct FileCrypt<'a> {
    secret: &'a [u8],
    buffer: Vec<u8>,
}

impl<'a> FileCrypt<'a> {
    pub fn new(secret: &'a [u8]) -> FileCrypt {
        let size = BLOCK_SIZE + Crypto::tag_len();

        let mut buffer = Vec::with_capacity(size);
        unsafe {
            buffer.set_len(size);
        }

        FileCrypt { secret, buffer }
    }

    pub fn encrypt(&mut self, src: &Path, dest: &Path) -> io::Result<()> {
        let salt = Salt::new()?;
        let mut crypto = Crypto::new(self.secret, &salt)?;

        let src_f = File::open(src)?;
        let mut size = src_f.metadata()?.len() as usize;
        let mut reader = BufReader::new(src_f);

        let dest_f = File::create(dest)?;
        let mut writer = BufWriter::new(dest_f);

        writer.write_all(v1::MAGIC)?;
        writer.write_all(&[v1::VERSION])?;
        writer.write_all(salt.get_bytes())?;

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

        reader.read_exact(&mut self.buffer[..v1::MAGIC.len()])?;
        if &self.buffer[..v1::MAGIC.len()] != v1::MAGIC {
            return Err(io_error("magic not match"));
        }

        reader.read_exact(&mut self.buffer[..1])?;
        if self.buffer[0] != v1::VERSION {
            return Err(io_error("version not match"));
        }

        reader.read_exact(&mut self.buffer[..Salt::len()])?;
        let salt = Salt::from_bytes(&self.buffer[..Salt::len()])?;
        let mut crypto = Crypto::new(self.secret, &salt)?;

        let header_len = v1::MAGIC.len() + 1 + Salt::len();
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
