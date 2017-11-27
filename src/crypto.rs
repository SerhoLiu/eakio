use std::fmt;
use std::io;
use std::result;

use ring::{aead, digest, hkdf, hmac};
use ring::rand::{SecureRandom, SystemRandom};


static CIPHER: &'static aead::Algorithm = &aead::AES_256_GCM;
static DIGEST: &'static digest::Algorithm = &digest::SHA256;


pub type Result<T> = result::Result<T, Error>;

#[derive(Clone, Copy, Debug)]
pub enum Error {
    GenSalt,
    SaltLenNotMatch(usize),
    OpenKey,
    SealKey,
    SealBufferTooSmall(usize),
    Open,
    Seal,
}

pub struct Salt {
    len: usize,
    bytes: [u8; digest::MAX_OUTPUT_LEN],
}


impl Salt {
    pub fn new() -> Result<Salt> {
        let len = Salt::len();

        let mut bytes = [0u8; digest::MAX_OUTPUT_LEN];
        let rng = SystemRandom::new();
        rng.fill(&mut bytes[..len]).map_err(|_| Error::GenSalt)?;

        Ok(Salt { len, bytes })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Salt> {
        let len = Salt::len();
        if bytes.len() != len {
            return Err(Error::SaltLenNotMatch(len));
        }

        let mut buf = [0u8; digest::MAX_OUTPUT_LEN];
        buf[..len].copy_from_slice(bytes);

        Ok(Salt { len, bytes: buf })
    }

    #[inline]
    pub fn len() -> usize {
        hmac::recommended_key_len(DIGEST)
    }

    #[inline]
    pub fn get_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    #[inline]
    fn get_signing_key(&self) -> hmac::SigningKey {
        hmac::SigningKey::new(DIGEST, &self.bytes[..self.len])
    }
}


const INFO_KEY: &str = "hello kelsi";

#[allow(dead_code)]
pub struct Crypto {
    tag_len: usize,
    key_len: usize,
    nonce_len: usize,

    open_key: aead::OpeningKey,
    open_nonce: Vec<u8>,

    seal_key: aead::SealingKey,
    seal_nonce: Vec<u8>,
}

impl Crypto {
    pub fn new(secret: &[u8], salt: &Salt) -> Result<Crypto> {
        let key_len = CIPHER.key_len();
        let mut key = Vec::with_capacity(key_len);

        // not need init it
        unsafe {
            key.set_len(key_len);
        }
        hkdf::extract_and_expand(
            &salt.get_signing_key(),
            secret,
            INFO_KEY.as_bytes(),
            &mut key,
        );

        let open_key = aead::OpeningKey::new(CIPHER, &key).map_err(|_| Error::OpenKey)?;
        let seal_key = aead::SealingKey::new(CIPHER, &key).map_err(|_| Error::SealKey)?;

        let nonce_len = CIPHER.nonce_len();

        Ok(Crypto {
            tag_len: CIPHER.tag_len(),
            key_len: CIPHER.key_len(),
            nonce_len: CIPHER.nonce_len(),

            open_key,
            open_nonce: vec![0u8; nonce_len],
            seal_key,
            seal_nonce: vec![0u8; nonce_len],
        })
    }

    #[inline]
    pub fn tag_len() -> usize {
        CIPHER.tag_len()
    }

    pub fn encrypt(&mut self, inout: &mut [u8], in_len: usize) -> Result<usize> {
        let out_len = in_len + self.tag_len;
        if inout.len() < out_len {
            return Err(Error::SealBufferTooSmall(out_len));
        }

        match aead::seal_in_place(
            &self.seal_key,
            &self.seal_nonce,
            &[],
            &mut inout[..out_len],
            self.tag_len,
        ) {
            Ok(outlen) => debug_assert_eq!(out_len, outlen),
            Err(_) => return Err(Error::Seal),
        };

        incr_nonce(&mut self.seal_nonce);

        Ok(out_len)
    }

    #[inline]
    pub fn decrypt(&mut self, inout: &mut [u8]) -> Result<usize> {
        match aead::open_in_place(&self.open_key, &self.open_nonce, &[], 0, inout) {
            Ok(buf) => {
                incr_nonce(&mut self.open_nonce);
                Ok(buf.len())
            }
            Err(_) => Err(Error::Open),
        }
    }
}

fn incr_nonce(nonce: &mut [u8]) {
    for byte in nonce.iter_mut() {
        let (sum, overflow) = (*byte).overflowing_add(1);
        *byte = sum;
        if !overflow {
            break;
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::GenSalt => write!(fmt, "generate salt error"),
            Error::SaltLenNotMatch(need) => write!(fmt, "salt length not match, need {}", need),
            Error::OpenKey => write!(fmt, "crypto ring open key error"),
            Error::SealKey => write!(fmt, "crypto ring seal key error"),
            Error::SealBufferTooSmall(need) => {
                write!(fmt, "crypto seal inout buffer too small, need {}", need)
            }
            Error::Open => write!(fmt, "crypto decrypt error"),
            Error::Seal => write!(fmt, "crypto encrypt error"),
        }
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        io::Error::new(io::ErrorKind::Other, format!("{}", err))
    }
}


#[cfg(test)]
mod test {

    #[test]
    fn test_incr_nonce() {
        let mut nonce = [0u8; 4];
        for i in 1..1024 {
            super::incr_nonce(&mut nonce);
            let x = (nonce[0] as usize) + ((nonce[1] as usize) << 8) + ((nonce[2] as usize) << 16)
                + ((nonce[3] as usize) << 24);
            assert_eq!(x, i);
        }
    }
}
