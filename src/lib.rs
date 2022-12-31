use std::io::{Read, Write};

use byteorder::{BigEndian, ByteOrder};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, AeadCore, AeadInPlace, KeyInit, OsRng},
    Key, XChaCha20Poly1305, XNonce,
};

use flate2::Compression;
use speedy::{Readable, Writable};

// Branka magic byte.
const VERSION: u8 = 0xBA;
// Base 62 alphabet.
const BASE62: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

pub struct Branka {
    cipher: XChaCha20Poly1305,
    ttl: u32,
}

#[derive(Debug)]
pub enum BrankaError {
    InvalidBase62,
    InvalidDataLength,
    InvalidVersion,
    InvalidData,
    Expired,
}

impl Branka {
    // Create a new Branka instance.
    // key: 32 bytes key.
    // ttl: Time to live in seconds, only used for decoding.
    pub fn new(key: &[u8], ttl: u32) -> Branka {
        let key = Key::from_slice(key);
        let cipher = XChaCha20Poly1305::new(&key);
        Branka { cipher, ttl }
    }

    pub fn encode_bytes(&self, data: &[u8]) -> String {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let timestamp = get_timestamp();

        // Version || Timestamp || Nonce
        let mut header = [0u8; 29];
        header[0] = VERSION;
        BigEndian::write_u32(&mut header[1..5], timestamp);
        header[5..].copy_from_slice(&nonce);

        let mut buf_crypt = vec![0u8; data.len() + 16 + 29];
        buf_crypt[..29].copy_from_slice(&header);
        buf_crypt[29..29 + data.len()].copy_from_slice(data);

        let sign = self
            .cipher
            .encrypt_in_place_detached(&nonce, &header, &mut buf_crypt[29..29 + data.len()])
            .unwrap();

        buf_crypt[29 + data.len()..].copy_from_slice(&sign);

        base_x::encode(BASE62, &buf_crypt)
    }

    pub fn decode_bytes(&self, data: &str) -> Result<Vec<u8>, BrankaError> {
        let buf_crypt = base_x::decode(BASE62, data).map_err(|_| BrankaError::InvalidBase62)?;
        if buf_crypt.len() < 29 + 16 {
            return Err(BrankaError::InvalidDataLength);
        }

        let version = buf_crypt[0];
        if version != VERSION {
            return Err(BrankaError::InvalidVersion);
        }

        let timestamp = BigEndian::read_u32(&buf_crypt[1..5]);

        let nonce = XNonce::from_slice(&buf_crypt[5..29]);

        let sign = GenericArray::from_slice(&buf_crypt[buf_crypt.len() - 16..]);

        let mut buf = vec![0u8; buf_crypt.len() - 29 - 16];
        buf.copy_from_slice(&buf_crypt[29..buf_crypt.len() - 16]);

        self.cipher
            .decrypt_in_place_detached(&nonce, &buf_crypt[..29], &mut buf, sign)
            .map_err(|_| BrankaError::InvalidData)?;

        if timestamp > get_timestamp() + self.ttl {
            return Err(BrankaError::Expired);
        }

        Ok(buf)
    }

    pub fn encode_struct<T>(&self, data: &T) -> String
    where
        T: Writable<speedy::LittleEndian>,
    {
        let buf = data.write_to_vec().unwrap();
        self.encode_bytes(&buf)
    }

    pub fn decode_struct<T>(&self, data: &str) -> Result<T, BrankaError>
    where
        T: for<'a> speedy::Readable<'a, speedy::LittleEndian>,
    {
        let buf = self.decode_bytes(data)?;
        let data = T::read_from_buffer(&buf).map_err(|_| BrankaError::InvalidData)?;
        Ok(data)
    }

    pub fn encode_gz_struct<T>(&self, data: &T, compression: Compression) -> String
    where
        T: Writable<speedy::LittleEndian>,
    {
        let buf = data.write_to_vec().unwrap();
        let mut b = flate2::write::GzEncoder::new(Vec::new(), compression);
        b.write_all(&buf).unwrap();
        let buf = b.finish().unwrap();

        self.encode_bytes(&buf)
    }

    pub fn decode_gz_struct<T>(&self, data: &str) -> Result<T, BrankaError>
    where
        T: for<'a> speedy::Readable<'a, speedy::LittleEndian>,
    {
        let decoded = self.decode_bytes(data)?;
        let mut b = flate2::read::GzDecoder::new(&decoded[..]);

        let mut buf = Vec::new();
        b.read_to_end(&mut buf).unwrap();

        let data = T::read_from_buffer(&buf).map_err(|_| BrankaError::InvalidData)?;
        Ok(data)
    }

    pub fn encode_zlib_struct<T>(&self, data: &T, compression: Compression) -> String
    where
        T: Writable<speedy::LittleEndian>,
    {
        let buf = data.write_to_vec().unwrap();
        let mut b = flate2::write::ZlibEncoder::new(Vec::new(), compression);
        b.write_all(&buf).unwrap();
        let buf = b.finish().unwrap();

        self.encode_bytes(&buf)
    }

    pub fn decode_zlib_struct<T>(&self, data: &str) -> Result<T, BrankaError>
    where
        T: for<'a> speedy::Readable<'a, speedy::LittleEndian>,
    {
        let decoded = self.decode_bytes(data)?;
        let mut b = flate2::read::ZlibDecoder::new(&decoded[..]);

        let mut buf = Vec::new();
        b.read_to_end(&mut buf).unwrap();

        let data = T::read_from_buffer(&buf).map_err(|_| BrankaError::InvalidData)?;
        Ok(data)
    }

    pub fn encode_deflate_struct<T>(&self, data: &T, compression: Compression) -> String
    where
        T: Writable<speedy::LittleEndian>,
    {
        let buf = data.write_to_vec().unwrap();
        let mut b = flate2::write::DeflateEncoder::new(Vec::new(), compression);
        b.write_all(&buf).unwrap();
        let buf = b.finish().unwrap();

        self.encode_bytes(&buf)
    }

    pub fn decode_deflate_struct<T>(&self, data: &str) -> Result<T, BrankaError>
    where
        T: for<'a> speedy::Readable<'a, speedy::LittleEndian>,
    {
        let decoded = self.decode_bytes(data)?;
        let mut b = flate2::read::DeflateDecoder::new(&decoded[..]);

        let mut buf = Vec::new();
        b.read_to_end(&mut buf).unwrap();

        let data = T::read_from_buffer(&buf).map_err(|_| BrankaError::InvalidData)?;
        Ok(data)
    }
}

#[inline]
fn get_timestamp() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32

    // 0
}

#[cfg(test)]
mod tests {

    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Writable, Readable, Serialize, Deserialize)]
    pub struct SvcTokenV1 {
        pub client_id: i64,
        pub flags: u32,

        pub user: Option<(i64, i32)>,

        #[speedy(length_type = u64_varint)]
        pub perms_i: Vec<u32>,
        #[speedy(length_type = u64_varint)]
        pub perms_s: Vec<PermissionStr>,
    }

    #[derive(Writable, Readable, Serialize, Deserialize)]
    pub struct PermissionStr {
        #[speedy(length_type = u64_varint)]
        pub scope: String,
        pub crud: u8,
    }

    fn load() -> SvcTokenV1 {
        // load json from test_1.json

        let f = std::fs::File::open("test_1.json").unwrap();
        serde_json::from_reader(f).unwrap()
    }

    #[test]
    fn test_encode_decode_with_other_impls() {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        let data = "Hello, world!".to_string();

        let branca1 = Branka::new(&key, 3000);
        let token1 = branca1.encode_struct(&data);
        let data1 = branca1.decode_struct::<String>(&token1).unwrap();
        println!("token1: {} {}", token1.len(), token1);
        assert_eq!(data, data1);

        let token2 = branca1.encode_gz_struct(&data, Compression::default());
        let data2 = branca1.decode_gz_struct::<String>(&token2).unwrap();
        println!("token2: {} {}", token2.len(), token2);
        assert_eq!(data, data2);

        let data = load();
        let token1 = branca1.encode_struct(&data);
        let data1 = branca1.decode_struct::<SvcTokenV1>(&token1).unwrap();
        println!("token1: {} {}", token1.len(), token1);

        let token2 = branca1.encode_gz_struct(&data, Compression::default());
        let data2 = branca1.decode_gz_struct::<SvcTokenV1>(&token2).unwrap();
        println!("token2: {} {}", token2.len(), token2);
    }
}
