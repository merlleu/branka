use byteorder::{BigEndian, ByteOrder};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, AeadCore, AeadInPlace, KeyInit, OsRng},
    Key, XChaCha20Poly1305, XNonce,
};

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

    pub fn encode(&self, data: &[u8]) -> String {
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

    pub fn decode(&self, data: &str) -> Result<Vec<u8>, BrankaError> {
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
            .decrypt_in_place_detached(
                &nonce,
                &buf_crypt[..29],
                &mut buf,
                sign,
            )
            .map_err(|_| BrankaError::InvalidData)?;

        if timestamp > get_timestamp() + self.ttl {
            return Err(BrankaError::Expired);
        }

        
        Ok(buf)
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
    use super::*;

    #[test]
    fn test_encode_decode_with_other_impls() {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        let data = "Hello, world!";

        let branca1 = Branka::new(&key, 3000);
        let token1 = branca1.encode(data.as_bytes());

        let mut branca2 = branca::Branca::new(&key).unwrap();
        let token2 = branca2.encode(data.as_bytes()).unwrap();


        // check if both tokens are valid and can be decoded by both implementations
        let d_1_1 = branca1.decode(&token1).unwrap();
        assert_eq!(d_1_1, data.as_bytes());

        let d_1_2 = branca1.decode(&token2).unwrap();
        assert_eq!(d_1_2, data.as_bytes());

        let d_2_1 = branca2.decode(&token1, 3000).unwrap();
        assert_eq!(d_2_1, data.as_bytes());

        let d_2_1 = branca2.decode(&token2, 3000).unwrap();
        assert_eq!(d_2_1, data.as_bytes());
    }
}
