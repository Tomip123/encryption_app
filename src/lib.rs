use aes_gcm::aead::{self, Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use argon2::{Argon2, Params};
use chacha20poly1305::ChaCha20Poly1305;
use image::GenericImageView;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::path::PathBuf; // Remove Cursor

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const END_MARKER: u8 = 0; // Add end marker

// Enum for encryption algorithms
#[derive(Debug, PartialEq)]
pub enum EncryptionAlgorithms {
    Aes256Gcm,
    Aes128Gcm,
    ChaCha20Poly1305,
}

impl Default for EncryptionAlgorithms {
    fn default() -> Self {
        EncryptionAlgorithms::Aes256Gcm
    }
}

pub trait SymmetricCipher {
    fn key_length() -> usize;
    fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, aead::Error>;
    fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, aead::Error>;
}

impl SymmetricCipher for Aes256Gcm {
    fn key_length() -> usize {
        32 // 256 bits
    }

    fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, aead::Error> {
        let key = aead::generic_array::GenericArray::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let nonce = aead::generic_array::GenericArray::from_slice(nonce);
        cipher.encrypt(nonce, plaintext)
    }

    fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, aead::Error> {
        let key = aead::generic_array::GenericArray::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let nonce = aead::generic_array::GenericArray::from_slice(nonce);
        cipher.decrypt(nonce, ciphertext)
    }
}

impl SymmetricCipher for Aes128Gcm {
    fn key_length() -> usize {
        16 // 128 bits
    }

    fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, aead::Error> {
        let key = aead::generic_array::GenericArray::from_slice(key);
        let cipher = Aes128Gcm::new(key);
        let nonce = aead::generic_array::GenericArray::from_slice(nonce);
        cipher.encrypt(nonce, plaintext)
    }

    fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, aead::Error> {
        let key = aead::generic_array::GenericArray::from_slice(key);
        let cipher = Aes128Gcm::new(key);
        let nonce = aead::generic_array::GenericArray::from_slice(nonce);
        cipher.decrypt(nonce, ciphertext)
    }
}

impl SymmetricCipher for ChaCha20Poly1305 {
    fn key_length() -> usize {
        32 // 256 bits
    }

    fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, aead::Error> {
        let key = aead::generic_array::GenericArray::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = aead::generic_array::GenericArray::from_slice(nonce);
        cipher.encrypt(nonce, plaintext)
    }

    fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, aead::Error> {
        let key = aead::generic_array::GenericArray::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = aead::generic_array::GenericArray::from_slice(nonce);
        cipher.decrypt(nonce, ciphertext)
    }
}

pub fn derive_key(password: &str, salt: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = vec![0u8; key_len];

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        Params::new(
            15000, // Iterations
            2,     // Memory size (in KB)
            1,     // Parallelism (threads)
            Some(key_len),
        )
        .unwrap(),
    );

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Failed to derive key with Argon2");

    key
}

fn get_key_length(algorithm: &EncryptionAlgorithms) -> usize {
    match algorithm {
        EncryptionAlgorithms::Aes256Gcm => Aes256Gcm::key_length(),
        EncryptionAlgorithms::Aes128Gcm => Aes128Gcm::key_length(),
        EncryptionAlgorithms::ChaCha20Poly1305 => ChaCha20Poly1305::key_length(),
    }
}

pub fn encrypt_file(
    path: &PathBuf,
    password: &str,
    algorithm: EncryptionAlgorithms,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(&path)?;

    // Generate random salt and nonce
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let key_len = get_key_length(&algorithm);

    // Derive key
    let key_bytes = derive_key(password, &salt, key_len);

    // Encrypt data
    let ciphertext = match algorithm {
        EncryptionAlgorithms::Aes256Gcm => {
            <Aes256Gcm as SymmetricCipher>::encrypt(&key_bytes, &nonce_bytes, &data)
        }
        EncryptionAlgorithms::Aes128Gcm => {
            <Aes128Gcm as SymmetricCipher>::encrypt(&key_bytes, &nonce_bytes, &data)
        }
        EncryptionAlgorithms::ChaCha20Poly1305 => {
            <ChaCha20Poly1305 as SymmetricCipher>::encrypt(&key_bytes, &nonce_bytes, &data)
        }
    }
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Encryption failed"))?;

    // Prepare output: [salt][nonce][ciphertext]
    let mut output_data = Vec::new();
    output_data.extend(&salt);
    output_data.extend(&nonce_bytes);
    output_data.extend(ciphertext);

    // Write to output file
    let mut encrypted_path = path.clone();
    match algorithm {
        EncryptionAlgorithms::Aes256Gcm => encrypted_path.set_extension("aes256.enc"),
        EncryptionAlgorithms::Aes128Gcm => encrypted_path.set_extension("aes128.enc"),
        EncryptionAlgorithms::ChaCha20Poly1305 => encrypted_path.set_extension("chacha20.enc"),
    };
    fs::write(encrypted_path, output_data)?;

    Ok(())
}

pub fn decrypt_file(
    path: &PathBuf,
    password: &str,
    algorithm: EncryptionAlgorithms,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(&path)?;

    // Retrieve salt, nonce, and ciphertext
    let salt = &data[..SALT_LEN];
    let nonce_bytes = &data[SALT_LEN..(SALT_LEN + NONCE_LEN)];
    let ciphertext = &data[(SALT_LEN + NONCE_LEN)..];

    let key_len = get_key_length(&algorithm);

    // Derive key
    let key_bytes = derive_key(password, salt, key_len);

    // Decrypt data
    let plaintext = match algorithm {
        EncryptionAlgorithms::Aes256Gcm => {
            <Aes256Gcm as SymmetricCipher>::decrypt(&key_bytes, &nonce_bytes, ciphertext)
        }
        EncryptionAlgorithms::Aes128Gcm => {
            <Aes128Gcm as SymmetricCipher>::decrypt(&key_bytes, &nonce_bytes, ciphertext)
        }
        EncryptionAlgorithms::ChaCha20Poly1305 => {
            <ChaCha20Poly1305 as SymmetricCipher>::decrypt(&key_bytes, &nonce_bytes, ciphertext)
        }
    }
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            "Decryption failed: Invalid password or corrupted file",
        )
    })?;

    // Write plaintext to a new file with .dec extension
    let mut decrypted_path = path.clone();
    decrypted_path.set_extension("dec");
    fs::write(decrypted_path, plaintext)?;

    Ok(())
}

pub fn hide_data_in_image(path: &PathBuf, data: &str) -> Result<(), Box<dyn std::error::Error>> {
    let img = image::open(path)?;

    let data_bytes = data.as_bytes();
    let mut data_index = 0;

    let (width, height) = img.dimensions();
    let mut img_buffer = img.to_rgba8();

    'outer: for y in 0..height {
        for x in 0..width {
            if data_index < data_bytes.len() {
                let byte = data_bytes[data_index];
                let pixel = img_buffer.get_pixel_mut(x, y);
                pixel[0] = byte;
                data_index += 1;
            } else {
                let pixel = img_buffer.get_pixel_mut(x, y);
                pixel[0] = END_MARKER; // Add end marker
                break 'outer;
            }
        }
    }

    let mut output_path = path.clone();
    output_path.set_extension("hidden.png");
    img_buffer.save(output_path)?;

    Ok(())
}

pub fn extract_data_from_image(path: &PathBuf) -> Result<String, Box<dyn std::error::Error>> {
    let img = image::open(path)?;

    let mut data_bytes = Vec::new();

    let (width, height) = img.dimensions();
    let img_buffer = img.to_rgba8();

    'outer: for y in 0..height {
        for x in 0..width {
            let pixel = img_buffer.get_pixel(x, y);
            if pixel[0] != END_MARKER {
                data_bytes.push(pixel[0]);
            } else {
                break 'outer;
            }
        }
    }

    let data = String::from_utf8_lossy(&data_bytes).to_string();
    Ok(data)
}
