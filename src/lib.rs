use aes_gcm::aead::{self, Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use argon2::{Argon2, Params};
use chacha20poly1305::ChaCha20Poly1305;
use image::{GenericImageView, ImageFormat};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fmt;
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
/// AES-GCM and ChaCha20-Poly1305 both append a 16-byte authentication tag to the ciphertext.
const TAG_LEN: usize = 16;
const END_MARKER: u8 = 0; // Add end marker

// Enum for encryption algorithms
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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

/// Why an in-memory operation failed. The messages are meant to be shown to a user.
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// The cipher refused to encrypt.
    EncryptionFailed,
    /// Wrong password, wrong algorithm, or the data was changed or damaged.
    DecryptionFailed,
    /// Too short to be something this program encrypted (it has no room for salt, nonce and tag).
    TooShort,
    /// The bytes are not an image the `image` crate can read.
    UnreadableImage(String),
    /// The text does not fit in the image (it needs one pixel per byte plus one for the end marker).
    DataTooLarge { bytes: usize, capacity: usize },
    /// Encoding the result as a PNG failed.
    ImageEncoding(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::EncryptionFailed => write!(f, "the cipher could not encrypt the data"),
            CryptoError::DecryptionFailed => {
                write!(f, "wrong password, wrong algorithm, or the file is damaged")
            }
            CryptoError::TooShort => write!(
                f,
                "this is too short to be an encrypted file: it is missing its salt, nonce or tag"
            ),
            CryptoError::UnreadableImage(reason) => write!(f, "could not read the image: {reason}"),
            CryptoError::DataTooLarge { bytes, capacity } => write!(
                f,
                "the text is too long for this image: {bytes} bytes, room for {capacity}"
            ),
            CryptoError::ImageEncoding(reason) => write!(f, "could not write the image: {reason}"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// The file extension this program gives to data encrypted with `algorithm`.
pub fn encrypted_extension(algorithm: EncryptionAlgorithms) -> &'static str {
    match algorithm {
        EncryptionAlgorithms::Aes256Gcm => "aes256.enc",
        EncryptionAlgorithms::Aes128Gcm => "aes128.enc",
        EncryptionAlgorithms::ChaCha20Poly1305 => "chacha20.enc",
    }
}

/// Encrypts `data` with a key derived from `password`. The result is `[salt][nonce][ciphertext+tag]`.
/// A fresh random salt and nonce are used every time, so the same input never encrypts to the same bytes.
pub fn encrypt_bytes(
    data: &[u8],
    password: &str,
    algorithm: EncryptionAlgorithms,
) -> Result<Vec<u8>, CryptoError> {
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
            <Aes256Gcm as SymmetricCipher>::encrypt(&key_bytes, &nonce_bytes, data)
        }
        EncryptionAlgorithms::Aes128Gcm => {
            <Aes128Gcm as SymmetricCipher>::encrypt(&key_bytes, &nonce_bytes, data)
        }
        EncryptionAlgorithms::ChaCha20Poly1305 => {
            <ChaCha20Poly1305 as SymmetricCipher>::encrypt(&key_bytes, &nonce_bytes, data)
        }
    }
    .map_err(|_| CryptoError::EncryptionFailed)?;

    // Prepare output: [salt][nonce][ciphertext]
    let mut output_data = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    output_data.extend(&salt);
    output_data.extend(&nonce_bytes);
    output_data.extend(ciphertext);
    Ok(output_data)
}

/// Reverses [`encrypt_bytes`]. Fails, never panics, on input that is too short, was encrypted with a
/// different algorithm or password, or has been modified.
pub fn decrypt_bytes(
    data: &[u8],
    password: &str,
    algorithm: EncryptionAlgorithms,
) -> Result<Vec<u8>, CryptoError> {
    if data.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
        return Err(CryptoError::TooShort);
    }

    // Retrieve salt, nonce, and ciphertext
    let salt = &data[..SALT_LEN];
    let nonce_bytes = &data[SALT_LEN..(SALT_LEN + NONCE_LEN)];
    let ciphertext = &data[(SALT_LEN + NONCE_LEN)..];

    let key_len = get_key_length(&algorithm);

    // Derive key
    let key_bytes = derive_key(password, salt, key_len);

    // Decrypt data
    match algorithm {
        EncryptionAlgorithms::Aes256Gcm => {
            <Aes256Gcm as SymmetricCipher>::decrypt(&key_bytes, nonce_bytes, ciphertext)
        }
        EncryptionAlgorithms::Aes128Gcm => {
            <Aes128Gcm as SymmetricCipher>::decrypt(&key_bytes, nonce_bytes, ciphertext)
        }
        EncryptionAlgorithms::ChaCha20Poly1305 => {
            <ChaCha20Poly1305 as SymmetricCipher>::decrypt(&key_bytes, nonce_bytes, ciphertext)
        }
    }
    .map_err(|_| CryptoError::DecryptionFailed)
}

pub fn encrypt_file(
    path: &PathBuf,
    password: &str,
    algorithm: EncryptionAlgorithms,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(path)?;
    let output_data = encrypt_bytes(&data, password, algorithm)?;

    // Write to output file
    let mut encrypted_path = path.clone();
    encrypted_path.set_extension(encrypted_extension(algorithm));
    fs::write(encrypted_path, output_data)?;

    Ok(())
}

pub fn decrypt_file(
    path: &PathBuf,
    password: &str,
    algorithm: EncryptionAlgorithms,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(path)?;
    let plaintext = decrypt_bytes(&data, password, algorithm)?;

    // Write plaintext to a new file with .dec extension
    let mut decrypted_path = path.clone();
    decrypted_path.set_extension("dec");
    fs::write(decrypted_path, plaintext)?;

    Ok(())
}

/// Hides `data` in the red channel of the first pixels of an image and returns the result as PNG bytes.
pub fn hide_data_in_image_bytes(image_bytes: &[u8], data: &str) -> Result<Vec<u8>, CryptoError> {
    let img = image::load_from_memory(image_bytes)
        .map_err(|e| CryptoError::UnreadableImage(e.to_string()))?;

    let data_bytes = data.as_bytes();
    let (width, height) = img.dimensions();
    let capacity = (width as usize * height as usize).saturating_sub(1);
    // One pixel per byte, plus one for the end marker. Before this check, longer text was silently cut off.
    if data_bytes.len() > capacity {
        return Err(CryptoError::DataTooLarge {
            bytes: data_bytes.len(),
            capacity,
        });
    }

    let mut data_index = 0;
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

    let mut png = Vec::new();
    img_buffer
        .write_to(&mut Cursor::new(&mut png), ImageFormat::Png)
        .map_err(|e| CryptoError::ImageEncoding(e.to_string()))?;
    Ok(png)
}

/// Reads back what [`hide_data_in_image_bytes`] hid.
pub fn extract_data_from_image_bytes(image_bytes: &[u8]) -> Result<String, CryptoError> {
    let img = image::load_from_memory(image_bytes)
        .map_err(|e| CryptoError::UnreadableImage(e.to_string()))?;

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

    Ok(String::from_utf8_lossy(&data_bytes).to_string())
}

/// Runs the cryptography on built-in samples and reports whether it behaves. The About tab offers
/// it so anyone can check, in their own browser, that the code works there too.
pub fn self_test() -> Result<String, String> {
    let sample = b"The quick brown fox jumps over the lazy dog";
    let algorithms = [
        (EncryptionAlgorithms::Aes256Gcm, "AES-256-GCM"),
        (EncryptionAlgorithms::Aes128Gcm, "AES-128-GCM"),
        (EncryptionAlgorithms::ChaCha20Poly1305, "ChaCha20-Poly1305"),
    ];

    for (algorithm, name) in algorithms {
        let encrypted = encrypt_bytes(sample, "self-test password", algorithm)
            .map_err(|e| format!("{name} encryption: {e}"))?;
        let decrypted = decrypt_bytes(&encrypted, "self-test password", algorithm)
            .map_err(|e| format!("{name} decryption: {e}"))?;
        if decrypted != sample {
            return Err(format!(
                "{name}: the decrypted text differs from the original"
            ));
        }
        if decrypt_bytes(&encrypted, "another password", algorithm).is_ok() {
            return Err(format!("{name}: a wrong password was accepted"));
        }
        let mut damaged = encrypted;
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        if decrypt_bytes(&damaged, "self-test password", algorithm).is_ok() {
            return Err(format!("{name}: a modified file was accepted"));
        }
    }

    let mut picture = Vec::new();
    image::RgbaImage::from_pixel(16, 16, image::Rgba([90, 120, 150, 255]))
        .write_to(&mut Cursor::new(&mut picture), ImageFormat::Png)
        .map_err(|e| format!("image: {e}"))?;
    let hidden = hide_data_in_image_bytes(&picture, "self-test")
        .map_err(|e| format!("image hiding: {e}"))?;
    let revealed =
        extract_data_from_image_bytes(&hidden).map_err(|e| format!("image reading: {e}"))?;
    if revealed != "self-test" {
        return Err("image: the hidden text did not come back".to_string());
    }

    Ok("Self-test passed: all three ciphers encrypt, decrypt, refuse a wrong password and detect tampering; hiding text in an image and reading it back works.".to_string())
}

pub fn hide_data_in_image(path: &PathBuf, data: &str) -> Result<(), Box<dyn std::error::Error>> {
    let png = hide_data_in_image_bytes(&fs::read(path)?, data)?;

    let mut output_path = path.clone();
    output_path.set_extension("hidden.png");
    fs::write(output_path, png)?;

    Ok(())
}

pub fn extract_data_from_image(path: &PathBuf) -> Result<String, Box<dyn std::error::Error>> {
    Ok(extract_data_from_image_bytes(&fs::read(path)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [EncryptionAlgorithms; 3] = [
        EncryptionAlgorithms::Aes256Gcm,
        EncryptionAlgorithms::Aes128Gcm,
        EncryptionAlgorithms::ChaCha20Poly1305,
    ];

    /// A PNG of the given size, every pixel the same colour.
    fn png(width: u32, height: u32) -> Vec<u8> {
        let mut out = Vec::new();
        image::RgbaImage::from_pixel(width, height, image::Rgba([200, 100, 50, 255]))
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("encryption_app_{}_{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn every_algorithm_round_trips() {
        for algorithm in ALL {
            let secret = b"attack at dawn";
            let encrypted = encrypt_bytes(secret, "correct horse", algorithm).unwrap();
            assert_eq!(
                decrypt_bytes(&encrypted, "correct horse", algorithm).unwrap(),
                secret
            );
        }
    }

    #[test]
    fn empty_and_binary_data_round_trip() {
        let binary: Vec<u8> = (0..=255).collect();
        for data in [Vec::new(), vec![0u8], binary] {
            let encrypted = encrypt_bytes(&data, "pw", EncryptionAlgorithms::Aes256Gcm).unwrap();
            assert_eq!(
                decrypt_bytes(&encrypted, "pw", EncryptionAlgorithms::Aes256Gcm).unwrap(),
                data
            );
        }
    }

    #[test]
    fn output_is_salt_nonce_ciphertext_and_tag() {
        let encrypted =
            encrypt_bytes(&[7u8; 100], "pw", EncryptionAlgorithms::ChaCha20Poly1305).unwrap();
        assert_eq!(encrypted.len(), SALT_LEN + NONCE_LEN + 100 + TAG_LEN);
    }

    #[test]
    fn the_same_input_never_encrypts_to_the_same_bytes() {
        let a = encrypt_bytes(b"same", "pw", EncryptionAlgorithms::Aes256Gcm).unwrap();
        let b = encrypt_bytes(b"same", "pw", EncryptionAlgorithms::Aes256Gcm).unwrap();
        assert_ne!(a, b);
        assert_ne!(
            a[..SALT_LEN],
            b[..SALT_LEN],
            "the salt must be fresh each time"
        );
    }

    #[test]
    fn a_wrong_password_is_refused() {
        let encrypted = encrypt_bytes(b"secret", "right", EncryptionAlgorithms::Aes256Gcm).unwrap();
        assert_eq!(
            decrypt_bytes(&encrypted, "wrong", EncryptionAlgorithms::Aes256Gcm),
            Err(CryptoError::DecryptionFailed)
        );
    }

    #[test]
    fn a_wrong_algorithm_is_refused() {
        let encrypted = encrypt_bytes(b"secret", "pw", EncryptionAlgorithms::Aes256Gcm).unwrap();
        for other in [
            EncryptionAlgorithms::Aes128Gcm,
            EncryptionAlgorithms::ChaCha20Poly1305,
        ] {
            assert_eq!(
                decrypt_bytes(&encrypted, "pw", other),
                Err(CryptoError::DecryptionFailed)
            );
        }
    }

    #[test]
    fn changing_any_byte_is_detected() {
        let encrypted =
            encrypt_bytes(b"do not tamper", "pw", EncryptionAlgorithms::Aes256Gcm).unwrap();
        for position in [0, SALT_LEN, SALT_LEN + NONCE_LEN, encrypted.len() - 1] {
            let mut damaged = encrypted.clone();
            damaged[position] ^= 0x01;
            assert_eq!(
                decrypt_bytes(&damaged, "pw", EncryptionAlgorithms::Aes256Gcm),
                Err(CryptoError::DecryptionFailed),
                "a change at byte {position} went unnoticed"
            );
        }
    }

    #[test]
    fn input_too_short_to_be_ours_fails_instead_of_panicking() {
        // The old code sliced the input unchecked, which panics, and a panic kills the web app.
        for length in [
            0,
            1,
            SALT_LEN,
            SALT_LEN + NONCE_LEN,
            SALT_LEN + NONCE_LEN + TAG_LEN - 1,
        ] {
            assert_eq!(
                decrypt_bytes(&vec![0u8; length], "pw", EncryptionAlgorithms::Aes256Gcm),
                Err(CryptoError::TooShort),
                "length {length}"
            );
        }
    }

    #[test]
    fn exactly_salt_nonce_and_tag_is_the_shortest_valid_size() {
        let encrypted = encrypt_bytes(b"", "pw", EncryptionAlgorithms::Aes256Gcm).unwrap();
        assert_eq!(encrypted.len(), SALT_LEN + NONCE_LEN + TAG_LEN);
        assert_eq!(
            decrypt_bytes(&encrypted, "pw", EncryptionAlgorithms::Aes256Gcm).unwrap(),
            b""
        );
    }

    #[test]
    fn extensions_match_the_algorithm() {
        assert_eq!(
            encrypted_extension(EncryptionAlgorithms::Aes256Gcm),
            "aes256.enc"
        );
        assert_eq!(
            encrypted_extension(EncryptionAlgorithms::Aes128Gcm),
            "aes128.enc"
        );
        assert_eq!(
            encrypted_extension(EncryptionAlgorithms::ChaCha20Poly1305),
            "chacha20.enc"
        );
    }

    #[test]
    fn hidden_text_comes_back_out_of_an_image() {
        let hidden = hide_data_in_image_bytes(&png(32, 32), "meet me at noon").unwrap();
        assert_eq!(
            extract_data_from_image_bytes(&hidden).unwrap(),
            "meet me at noon"
        );
    }

    #[test]
    fn empty_text_hides_and_extracts_as_empty() {
        let hidden = hide_data_in_image_bytes(&png(4, 4), "").unwrap();
        assert_eq!(extract_data_from_image_bytes(&hidden).unwrap(), "");
    }

    #[test]
    fn text_exactly_filling_the_image_is_accepted_and_one_more_byte_is_not() {
        let image = png(4, 4); // 16 pixels: 15 bytes of text plus the end marker
        let fits = "a".repeat(15);
        let hidden = hide_data_in_image_bytes(&image, &fits).unwrap();
        assert_eq!(extract_data_from_image_bytes(&hidden).unwrap(), fits);
        assert_eq!(
            hide_data_in_image_bytes(&image, &"a".repeat(16)),
            Err(CryptoError::DataTooLarge {
                bytes: 16,
                capacity: 15
            })
        );
    }

    #[test]
    fn something_that_is_not_an_image_is_refused() {
        assert!(matches!(
            hide_data_in_image_bytes(b"definitely not a picture", "x"),
            Err(CryptoError::UnreadableImage(_))
        ));
        assert!(matches!(
            extract_data_from_image_bytes(&[]),
            Err(CryptoError::UnreadableImage(_))
        ));
    }

    #[test]
    fn the_file_functions_still_work_end_to_end() {
        let dir = scratch_dir("files");
        let original = dir.join("note.txt");
        fs::write(&original, b"on disk").unwrap();

        encrypt_file(&original, "pw", EncryptionAlgorithms::Aes256Gcm).unwrap();
        let encrypted = dir.join("note.aes256.enc");
        assert!(encrypted.exists());

        decrypt_file(&encrypted, "pw", EncryptionAlgorithms::Aes256Gcm).unwrap();
        assert_eq!(fs::read(dir.join("note.aes256.dec")).unwrap(), b"on disk");

        let picture = dir.join("pic.png");
        fs::write(&picture, png(16, 16)).unwrap();
        hide_data_in_image(&picture, "via files").unwrap();
        assert_eq!(
            extract_data_from_image(&dir.join("pic.hidden.png")).unwrap(),
            "via files"
        );

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_self_test_passes() {
        assert!(self_test().unwrap().starts_with("Self-test passed"));
    }

    #[test]
    fn the_file_functions_report_a_missing_file() {
        let missing = PathBuf::from("/definitely/not/here.txt");
        assert!(encrypt_file(&missing, "pw", EncryptionAlgorithms::Aes256Gcm).is_err());
        assert!(decrypt_file(&missing, "pw", EncryptionAlgorithms::Aes256Gcm).is_err());
    }
}
