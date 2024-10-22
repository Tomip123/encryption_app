use encryption_app::{decrypt_file, encrypt_file, EncryptionAlgorithms};
use std::env;
use std::error::Error;
use std::path::PathBuf; // Import from lib.rs

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 5 {
        eprintln!(
            "Usage: {} <encrypt|decrypt> <algorithm> <file> <password>",
            args[0]
        );
        eprintln!("Algorithms: aes256gcm, aes128gcm, chacha20poly1305");
        std::process::exit(1);
    }

    let command = &args[1];
    let algorithm = &args[2];
    let file_path = PathBuf::from(&args[3]);
    let password = &args[4];

    let algorithm = match algorithm.to_lowercase().as_str() {
        "aes256gcm" => EncryptionAlgorithms::Aes256Gcm,
        "aes128gcm" => EncryptionAlgorithms::Aes128Gcm,
        "chacha20poly1305" => EncryptionAlgorithms::ChaCha20Poly1305,
        _ => {
            eprintln!("Unknown algorithm: {}", algorithm);
            eprintln!("Supported algorithms: aes256gcm, aes128gcm, chacha20poly1305");
            std::process::exit(1);
        }
    };

    match command.as_str() {
        "encrypt" => {
            encrypt_file(&file_path, password, algorithm)?;
            println!("File encrypted successfully.");
        }
        "decrypt" => {
            decrypt_file(&file_path, password, algorithm)?;
            println!("File decrypted successfully.");
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            eprintln!(
                "Usage: {} <encrypt|decrypt> <algorithm> <file> <password>",
                args[0]
            );
            std::process::exit(1);
        }
    }

    Ok(())
}
