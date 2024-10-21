use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES256-GCM cipher
use eframe::egui::{self, TextEdit};
use rand::RngCore;
use rfd::FileDialog;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

fn main() {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Rust Encryption App",
        options,
        Box::new(|_cc| Box::new(EncryptionApp::default())),
    );
}

struct EncryptionApp {
    file_path: Option<PathBuf>,
    password: String,
    status_message: String,
}

impl Default for EncryptionApp {
    fn default() -> Self {
        Self {
            file_path: None,
            password: String::new(),
            status_message: String::new(),
        }
    }
}

impl eframe::App for EncryptionApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Rust Encryption App");

            if ui.button("Select File").clicked() {
                if let Some(path) = FileDialog::new().pick_file() {
                    self.file_path = Some(path);
                    self.status_message.clear();
                }
            }

            if let Some(path) = &self.file_path {
                ui.label(format!("Selected File: {}", path.display()));
            } else {
                ui.label("No file selected.");
            }

            ui.label("Enter Password:");
            ui.add(
                TextEdit::singleline(&mut self.password)
                    .password(true)
                    .hint_text("Password"),
            );

            if ui.button("Encrypt").clicked() {
                if let Some(path) = &self.file_path {
                    match encrypt_file(path, &self.password) {
                        Ok(_) => {
                            self.status_message = "File encrypted successfully.".to_string();
                            self.file_path = None;
                        }
                        Err(e) => self.status_message = format!("Encryption failed: {}", e),
                    }
                } else {
                    self.status_message = "Please select a file.".to_string();
                }
            }

            if ui.button("Decrypt").clicked() {
                if let Some(path) = &self.file_path {
                    match decrypt_file(path, &self.password) {
                        Ok(_) => {
                            self.status_message = "File decrypted successfully.".to_string();
                            self.file_path = None;
                        }
                        Err(e) => self.status_message = format!("Decryption failed: {}", e),
                    }
                } else {
                    self.status_message = "Please select a file.".to_string();
                }
            }

            if !self.status_message.is_empty() {
                ui.separator();
                ui.label(&self.status_message);
            }
        });
    }
}

fn derive_key(password: &str) -> Key<Aes256Gcm> {
    // Hash the password to create a 256-bit key
    let hash = Sha256::digest(password.as_bytes());
    // Clone from slice to get an owned Key<Aes256Gcm>
    Key::<Aes256Gcm>::clone_from_slice(&hash)
}

fn encrypt_file(path: &PathBuf, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(&path)?;

    // Generate a random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let key = derive_key(password);
    let cipher = Aes256Gcm::new(&key);

    // Encrypt data
    let ciphertext = cipher
        .encrypt(nonce, data.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Encryption failed"))?;

    // Write nonce and ciphertext to a new file with .enc extension
    let mut output_data = nonce_bytes.to_vec();
    output_data.extend(ciphertext);

    let mut encrypted_path = path.clone();
    encrypted_path.set_extension("enc");
    fs::write(encrypted_path, output_data)?;

    Ok(())
}

fn decrypt_file(path: &PathBuf, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(&path)?;

    // Split the nonce and ciphertext
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let key = derive_key(password);
    let cipher = Aes256Gcm::new(&key);

    // Decrypt data
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Decryption failed"))?;

    // Write plaintext to a new file with .dec extension
    let mut decrypted_path = path.clone();
    decrypted_path.set_extension("dec");
    fs::write(decrypted_path, plaintext)?;

    Ok(())
}
