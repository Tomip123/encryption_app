use eframe::egui::{self, TextEdit};
use encryption_app::{decrypt_file, encrypt_file, EncryptionAlgorithms};
use rfd::FileDialog;
use std::path::PathBuf; // Import from lib.rs

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Rust Encryption App",
        options,
        Box::new(|_cc| Ok(Box::new(EncryptionApp::default()))),
    )
}

struct EncryptionApp {
    file_path: Option<PathBuf>,
    password: String,
    status_message: String,
    algorithm: EncryptionAlgorithms,
}

impl Default for EncryptionApp {
    fn default() -> Self {
        Self {
            file_path: None,
            password: String::new(),
            status_message: String::new(),
            algorithm: EncryptionAlgorithms::default(),
        }
    }
}

impl eframe::App for EncryptionApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        use encryption_app::EncryptionAlgorithms;

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

            ui.separator();
            ui.label("Select Encryption Algorithm:");
            egui::ComboBox::from_label("Algorithm")
                .selected_text(format!("{:?}", self.algorithm))
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.algorithm,
                        EncryptionAlgorithms::Aes256Gcm,
                        "AES-256-GCM",
                    );
                    ui.selectable_value(
                        &mut self.algorithm,
                        EncryptionAlgorithms::Aes128Gcm,
                        "AES-128-GCM",
                    );
                    ui.selectable_value(
                        &mut self.algorithm,
                        EncryptionAlgorithms::ChaCha20Poly1305,
                        "ChaCha20-Poly1305",
                    );
                });

            if ui.button("Encrypt").clicked() {
                if let Some(path) = &self.file_path {
                    let algo = match self.algorithm {
                        EncryptionAlgorithms::Aes256Gcm => EncryptionAlgorithms::Aes256Gcm,
                        EncryptionAlgorithms::Aes128Gcm => EncryptionAlgorithms::Aes128Gcm,
                        EncryptionAlgorithms::ChaCha20Poly1305 => {
                            EncryptionAlgorithms::ChaCha20Poly1305
                        }
                    };

                    match encrypt_file(path, &self.password, algo) {
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
                    let algo = match self.algorithm {
                        EncryptionAlgorithms::Aes256Gcm => EncryptionAlgorithms::Aes256Gcm,
                        EncryptionAlgorithms::Aes128Gcm => EncryptionAlgorithms::Aes128Gcm,
                        EncryptionAlgorithms::ChaCha20Poly1305 => {
                            EncryptionAlgorithms::ChaCha20Poly1305
                        }
                    };

                    match decrypt_file(path, &self.password, algo) {
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

            // Add a separator before the "Close Program" button
            ui.separator();

            // Add the "Close Program" button
            if ui.button("Close Program").clicked() {
                std::process::exit(0);
            }
        });
    }
}
