use eframe::egui::{self, CentralPanel, RichText, ScrollArea, TextEdit, TopBottomPanel}; // Remove TabBar and TabButton
use encryption_app::{
    decrypt_file, encrypt_file, extract_data_from_image, hide_data_in_image, EncryptionAlgorithms,
}; // Add extract_data_from_image
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
    image_path: Option<PathBuf>, // Add image_path
    hidden_data: String,         // Add hidden_data
    extracted_data: String,      // Add extracted_data
    selected_tab: String,        // Add selected_tab
}

impl Default for EncryptionApp {
    fn default() -> Self {
        Self {
            file_path: None,
            password: String::new(),
            status_message: String::new(),
            algorithm: EncryptionAlgorithms::default(),
            image_path: None,                            // Add image_path
            hidden_data: String::new(),                  // Add hidden_data
            extracted_data: String::new(),               // Add extracted_data
            selected_tab: "File Encryption".to_string(), // Add selected_tab
        }
    }
}

impl eframe::App for EncryptionApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        use encryption_app::EncryptionAlgorithms;

        TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui
                    .selectable_label(self.selected_tab == "File Encryption", "File Encryption")
                    .clicked()
                {
                    self.selected_tab = "File Encryption".to_string();
                }
                if ui
                    .selectable_label(
                        self.selected_tab == "Image Hidden Data",
                        "Image Hidden Data",
                    )
                    .clicked()
                {
                    self.selected_tab = "Image Hidden Data".to_string();
                }
            });
        });

        CentralPanel::default().show(ctx, |ui| {
            ScrollArea::vertical().show(ui, |ui| {
                match self.selected_tab.as_str() {
                    "File Encryption" => {
                        ui.heading("File Encryption");

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
                                    EncryptionAlgorithms::Aes256Gcm => {
                                        EncryptionAlgorithms::Aes256Gcm
                                    }
                                    EncryptionAlgorithms::Aes128Gcm => {
                                        EncryptionAlgorithms::Aes128Gcm
                                    }
                                    EncryptionAlgorithms::ChaCha20Poly1305 => {
                                        EncryptionAlgorithms::ChaCha20Poly1305
                                    }
                                };

                                match encrypt_file(path, &self.password, algo) {
                                    Ok(_) => {
                                        self.status_message =
                                            "File encrypted successfully.".to_string();
                                        self.file_path = None;
                                    }
                                    Err(e) => {
                                        self.status_message = format!("Encryption failed: {}", e)
                                    }
                                }
                            } else {
                                self.status_message = "Please select a file.".to_string();
                            }
                        }

                        if ui.button("Decrypt").clicked() {
                            if let Some(path) = &self.file_path {
                                let algo = match self.algorithm {
                                    EncryptionAlgorithms::Aes256Gcm => {
                                        EncryptionAlgorithms::Aes256Gcm
                                    }
                                    EncryptionAlgorithms::Aes128Gcm => {
                                        EncryptionAlgorithms::Aes128Gcm
                                    }
                                    EncryptionAlgorithms::ChaCha20Poly1305 => {
                                        EncryptionAlgorithms::ChaCha20Poly1305
                                    }
                                };

                                match decrypt_file(path, &self.password, algo) {
                                    Ok(_) => {
                                        self.status_message =
                                            "File decrypted successfully.".to_string();
                                        self.file_path = None;
                                    }
                                    Err(e) => {
                                        self.status_message = format!("Decryption failed: {}", e)
                                    }
                                }
                            } else {
                                self.status_message = "Please select a file.".to_string();
                            }
                        }

                        if !self.status_message.is_empty() {
                            ui.separator();
                            ui.label(&self.status_message);
                        }
                    }
                    "Image Hidden Data" => {
                        ui.heading("Image Hidden Data");

                        if ui.button("Select Image").clicked() {
                            if let Some(path) = FileDialog::new().pick_file() {
                                self.image_path = Some(path);
                                self.status_message.clear();
                            }
                        }

                        if let Some(path) = &self.image_path {
                            ui.label(format!("Selected Image: {}", path.display()));
                        } else {
                            ui.label("No image selected.");
                        }

                        ui.label("Enter Data to Hide:");
                        ui.add(TextEdit::multiline(&mut self.hidden_data).hint_text("Data"));

                        if ui.button("Hide Data").clicked() {
                            if let Some(path) = &self.image_path {
                                match hide_data_in_image(path, &self.hidden_data) {
                                    Ok(_) => {
                                        self.status_message =
                                            "Data hidden in image successfully.".to_string();
                                        self.image_path = None;
                                    }
                                    Err(e) => {
                                        self.status_message = format!("Failed to hide data: {}", e)
                                    }
                                }
                            } else {
                                self.status_message = "Please select an image.".to_string();
                            }
                        }

                        ui.separator();
                        ui.heading("Extract Data from Image");

                        if ui.button("Select Image").clicked() {
                            if let Some(path) = FileDialog::new().pick_file() {
                                self.image_path = Some(path);
                                self.status_message.clear();
                            }
                        }

                        if let Some(path) = &self.image_path {
                            ui.label(format!("Selected Image: {}", path.display()));
                        } else {
                            ui.label("No image selected.");
                        }

                        if ui.button("Extract Data").clicked() {
                            if let Some(path) = &self.image_path {
                                match extract_data_from_image(path) {
                                    Ok(data) => {
                                        self.extracted_data = data;
                                        self.status_message =
                                            "Data extracted successfully.".to_string();
                                        self.image_path = None;
                                    }
                                    Err(e) => {
                                        self.status_message =
                                            format!("Failed to extract data: {}", e)
                                    }
                                }
                            } else {
                                self.status_message = "Please select an image.".to_string();
                            }
                        }

                        ui.label("Extracted Data:");
                        ui.add(
                            TextEdit::multiline(&mut self.extracted_data)
                                .hint_text("Extracted Data")
                                .interactive(false),
                        );

                        if !self.status_message.is_empty() {
                            ui.separator();
                            ui.label(RichText::new(&self.status_message).color(egui::Color32::RED));
                        }
                    }
                    _ => {}
                }

                // Add a separator before the "Close Program" button
                ui.separator();

                // Add the "Close Program" button
                if ui.button("Close Program").clicked() {
                    std::process::exit(0);
                }
            });
        });
    }
}
