use eframe::egui::{self, TextEdit};
use encryption_app::{decrypt_file, encrypt_file, EncryptionAlgorithms};
use rfd::FileDialog;

pub fn file_encryption_ui(app: &mut crate::EncryptionApp, ui: &mut egui::Ui) {
    ui.heading("File Encryption");

    if ui.button("Select File").clicked() {
        if let Some(path) = FileDialog::new().pick_file() {
            app.file_path = Some(path);
            app.status_message.clear();
        }
    }

    if let Some(path) = &app.file_path {
        ui.label(format!("Selected File: {}", path.display()));
    } else {
        ui.label("No file selected.");
    }

    ui.label("Enter Password:");
    ui.add(
        TextEdit::singleline(&mut app.password)
            .password(true)
            .hint_text("Password"),
    );

    ui.separator();
    ui.label("Select Encryption Algorithm:");
    egui::ComboBox::from_label("Algorithm")
        .selected_text(format!("{:?}", app.algorithm))
        .show_ui(ui, |ui| {
            ui.selectable_value(
                &mut app.algorithm,
                EncryptionAlgorithms::Aes256Gcm,
                "AES-256-GCM",
            );
            ui.selectable_value(
                &mut app.algorithm,
                EncryptionAlgorithms::Aes128Gcm,
                "AES-128-GCM",
            );
            ui.selectable_value(
                &mut app.algorithm,
                EncryptionAlgorithms::ChaCha20Poly1305,
                "ChaCha20-Poly1305",
            );
        });

    if ui.button("Encrypt").clicked() {
        if let Some(path) = &app.file_path {
            let algo = match app.algorithm {
                EncryptionAlgorithms::Aes256Gcm => EncryptionAlgorithms::Aes256Gcm,
                EncryptionAlgorithms::Aes128Gcm => EncryptionAlgorithms::Aes128Gcm,
                EncryptionAlgorithms::ChaCha20Poly1305 => EncryptionAlgorithms::ChaCha20Poly1305,
            };

            match encrypt_file(path, &app.password, algo) {
                Ok(_) => {
                    app.status_message = "File encrypted successfully.".to_string();
                    app.file_path = None;
                }
                Err(e) => app.status_message = format!("Encryption failed: {}", e),
            }
        } else {
            app.status_message = "Please select a file.".to_string();
        }
    }

    if ui.button("Decrypt").clicked() {
        if let Some(path) = &app.file_path {
            let algo = match app.algorithm {
                EncryptionAlgorithms::Aes256Gcm => EncryptionAlgorithms::Aes256Gcm,
                EncryptionAlgorithms::Aes128Gcm => EncryptionAlgorithms::Aes128Gcm,
                EncryptionAlgorithms::ChaCha20Poly1305 => EncryptionAlgorithms::ChaCha20Poly1305,
            };

            match decrypt_file(path, &app.password, algo) {
                Ok(_) => {
                    app.status_message = "File decrypted successfully.".to_string();
                    app.file_path = None;
                }
                Err(e) => app.status_message = format!("Decryption failed: {}", e),
            }
        } else {
            app.status_message = "Please select a file.".to_string();
        }
    }

    if !app.status_message.is_empty() {
        ui.separator();
        ui.label(&app.status_message);
    }
}
