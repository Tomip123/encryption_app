use crate::app::{EncryptionApp, PickTarget};
use crate::files::{self, PickedFile, SharedInbox};
use eframe::egui::{self, TextEdit};
use encryption_app::EncryptionAlgorithms;

type Operation =
    fn(&PickedFile, &str, EncryptionAlgorithms, &SharedInbox) -> Result<String, String>;

/// Runs `operation` on the selected file and reports the outcome in the status line.
fn run(app: &mut EncryptionApp, operation: Operation, failure: &str) {
    let Some(file) = &app.file else {
        app.status_message = "Please select a file.".to_string();
        return;
    };
    match operation(file, &app.password, app.algorithm, &app.inbox) {
        Ok(message) => {
            app.status_message = message;
            app.file = None;
        }
        Err(e) => app.status_message = format!("{failure}: {e}"),
    }
}

pub fn file_encryption_ui(app: &mut EncryptionApp, ui: &mut egui::Ui) {
    ui.heading("File Encryption");

    if ui.button("Select File").clicked() {
        app.pick_target = PickTarget::File;
        files::pick_file(&app.inbox, ui.ctx());
    }

    match &app.file {
        Some(file) => ui.label(format!("Selected File: {}", file.name)),
        None => ui.label("No file selected."),
    };

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
        run(app, files::encrypt, "Encryption failed");
    }

    if ui.button("Decrypt").clicked() {
        run(app, files::decrypt, "Decryption failed");
    }

    if !app.status_message.is_empty() {
        ui.separator();
        ui.label(&app.status_message);
    }
}
