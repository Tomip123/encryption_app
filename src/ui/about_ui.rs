use crate::app::EncryptionApp;
use eframe::egui;

pub fn about_ui(app: &mut EncryptionApp, ui: &mut egui::Ui) {
    ui.heading("About");
    ui.label(
        "Encrypts files with AES-256-GCM, AES-128-GCM or ChaCha20-Poly1305, using a key derived from \
         your password with Argon2id, and hides short text inside PNG images.",
    );

    #[cfg(target_arch = "wasm32")]
    ui.label(
        "This copy runs entirely inside your browser as WebAssembly. The program contains no \
         networking code, so your files and passwords never leave your device.",
    );

    ui.separator();
    ui.label("Check that the cryptography works here, on built-in sample data:");
    if ui.button("Run self-test").clicked() {
        app.status_message = match encryption_app::self_test() {
            Ok(message) => message,
            Err(reason) => format!("Self-test FAILED: {reason}"),
        };
    }

    if !app.status_message.is_empty() {
        ui.separator();
        ui.label(&app.status_message);
    }
}
