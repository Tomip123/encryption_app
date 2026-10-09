//! The only place where the desktop app and the browser build differ: how a file is chosen, and
//! where a result goes. Everything else in the program is shared.
//!
//! Desktop: a native dialog picks a path, and results are written next to the original file, as
//! the CLI does. Browser: there is no disk, so the picked file is read into memory and a result
//! is offered to the visitor as a download. Nothing is ever sent anywhere.

use eframe::egui;
use encryption_app::EncryptionAlgorithms;
use std::sync::{Arc, Mutex};

/// A file the user chose.
pub struct PickedFile {
    pub name: String,
    /// Desktop: where it is on disk. Operations read it and write results beside it.
    #[cfg(not(target_arch = "wasm32"))]
    pub path: std::path::PathBuf,
    /// Browser: the contents, read when the file was picked.
    #[cfg(target_arch = "wasm32")]
    pub bytes: Vec<u8>,
}

/// What a background task (the browser's file picker and downloads are asynchronous) hands back
/// to the interface. The interface drains it once per frame.
#[derive(Default)]
pub struct Inbox {
    pub picked: Mutex<Option<PickedFile>>,
    pub notice: Mutex<Option<String>>,
}

pub type SharedInbox = Arc<Inbox>;

/// Name of the output when decrypting `name` in the browser: the encrypted-file suffix is removed,
/// so `photo.jpg.aes256.enc` becomes `photo.jpg`. Anything else gets `.dec` appended.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub fn decrypted_name(name: &str) -> String {
    for algorithm in [
        EncryptionAlgorithms::Aes256Gcm,
        EncryptionAlgorithms::Aes128Gcm,
        EncryptionAlgorithms::ChaCha20Poly1305,
    ] {
        let suffix = format!(".{}", encryption_app::encrypted_extension(algorithm));
        if let Some(stem) = name.strip_suffix(&suffix) {
            if !stem.is_empty() {
                return stem.to_string();
            }
        }
    }
    format!("{name}.dec")
}

/// Name of the output when hiding text in the image called `name`: `holiday.jpg` becomes `holiday.hidden.png`.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub fn hidden_image_name(name: &str) -> String {
    let stem = match name.rfind('.') {
        Some(dot) if dot > 0 => &name[..dot],
        _ => name,
    };
    format!("{stem}.hidden.png")
}

#[cfg(not(target_arch = "wasm32"))]
mod platform {
    use super::*;
    use encryption_app::{decrypt_file, encrypt_file, extract_data_from_image, hide_data_in_image};

    pub fn pick_file(inbox: &SharedInbox, ctx: &egui::Context) {
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.display().to_string());
            *inbox.picked.lock().unwrap() = Some(PickedFile { name, path });
            ctx.request_repaint();
        }
    }

    pub fn encrypt(
        file: &PickedFile,
        password: &str,
        algorithm: EncryptionAlgorithms,
        _inbox: &SharedInbox,
    ) -> Result<String, String> {
        encrypt_file(&file.path, password, algorithm).map_err(|e| e.to_string())?;
        Ok("File encrypted successfully.".to_string())
    }

    pub fn decrypt(
        file: &PickedFile,
        password: &str,
        algorithm: EncryptionAlgorithms,
        _inbox: &SharedInbox,
    ) -> Result<String, String> {
        decrypt_file(&file.path, password, algorithm).map_err(|e| e.to_string())?;
        Ok("File decrypted successfully.".to_string())
    }

    pub fn hide_data(
        file: &PickedFile,
        data: &str,
        _inbox: &SharedInbox,
    ) -> Result<String, String> {
        hide_data_in_image(&file.path, data).map_err(|e| e.to_string())?;
        Ok("Data hidden in image successfully.".to_string())
    }

    pub fn extract_data(file: &PickedFile) -> Result<String, String> {
        extract_data_from_image(&file.path).map_err(|e| e.to_string())
    }
}

#[cfg(target_arch = "wasm32")]
mod platform {
    use super::*;
    use encryption_app::{
        decrypt_bytes, encrypt_bytes, encrypted_extension, extract_data_from_image_bytes,
        hide_data_in_image_bytes,
    };

    pub fn pick_file(inbox: &SharedInbox, ctx: &egui::Context) {
        let (inbox, ctx) = (inbox.clone(), ctx.clone());
        wasm_bindgen_futures::spawn_local(async move {
            if let Some(handle) = rfd::AsyncFileDialog::new().pick_file().await {
                let bytes = handle.read().await;
                let name = handle.file_name();
                *inbox.picked.lock().unwrap() = Some(PickedFile { name, bytes });
                ctx.request_repaint();
            }
        });
    }

    /// Offers `bytes` to the visitor as a download called `name`. If the browser refuses, the
    /// reason is shown in the status line.
    fn download(name: String, bytes: Vec<u8>, inbox: &SharedInbox) {
        let inbox = inbox.clone();
        wasm_bindgen_futures::spawn_local(async move {
            if let Some(handle) = rfd::AsyncFileDialog::new()
                .set_file_name(&name)
                .save_file()
                .await
            {
                if let Err(e) = handle.write(&bytes).await {
                    *inbox.notice.lock().unwrap() = Some(format!("Could not save {name}: {e}"));
                }
            }
        });
    }

    pub fn encrypt(
        file: &PickedFile,
        password: &str,
        algorithm: EncryptionAlgorithms,
        inbox: &SharedInbox,
    ) -> Result<String, String> {
        let encrypted =
            encrypt_bytes(&file.bytes, password, algorithm).map_err(|e| e.to_string())?;
        let name = format!("{}.{}", file.name, encrypted_extension(algorithm));
        let message = format!("File encrypted. Saving {name} to your device.");
        download(name, encrypted, inbox);
        Ok(message)
    }

    pub fn decrypt(
        file: &PickedFile,
        password: &str,
        algorithm: EncryptionAlgorithms,
        inbox: &SharedInbox,
    ) -> Result<String, String> {
        let plain = decrypt_bytes(&file.bytes, password, algorithm).map_err(|e| e.to_string())?;
        let name = decrypted_name(&file.name);
        let message = format!("File decrypted. Saving {name} to your device.");
        download(name, plain, inbox);
        Ok(message)
    }

    pub fn hide_data(file: &PickedFile, data: &str, inbox: &SharedInbox) -> Result<String, String> {
        let png = hide_data_in_image_bytes(&file.bytes, data).map_err(|e| e.to_string())?;
        let name = hidden_image_name(&file.name);
        let message = format!("Data hidden. Saving {name} to your device.");
        download(name, png, inbox);
        Ok(message)
    }

    pub fn extract_data(file: &PickedFile) -> Result<String, String> {
        extract_data_from_image_bytes(&file.bytes).map_err(|e| e.to_string())
    }
}

pub use platform::{decrypt, encrypt, extract_data, hide_data, pick_file};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypting_removes_the_encrypted_suffix() {
        assert_eq!(decrypted_name("photo.jpg.aes256.enc"), "photo.jpg");
        assert_eq!(decrypted_name("notes.txt.aes128.enc"), "notes.txt");
        assert_eq!(decrypted_name("a.b.chacha20.enc"), "a.b");
    }

    #[test]
    fn a_file_without_our_suffix_gets_dec_appended() {
        assert_eq!(decrypted_name("mystery.bin"), "mystery.bin.dec");
        assert_eq!(decrypted_name("README"), "README.dec");
    }

    #[test]
    fn a_name_that_is_only_the_suffix_is_not_emptied() {
        assert_eq!(decrypted_name(".aes256.enc"), ".aes256.enc.dec");
    }

    #[test]
    fn hidden_images_are_pngs_named_after_the_original() {
        assert_eq!(hidden_image_name("holiday.jpg"), "holiday.hidden.png");
        assert_eq!(
            hidden_image_name("archive.tar.png"),
            "archive.tar.hidden.png"
        );
        assert_eq!(hidden_image_name("noextension"), "noextension.hidden.png");
        assert_eq!(hidden_image_name(".hidden"), ".hidden.hidden.png");
    }
}
