use eframe::egui::{self, TextEdit};
use encryption_app::{extract_data_from_image, hide_data_in_image};
use rfd::FileDialog;

pub fn image_hidden_data_ui(app: &mut crate::EncryptionApp, ui: &mut egui::Ui) {
    ui.heading("Image Hidden Data");

    if ui.button("Select Image").clicked() {
        if let Some(path) = FileDialog::new().pick_file() {
            app.image_path = Some(path);
            app.status_message.clear();
        }
    }

    if let Some(path) = &app.image_path {
        ui.label(format!("Selected Image: {}", path.display()));
    } else {
        ui.label("No image selected.");
    }

    ui.label("Enter Data to Hide:");
    ui.add(TextEdit::multiline(&mut app.hidden_data).hint_text("Data"));

    if ui.button("Hide Data").clicked() {
        if let Some(path) = &app.image_path {
            match hide_data_in_image(path, &app.hidden_data) {
                Ok(_) => {
                    app.status_message = "Data hidden in image successfully.".to_string();
                    app.image_path = None;
                }
                Err(e) => app.status_message = format!("Failed to hide data: {}", e),
            }
        } else {
            app.status_message = "Please select an image.".to_string();
        }
    }

    ui.separator();
    ui.heading("Extract Data from Image");

    if ui.button("Select Image").clicked() {
        if let Some(path) = FileDialog::new().pick_file() {
            app.image_path = Some(path);
            app.status_message.clear();
        }
    }

    if let Some(path) = &app.image_path {
        ui.label(format!("Selected Image: {}", path.display()));
    } else {
        ui.label("No image selected.");
    }

    if ui.button("Extract Data").clicked() {
        if let Some(path) = &app.image_path {
            match extract_data_from_image(path) {
                Ok(data) => {
                    app.extracted_data = data;
                    app.status_message = "Data extracted successfully.".to_string();
                    app.image_path = None;
                }
                Err(e) => app.status_message = format!("Failed to extract data: {}", e),
            }
        } else {
            app.status_message = "Please select an image.".to_string();
        }
    }

    ui.label("Extracted Data:");
    ui.add(
        TextEdit::multiline(&mut app.extracted_data)
            .hint_text("Extracted Data")
            .interactive(false),
    );

    if !app.status_message.is_empty() {
        ui.separator();
        ui.label(egui::RichText::new(&app.status_message).color(egui::Color32::RED));
    }
}
