use crate::app::{EncryptionApp, PickTarget};
use crate::files;
use eframe::egui::{self, TextEdit};

fn select_image(app: &mut EncryptionApp, ui: &mut egui::Ui) {
    if ui.button("Select Image").clicked() {
        app.pick_target = PickTarget::Image;
        files::pick_file(&app.inbox, ui.ctx());
    }

    match &app.image {
        Some(image) => ui.label(format!("Selected Image: {}", image.name)),
        None => ui.label("No image selected."),
    };
}

pub fn image_hidden_data_ui(app: &mut EncryptionApp, ui: &mut egui::Ui) {
    ui.heading("Image Hidden Data");

    select_image(app, ui);

    ui.label("Enter Data to Hide:");
    ui.add(TextEdit::multiline(&mut app.hidden_data).hint_text("Data"));

    if ui.button("Hide Data").clicked() {
        if let Some(image) = &app.image {
            match files::hide_data(image, &app.hidden_data, &app.inbox) {
                Ok(message) => {
                    app.status_message = message;
                    app.image = None;
                }
                Err(e) => app.status_message = format!("Failed to hide data: {e}"),
            }
        } else {
            app.status_message = "Please select an image.".to_string();
        }
    }

    ui.separator();
    ui.heading("Extract Data from Image");

    select_image(app, ui);

    if ui.button("Extract Data").clicked() {
        if let Some(image) = &app.image {
            match files::extract_data(image) {
                Ok(data) => {
                    app.extracted_data = data;
                    app.status_message = "Data extracted successfully.".to_string();
                    app.image = None;
                }
                Err(e) => app.status_message = format!("Failed to extract data: {e}"),
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
