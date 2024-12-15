use eframe::egui::{self, CentralPanel, ScrollArea, TopBottomPanel};
use encryption_app::EncryptionAlgorithms;
use std::path::PathBuf;

mod ui {
    pub mod file_encryption_ui;
    pub mod image_hidden_data_ui;
}

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
    image_path: Option<PathBuf>,
    hidden_data: String,
    extracted_data: String,
    selected_tab: String,
}

impl Default for EncryptionApp {
    fn default() -> Self {
        Self {
            file_path: None,
            password: String::new(),
            status_message: String::new(),
            algorithm: EncryptionAlgorithms::default(),
            image_path: None,
            hidden_data: String::new(),
            extracted_data: String::new(),
            selected_tab: "File Encryption".to_string(),
        }
    }
}

impl eframe::App for EncryptionApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
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
                    "File Encryption" => ui::file_encryption_ui::file_encryption_ui(self, ui),
                    "Image Hidden Data" => ui::image_hidden_data_ui::image_hidden_data_ui(self, ui),
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
