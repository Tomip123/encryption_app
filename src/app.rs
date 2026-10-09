use crate::files::{Inbox, PickedFile, SharedInbox};
use crate::ui;
use eframe::egui::{self, CentralPanel, ScrollArea, TopBottomPanel};
use encryption_app::EncryptionAlgorithms;

/// Which of the two file slots a pick is for.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum PickTarget {
    #[default]
    File,
    Image,
}

pub struct EncryptionApp {
    pub file: Option<PickedFile>,
    pub password: String,
    pub status_message: String,
    pub algorithm: EncryptionAlgorithms,
    pub image: Option<PickedFile>,
    pub hidden_data: String,
    pub extracted_data: String,
    pub selected_tab: String,
    /// Where a pick or a download running in the background reports back (the browser's are asynchronous).
    pub inbox: SharedInbox,
    pub pick_target: PickTarget,
}

impl Default for EncryptionApp {
    fn default() -> Self {
        Self {
            file: None,
            password: String::new(),
            status_message: String::new(),
            algorithm: EncryptionAlgorithms::default(),
            image: None,
            hidden_data: String::new(),
            extracted_data: String::new(),
            selected_tab: "File Encryption".to_string(),
            inbox: SharedInbox::new(Inbox::default()),
            pick_target: PickTarget::default(),
        }
    }
}

impl EncryptionApp {
    /// Moves anything a background task delivered into the interface state.
    fn drain_inbox(&mut self) {
        if let Some(picked) = self.inbox.picked.lock().unwrap().take() {
            match self.pick_target {
                PickTarget::File => self.file = Some(picked),
                PickTarget::Image => self.image = Some(picked),
            }
            self.status_message.clear();
        }
        if let Some(notice) = self.inbox.notice.lock().unwrap().take() {
            self.status_message = notice;
        }
    }
}

impl eframe::App for EncryptionApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_inbox();

        TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                for tab in ["File Encryption", "Image Hidden Data", "About"] {
                    if ui.selectable_label(self.selected_tab == tab, tab).clicked() {
                        self.selected_tab = tab.to_string();
                    }
                }
            });
        });

        CentralPanel::default().show(ctx, |ui| {
            ScrollArea::vertical().show(ui, |ui| {
                match self.selected_tab.as_str() {
                    "File Encryption" => ui::file_encryption_ui::file_encryption_ui(self, ui),
                    "Image Hidden Data" => ui::image_hidden_data_ui::image_hidden_data_ui(self, ui),
                    "About" => ui::about_ui::about_ui(self, ui),
                    _ => {}
                }

                // A browser tab cannot be closed from inside the page, and exiting would crash the app.
                #[cfg(not(target_arch = "wasm32"))]
                {
                    ui.separator();
                    if ui.button("Close Program").clicked() {
                        std::process::exit(0);
                    }
                }
            });
        });
    }
}
