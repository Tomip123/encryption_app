mod app;
mod files;
mod ui;

#[cfg(not(target_arch = "wasm32"))]
fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Rust Encryption App",
        options,
        Box::new(|_cc| Ok(Box::new(app::EncryptionApp::default()))),
    )
}

/// Browser entry point: draws the app on the canvas that web/index.html provides.
#[cfg(target_arch = "wasm32")]
fn main() {
    use eframe::wasm_bindgen::JsCast as _;
    use eframe::web_sys;

    /// Shows a message in the page's status line, so a failure is visible instead of a blank canvas.
    fn show_error(message: &str) {
        if let Some(status) = web_sys::window()
            .and_then(|window| window.document())
            .and_then(|document| document.get_element_by_id("status"))
        {
            status.set_text_content(Some(message));
        }
    }

    wasm_bindgen_futures::spawn_local(async {
        let canvas = web_sys::window()
            .and_then(|window| window.document())
            .and_then(|document| document.get_element_by_id("app_canvas"))
            .and_then(|element| element.dyn_into::<web_sys::HtmlCanvasElement>().ok());
        let Some(canvas) = canvas else {
            show_error("The page is missing its canvas element (id app_canvas).");
            return;
        };

        let started = eframe::WebRunner::new()
            .start(
                canvas,
                eframe::WebOptions::default(),
                Box::new(|_cc| Ok(Box::new(app::EncryptionApp::default()))),
            )
            .await;

        match started {
            // The page hides its loading message once the app is running.
            Ok(()) => show_error(""),
            Err(error) => show_error(&format!("Could not start the app: {error:?}")),
        }
    });
}
