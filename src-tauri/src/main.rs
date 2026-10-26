#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Chrome launches the native messaging host as `<exe> chrome-extension://<id>/ …`.
    // Handle that before Tauri starts so no window opens.
    if let Some(origin) = std::env::args().nth(1).filter(|a| a.starts_with("chrome-extension://")) {
        std::process::exit(securevault_lib::run_native_host(&origin));
    }
    securevault_lib::run()
}
