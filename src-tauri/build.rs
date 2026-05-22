//! Tauri build script — generates resource bundles and platform metadata.

fn main() {
    #[cfg(feature = "tauri-app")]
    tauri_build::build()
}
