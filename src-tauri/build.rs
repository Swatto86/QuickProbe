//! Tauri build script — generates resource bundles and platform metadata.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    generate_quickprobe_console_font_module();
    tauri_build::build()
}

fn generate_quickprobe_console_font_module() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set"));
    let font_path = manifest_dir
        .join("assets")
        .join("fonts")
        .join("MesloLGS NF Regular.ttf");
    let generated_path = out_dir.join("quickprobe_console_font.rs");

    println!("cargo:rerun-if-changed={}", font_path.display());

    let content = if font_path.exists() {
        format!(
            "pub const QUICKPROBE_CONSOLE_FONT_BYTES: Option<&'static [u8]> = Some(include_bytes!(r#\"{}\"#));",
            font_path.display()
        )
    } else {
        "pub const QUICKPROBE_CONSOLE_FONT_BYTES: Option<&'static [u8]> = None;".to_string()
    };

    fs::write(generated_path, content).expect("generated console font module written");
}
