//! QuickProbe — Tauri application entry point.
//!
//! Command handlers live in the `commands` module.
//! This file wires the Tauri runtime, system tray, window lifecycle,
//! and the `generate_handler![]` macro.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod logger;
mod normalize;

use commands::*;
use quickprobe::updater;
use tauri::{
    async_runtime,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder, WindowEvent,
};
use tauri_plugin_global_shortcut::GlobalShortcutExt;

// Imports used only by tests (types constructed directly in assertions).
#[cfg(test)]
use chrono::Utc;
#[cfg(test)]
use quickprobe::{
    backup::{BackupPayload, HostBackupRow, BACKUP_SCHEMA_VERSION},
    db,
    models::{CredentialProfile, Credentials, SecureString, Username},
    platform::WindowsRemoteSession,
    CredentialStore,
};
#[cfg(test)]
use std::time::SystemTime;

// --------------------------------------------------------------------------
// Window lifecycle helpers
// --------------------------------------------------------------------------

/// Show the main window with normal startup logic (respects start_hidden setting).
#[allow(dead_code)]
fn show_main_window_normal(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.set_fullscreen(false);
        let start_hidden = load_app_settings().unwrap_or_default().start_hidden;
        let has_creds = has_saved_credentials_sync().unwrap_or(false);

        if start_hidden && has_creds {
            let _ = hide_to_tray(&window);
        } else {
            let _ = window.set_skip_taskbar(false);
            let _ = window.maximize();
            let _ = window.show();
            let _ = window.set_focus();
        }
    }
}

/// Bring the main window to the foreground and ensure it is visible.
fn show_and_focus_main(app: &tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        window.set_skip_taskbar(false).map_err(|e| e.to_string())?;
        window.show().map_err(|e| e.to_string())?;
        window.set_focus().map_err(|e| e.to_string())?;
        window.set_fullscreen(false).map_err(|e| e.to_string())?;
        window.maximize().map_err(|e| e.to_string())?;
        let _ = focus_dashboard_search(&window);
    }
    Ok(())
}

/// Show or create the About window from the tray.
fn show_and_focus_about(app: &tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("about") {
        window.show().map_err(|e| e.to_string())?;
        window.set_focus().map_err(|e| e.to_string())?;
        return Ok(());
    }

    let window = WebviewWindowBuilder::new(app, "about", WebviewUrl::App("about.html".into()))
        .title("About QuickProbe")
        .inner_size(620.0, 850.0)
        .resizable(false)
        .visible(false)
        .build()
        .map_err(|e| e.to_string())?;

    window.center().map_err(|e| e.to_string())?;
    window.show().map_err(|e| e.to_string())?;
    window.set_focus().map_err(|e| e.to_string())?;

    Ok(())
}

/// Show or create the Options window from the tray.
fn show_and_focus_options(app: &tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("options") {
        window.show().map_err(|e| e.to_string())?;
        window.set_focus().map_err(|e| e.to_string())?;
        return Ok(());
    }

    let window = WebviewWindowBuilder::new(app, "options", WebviewUrl::App("options.html".into()))
        .title("QuickProbe Options")
        .inner_size(900.0, 920.0)
        .min_inner_size(760.0, 820.0)
        .resizable(true)
        .visible(false)
        .build()
        .map_err(|e| e.to_string())?;

    window.center().map_err(|e| e.to_string())?;
    window.show().map_err(|e| e.to_string())?;
    window.set_focus().map_err(|e| e.to_string())?;

    Ok(())
}

/// Hide window to tray and remove from taskbar.
fn hide_to_tray<R: tauri::Runtime>(window: &WebviewWindow<R>) -> Result<(), String> {
    window.hide().map_err(|e| e.to_string())?;
    window.set_skip_taskbar(true).map_err(|e| e.to_string())?;
    Ok(())
}

fn focus_dashboard_search<R: tauri::Runtime>(window: &WebviewWindow<R>) -> Result<(), String> {
    // Try to focus the dashboard search box when the window is shown.
    window
        .eval(
            r#"
            (() => {
                const el = document.getElementById('server-search')
                    || document.querySelector('input[type="search"]');
                if (el) {
                    el.focus();
                    if (typeof el.select === 'function') {
                        el.select();
                    }
                }
            })();
            "#,
        )
        .map_err(|e| e.to_string())
}

fn toggle_main_window(app: &tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        let visible = window.is_visible().unwrap_or(true);
        let focused = window.is_focused().unwrap_or(false);

        if visible && focused {
            // Only hide if window is both visible AND focused
            hide_to_tray(&window)?;
        } else {
            // Show and focus if hidden, OR if visible but not focused (behind other windows)
            show_and_focus_main(app)?;
            let _ = focus_dashboard_search(&window);
        }
    }
    Ok(())
}

// --------------------------------------------------------------------------
// Application entry point
// --------------------------------------------------------------------------

// ============================================================================
// Elevation Check
// ============================================================================

fn main() {
    logger::init_dev_logger();
    logger::log_info("QuickProbe starting");
    if let Ok(mode) = compute_runtime_mode_info() {
        let detail = mode
            .details
            .db_path
            .clone()
            .unwrap_or_else(|| "<unset>".to_string());
        logger::log_info(&format!(
            "Runtime mode={} source={} detail={}",
            mode.mode, mode.config_source, detail
        ));
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            // When a second instance is launched, focus the existing main window
            logger::log_info("Second instance detected, focusing existing window");
            let _ = show_and_focus_main(app);
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_fs::init())
        .setup(|app| {
            let app_handle = app.handle().clone();

            // Build system tray with menu
            let options_item = MenuItem::with_id(app, "options", "Options", true, None::<&str>)?;
            let about_item = MenuItem::with_id(app, "about", "About QuickProbe", true, None::<&str>)?;
            let separator = PredefinedMenuItem::separator(app)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

            let menu = Menu::with_items(app, &[&options_item, &about_item, &separator, &quit_item])?;

            // Load icon from resources - Tauri 2.x requires explicit icon
            // Use the default window icon which is already loaded by Tauri
            let icon = app.default_window_icon().cloned().expect("Default window icon not found");

            let _tray = TrayIconBuilder::new()
                .icon(icon)
                .menu(&menu)
                .tooltip("QuickProbe")
                .on_menu_event(move |app, event| {
                    match event.id.as_ref() {
                        "options" => {
                            let _ = show_and_focus_options(app);
                        }
                        "about" => {
                            let _ = show_and_focus_about(app);
                        }
                        "quit" => {
                            app.exit(0);
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let _ = show_and_focus_main(tray.app_handle());
                    }
                })
                .build(app)?;

            // Spawn async task to check for updates on startup
            let update_app_handle = app_handle.clone();
            async_runtime::spawn(async move {
                // Small delay to ensure windows are initialized
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                logger::log_info("Checking for updates on startup...");

                match updater::check_for_update_impl().await {
                    Ok(update_info) if update_info.available => {
                        logger::log_info(&format!(
                            "Update available: {} -> {}",
                            update_info.current_version, update_info.version
                        ));

                        // Hide main window
                        if let Some(main_window) = update_app_handle.get_webview_window("main") {
                            logger::log_info("Hiding main window for update...");
                            let _ = main_window.hide();
                        }

                        // Create and show the update-required window dynamically
                        // This is more reliable than using a pre-configured window
                        match WebviewWindowBuilder::new(
                            &update_app_handle,
                            "update-required-dynamic",
                            WebviewUrl::App("update-required.html".into()),
                        )
                        .title("QuickProbe - Update Required")
                        .inner_size(500.0, 600.0)
                        .min_inner_size(450.0, 500.0)
                        .resizable(false)
                        .decorations(true)
                        .center()
                        .visible(true)
                        .skip_taskbar(false)
                        .build()
                        {
                            Ok(window) => {
                                logger::log_info("Update-required window created successfully");
                                let _ = window.set_focus();
                            }
                            Err(e) => {
                                logger::log_error(&format!("Failed to create update-required window: {}. Falling back to pre-configured window.", e));
                                // Fallback: try the pre-configured window
                                if let Some(update_window) = update_app_handle.get_webview_window("update-required") {
                                    let _ = update_window.show();
                                    let _ = update_window.set_focus();
                                } else {
                                    // If all else fails, emit event to let UI know update check is done
                                    logger::log_warn("Could not show update window, letting UI handle window visibility");
                                    if let Some(main_window) = update_app_handle.get_webview_window("main") {
                                        let _ = main_window.emit("update-check-complete", serde_json::json!({"has_update": false}));
                                    }
                                }
                            }
                        }
                    }
                    Ok(_) => {
                        // No updates available - let the UI handle window visibility
                        // The login page already calls ensureWindowVisible() appropriately
                        logger::log_info("No updates available, update check complete");
                        if let Some(main_window) = update_app_handle.get_webview_window("main") {
                            let _ = main_window.emit("update-check-complete", serde_json::json!({"has_update": false}));
                        }
                    }
                    Err(e) => {
                        // Update check failed - let the UI handle window visibility
                        logger::log_warn(&format!("Update check failed: {}. Continuing normally.", e));
                        if let Some(main_window) = update_app_handle.get_webview_window("main") {
                            let _ = main_window.emit("update-check-complete", serde_json::json!({"has_update": false, "error": e}));
                        }
                    }
                }
            });

            // Register global shortcut
            let shortcut_app_handle = app_handle.clone();
            app.global_shortcut().on_shortcut("Ctrl+Shift+R", move |_app, _shortcut, event| {
                // Only toggle on key press, not release (Tauri 2.x fires both events)
                if event.state == tauri_plugin_global_shortcut::ShortcutState::Pressed {
                    let _ = toggle_main_window(&shortcut_app_handle);
                }
            })?;

            Ok(())
        })
        .on_window_event(|window, event| match event {
            WindowEvent::CloseRequested { api, .. } => match window.label() {
                "main" => {
                    let _ = window.hide();
                    let _ = window.set_skip_taskbar(true);
                    api.prevent_close();
                }
                "options" | "about" => {
                    let _ = window.hide();
                    api.prevent_close();
                }
                "update-required" | "update-required-dynamic" => {
                    // Closing the update window should exit the app
                    // (user must either update or quit)
                }
                _ => {}
            },
            WindowEvent::Resized(_size) => {
                if window.is_minimized().unwrap_or(false) {
                    let _ = window.hide();
                    let _ = window.set_skip_taskbar(true);
                }
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            login,
            login_local_mode,
            get_login_mode,
            logout,
            check_saved_credentials,
            login_with_saved_credentials,
            get_hosts,
            save_server_notes,
            update_host,
            set_hosts,
            get_system_health,
            get_quick_status,
            scan_domain,
            save_rdp_credentials,
            launch_rdp,
            launch_ssh,
            open_explorer_share,
            launch_remote_registry,
            remote_restart,
            remote_shutdown,
            check_autostart,
            toggle_autostart,
            get_start_hidden_setting,
            set_start_hidden_setting,
            enable_options_menu,
            export_backup_encrypted,
            import_backup_encrypted,
            export_hosts_csv,
            get_app_info,
            fetch_net_adapters,
            fetch_os_info,
            get_remote_services,
            control_service,
            get_remote_processes,
            kill_process,
            execute_remote_powershell,
            execute_remote_ssh,
            execute_remote_ssh_pty,
            rename_group,
            get_runtime_mode_info,
            debug_local_store_status,
            settings_get_all,
            settings_set_all,
            cache_get_dashboard,
            cache_set_dashboard,
            persist_health_snapshot,
            load_health_snapshots,
            log_debug,
            log_info,
            log_warn,
            log_error,
            open_logs_folder,
            check_for_update,
            download_and_install_update,

        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use quickprobe::utils::CredentialError;
    use std::collections::HashMap;
    use std::sync::{Mutex, MutexGuard};
    use tempfile::tempdir;
    use tokio::runtime::Runtime;

    fn lock_appdata() -> MutexGuard<'static, ()> {
        db::appdata_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    fn with_temp_appdata<F: FnOnce() -> Result<(), String>>(f: F) {
        let _guard = lock_appdata();

        let temp = tempdir().expect("tempdir");
        let appdata = temp.path().to_path_buf();
        let original = std::env::var("APPDATA").ok();
        let original_backend = std::env::var("QP_PERSIST_BACKEND").ok();
        std::env::set_var("APPDATA", &appdata);
        if original_backend.is_none() {
            std::env::set_var("QP_PERSIST_BACKEND", "sqlite");
        }
        // ensure clean state
        let _ = std::fs::remove_dir_all(appdata.join("QuickProbe"));
        let result = f();
        if let Err(e) = result {
            panic!("test failed: {}", e);
        }
        if let Some(val) = original {
            std::env::set_var("APPDATA", val);
        }
        match original_backend {
            Some(val) => std::env::set_var("QP_PERSIST_BACKEND", val),
            None => std::env::remove_var("QP_PERSIST_BACKEND"),
        }
    }

    fn with_backend<F: FnOnce() -> Result<(), String>>(backend: &str, f: F) -> Result<(), String> {
        let original = std::env::var("QP_PERSIST_BACKEND").ok();
        std::env::set_var("QP_PERSIST_BACKEND", backend);
        let result = f();
        match original {
            Some(val) => std::env::set_var("QP_PERSIST_BACKEND", val),
            None => std::env::remove_var("QP_PERSIST_BACKEND"),
        }
        result
    }

    #[derive(Default)]
    struct MemoryStore {
        inner: Mutex<HashMap<String, Credentials>>,
    }

    #[async_trait]
    impl CredentialStore for MemoryStore {
        async fn store(
            &self,
            profile: &CredentialProfile,
            creds: &Credentials,
        ) -> Result<(), CredentialError> {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            guard.insert(profile.as_str().to_string(), creds.clone());
            Ok(())
        }

        async fn retrieve(
            &self,
            profile: &CredentialProfile,
        ) -> Result<Option<Credentials>, CredentialError> {
            let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            Ok(guard.get(profile.as_str()).cloned())
        }

        async fn exists(&self, profile: &CredentialProfile) -> Result<bool, CredentialError> {
            let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            Ok(guard.contains_key(profile.as_str()))
        }

        async fn delete(&self, profile: &CredentialProfile) -> Result<(), CredentialError> {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            guard.remove(profile.as_str());
            Ok(())
        }
    }

    fn make_creds(user: &str) -> Credentials {
        Credentials::new(
            Username::new(user).expect("username"),
            SecureString::new("Secret123!"),
        )
    }

    #[test]
    fn resolve_host_credentials_prefers_host_profile() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let store = MemoryStore::default();
            let server = "web1.contoso.com";
            let host_profile = CredentialProfile::new("QuickProbe:HOST/WEB1");
            let rdp_profile = CredentialProfile::new(format!("TERMSRV/{}", server));
            let default_profile = CredentialProfile::default();

            store
                .store(&default_profile, &make_creds("global-user"))
                .await
                .expect("store default");
            store
                .store(&rdp_profile, &make_creds("rdp-user"))
                .await
                .expect("store rdp");
            let host_creds = make_creds("host-user");
            store
                .store(&host_profile, &host_creds)
                .await
                .expect("store host");

            let (creds, used_profile) = resolve_host_credentials_with_store(&store, server)
                .await
                .expect("resolve");

            assert_eq!(used_profile, host_profile.as_str());
            assert_eq!(creds.username().as_str(), host_creds.username().as_str());
        });
    }

    #[test]
    fn resolve_host_credentials_prefers_rdp_over_default() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let store = MemoryStore::default();
            let server = "app1.contoso.com";
            let rdp_profile = CredentialProfile::new(format!("TERMSRV/{}", server));
            let default_profile = CredentialProfile::default();
            let host_profile = CredentialProfile::new("QuickProbe:HOST/APP1");

            let rdp_creds = make_creds("rdp-user");
            store
                .store(&rdp_profile, &rdp_creds)
                .await
                .expect("store rdp");
            store
                .store(&default_profile, &make_creds("global-user"))
                .await
                .expect("store default");

            let (creds, used_profile) = resolve_host_credentials_with_store(&store, server)
                .await
                .expect("resolve");

            assert_eq!(used_profile, rdp_profile.as_str());
            assert_eq!(creds.username().as_str(), rdp_creds.username().as_str());

            // Should promote to host profile for future reuse
            let promoted = store.retrieve(&host_profile).await.expect("retrieve host");
            assert!(promoted.is_some());
            assert_eq!(
                promoted.unwrap().username().as_str(),
                rdp_creds.username().as_str()
            );
        });
    }

    #[test]
    fn resolve_host_credentials_falls_back_to_default() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let store = MemoryStore::default();
            let server = "db1.contoso.com";
            let default_profile = CredentialProfile::default();
            let host_profile = CredentialProfile::new("QuickProbe:HOST/DB1");

            let default_creds = make_creds("global-user");
            store
                .store(&default_profile, &default_creds)
                .await
                .expect("store default");

            let (creds, used_profile) = resolve_host_credentials_with_store(&store, server)
                .await
                .expect("resolve");

            assert_eq!(used_profile, default_profile.as_str());
            assert_eq!(creds.username().as_str(), default_creds.username().as_str());

            // Host profile should be backfilled for next lookup
            let promoted = store.retrieve(&host_profile).await.expect("retrieve host");
            assert!(promoted.is_some());
            assert_eq!(
                promoted.unwrap().username().as_str(),
                default_creds.username().as_str()
            );
        });
    }

    #[test]
    fn normalize_host_name_strips_domain_and_uppercases() {
        let out = normalize_host_name("server01.contoso.com").unwrap();
        assert_eq!(out, "SERVER01");
    }

    #[test]
    fn normalize_host_name_rejects_empty() {
        assert!(normalize_host_name("").is_err());
        assert!(normalize_host_name("   ").is_err());
    }

    #[test]
    fn ldap_filter_toggles_server_only_vs_all_windows() {
        assert_eq!(
            ldap_windows_filter(false),
            "(&(objectClass=computer)(operatingSystem=Windows Server*))"
        );
        assert_eq!(
            ldap_windows_filter(true),
            "(&(objectClass=computer)(operatingSystem=Windows*))"
        );
    }

    #[test]
    fn ldap_host_identifier_prefers_dns_then_name_then_cn() {
        let mut attrs = HashMap::new();
        attrs.insert(
            "dNSHostName".to_string(),
            vec!["app1.contoso.com".to_string()],
        );
        attrs.insert("name".to_string(), vec!["APP1".to_string()]);
        attrs.insert("cn".to_string(), vec!["APP1-CN".to_string()]);
        assert_eq!(
            ldap_host_identifier(&attrs).as_deref(),
            Some("app1.contoso.com")
        );

        let mut attrs2 = HashMap::new();
        attrs2.insert("name".to_string(), vec!["APP2".to_string()]);
        attrs2.insert("cn".to_string(), vec!["APP2-CN".to_string()]);
        assert_eq!(ldap_host_identifier(&attrs2).as_deref(), Some("APP2"));

        let mut attrs3 = HashMap::new();
        attrs3.insert("cn".to_string(), vec!["APP3-CN".to_string()]);
        assert_eq!(ldap_host_identifier(&attrs3).as_deref(), Some("APP3-CN"));
    }

    #[test]
    fn merge_hosts_preserves_existing_and_uses_ad_description() {
        let existing = vec![
            ServerInfo {
                name: "app1.contoso.com".to_string(),
                notes: Some("keep me".to_string()),
                group: None,
                services: Some(vec!["WINRM".to_string(), "DFSR".to_string()]),
                os_type: Some("Windows".to_string()),
            },
            ServerInfo {
                name: "DB1".to_string(),
                notes: Some("db".to_string()),
                group: None,
                services: Some(vec!["SQL".to_string()]),
                os_type: Some("Windows".to_string()),
            },
        ];

        let discovered = vec![
            AdComputer {
                fqdn: "app1.contoso.local".to_string(),
                description: Some("AD desc that should not override".to_string()),
            },
            AdComputer {
                fqdn: "web1.contoso.local".to_string(),
                description: Some("Web role".to_string()),
            },
            AdComputer {
                fqdn: "db1.contoso.com".to_string(),
                description: Some("Duplicate".to_string()),
            },
        ];

        let merged = merge_hosts(existing, discovered, true).expect("merge should succeed");
        assert_eq!(merged.len(), 3);

        let app1 = merged.iter().find(|h| h.name == "APP1").expect("app1");
        assert_eq!(app1.notes.as_deref(), Some("keep me"));
        assert_eq!(
            app1.services.as_ref().unwrap(),
            &vec!["WINRM".to_string(), "DFSR".to_string()]
        );

        let web1 = merged.iter().find(|h| h.name == "WEB1").expect("web1");
        assert_eq!(web1.notes.as_deref(), Some("Web role"));
        assert!(web1.services.is_none());

        let db1 = merged.iter().find(|h| h.name == "DB1").expect("db1");
        assert_eq!(db1.notes.as_deref(), Some("db"));
        assert_eq!(db1.services.as_ref().unwrap(), &vec!["SQL".to_string()]);
    }

    #[test]
    fn merge_hosts_removes_missing_entries() {
        let existing = vec![
            ServerInfo {
                name: "app1.contoso.com".to_string(),
                notes: Some("keep me".to_string()),
                group: None,
                services: Some(vec!["WINRM".to_string()]),
                os_type: Some("Windows".to_string()),
            },
            ServerInfo {
                name: "DB1".to_string(),
                notes: Some("db".to_string()),
                group: Some("SQL".to_string()),
                services: Some(vec!["SQL".to_string()]),
                os_type: Some("Windows".to_string()),
            },
        ];

        let discovered = vec![AdComputer {
            fqdn: "db1.contoso.com".to_string(),
            description: Some("Database server".to_string()),
        }];

        let merged = merge_hosts(existing, discovered, true).expect("merge should succeed");
        assert_eq!(merged.len(), 1);
        let db1 = merged.first().expect("db1 present");
        assert_eq!(db1.name, "DB1");
        assert_eq!(db1.notes.as_deref(), Some("db"));
        assert_eq!(db1.group.as_deref(), Some("SQL"));
        assert_eq!(db1.services.as_ref().unwrap(), &vec!["SQL".to_string()]);
    }

    #[test]
    fn merge_hosts_can_keep_missing_windows_when_requested() {
        let existing = vec![
            ServerInfo {
                name: "app1.contoso.com".to_string(),
                notes: Some("keep me".to_string()),
                group: Some("App".to_string()),
                services: Some(vec!["WINRM".to_string()]),
                os_type: Some("Windows".to_string()),
            },
            ServerInfo {
                name: "db1.contoso.com".to_string(),
                notes: Some("db".to_string()),
                group: None,
                services: Some(vec!["SQL".to_string()]),
                os_type: Some("Windows".to_string()),
            },
        ];

        let discovered = vec![
            AdComputer {
                fqdn: "app1.contoso.local".to_string(),
                description: Some("AD desc that should not override".to_string()),
            },
            AdComputer {
                fqdn: "web1.contoso.com".to_string(),
                description: Some("Web role".to_string()),
            },
        ];

        let merged = merge_hosts(existing, discovered, false).expect("merge should succeed");
        assert_eq!(merged.len(), 3);

        let app1 = merged.iter().find(|h| h.name == "APP1").expect("app1");
        assert_eq!(app1.notes.as_deref(), Some("keep me"));
        let db1 = merged.iter().find(|h| h.name == "DB1").expect("db1 kept");
        assert_eq!(db1.notes.as_deref(), Some("db"));
        let web1 = merged
            .iter()
            .find(|h| h.name == "WEB1")
            .expect("web1 added");
        assert_eq!(web1.notes.as_deref(), Some("Web role"));
    }

    #[test]
    fn merge_hosts_keeps_linux_hosts_and_adds_discovered_windows() {
        let existing = vec![ServerInfo {
            name: "linux01.contoso.com".to_string(),
            notes: Some("linux host".to_string()),
            group: Some("Linux".to_string()),
            services: None,
            os_type: Some("Linux".to_string()),
        }];

        let discovered = vec![AdComputer {
            fqdn: "web1.contoso.com".to_string(),
            description: Some("Windows Web".to_string()),
        }];

        let merged = merge_hosts(existing, discovered, true).expect("merge should succeed");
        assert_eq!(merged.len(), 2);
        let linux = merged
            .iter()
            .find(|h| h.name == "LINUX01")
            .expect("linux kept");
        assert_eq!(linux.os_type.as_deref(), Some("Linux"));
        let web = merged
            .iter()
            .find(|h| h.name == "WEB1")
            .expect("web1 added");
        assert_eq!(web.notes.as_deref(), Some("Windows Web"));
    }

    #[test]
    fn save_server_notes_updates_normalized_row_and_preserves_services() {
        with_temp_appdata(|| {
            let initial = vec![
                HostUpdate {
                    name: "db1.contoso.com".to_string(),
                    notes: Some("old".to_string()),
                    group: None,
                    services: Some(vec!["SQL".to_string(), "WinRM".to_string()]),
                    os_type: Some("Windows".to_string()),
                },
                HostUpdate {
                    name: "WEB1".to_string(),
                    notes: Some("web".to_string()),
                    group: None,
                    services: None,
                    os_type: Some("Windows".to_string()),
                },
            ];
            write_hosts_sqlite(&initial)?;

            let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
            rt.block_on(save_server_notes(
                "db1".to_string(),
                "new-notes".to_string(),
            ))?;

            let hosts = rt.block_on(get_hosts())?;
            let db1 = hosts.iter().find(|h| h.name == "DB1").unwrap();
            assert_eq!(db1.notes.as_deref(), Some("new-notes"));
            assert_eq!(
                db1.services.as_ref().unwrap(),
                &vec!["SQL".to_string(), "WINRM".to_string()]
            );
            let web1 = hosts.iter().find(|h| h.name == "WEB1").unwrap();
            assert_eq!(web1.notes.as_deref(), Some("web"));
            Ok(())
        });
    }

    #[test]
    fn update_host_normalizes_services_and_os_type() {
        with_temp_appdata(|| {
            let initial = vec![HostUpdate {
                name: "app1.contoso.com".to_string(),
                notes: Some("old".to_string()),
                group: Some("legacy".to_string()),
                services: Some(vec!["WINRM".to_string()]),
                os_type: Some("Windows".to_string()),
            }];
            write_hosts_sqlite(&initial)?;

            let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
            rt.block_on(update_host(
                "app1".to_string(),
                Some("new note".to_string()),
                Some("ops".to_string()),
                Some("linux".to_string()),
                Some(vec![
                    " winrm ".to_string(),
                    "dns".to_string(),
                    "DNS".to_string(),
                ]),
            ))?;

            let hosts = rt.block_on(get_hosts())?;
            let app1 = hosts
                .iter()
                .find(|h| h.name == "APP1")
                .expect("app1 exists");
            assert_eq!(app1.notes.as_deref(), Some("new note"));
            assert_eq!(app1.group.as_deref(), Some("ops"));
            assert_eq!(app1.os_type.as_deref(), Some("Linux"));
            assert_eq!(
                app1.services.as_ref().unwrap(),
                &vec!["WINRM".to_string(), "DNS".to_string()]
            );
            Ok(())
        });
    }

    #[test]
    fn update_host_rejects_invalid_service_names() {
        with_temp_appdata(|| {
            let initial = vec![HostUpdate {
                name: "app1".to_string(),
                notes: Some("old".to_string()),
                group: None,
                services: Some(vec!["WINRM".to_string()]),
                os_type: Some("Windows".to_string()),
            }];
            write_hosts_sqlite(&initial)?;

            let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
            let err = rt
                .block_on(update_host(
                    "app1".to_string(),
                    None,
                    None,
                    Some("windows".to_string()),
                    Some(vec!["bad*svc".to_string()]),
                ))
                .expect_err("invalid service name should fail");
            assert!(
                err.contains("Invalid services list"),
                "unexpected error: {}",
                err
            );

            // Host row should remain unchanged after failed update.
            let hosts = rt.block_on(get_hosts())?;
            let app1 = hosts
                .iter()
                .find(|h| h.name == "APP1")
                .expect("app1 exists");
            assert_eq!(app1.services.as_ref().unwrap(), &vec!["WINRM".to_string()]);
            assert_eq!(app1.os_type.as_deref(), Some("Windows"));
            Ok(())
        });
    }

    #[test]
    fn set_hosts_clears_session_cache_on_success() {
        with_temp_appdata(|| {
            let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
            rt.block_on(clear_session_cache());

            let session = rt
                .block_on(WindowsRemoteSession::connect(
                    "APP1".to_string(),
                    make_creds("cache-user"),
                ))
                .map_err(|e| format!("session build: {}", e))?;

            rt.block_on(async {
                session_pool().write().await.insert(
                    "app1".to_string(),
                    CachedSession {
                        session: std::sync::Arc::new(session),
                        created_at: SystemTime::now(),
                    },
                );
            });

            let before = rt.block_on(async { session_pool().read().await.len() });
            assert_eq!(before, 1);

            rt.block_on(set_hosts(vec![HostUpdate {
                name: "app1".to_string(),
                notes: Some("cache test".to_string()),
                group: None,
                services: Some(vec!["winrm".to_string()]),
                os_type: Some("windows".to_string()),
            }]))?;

            let after = rt.block_on(async { session_pool().read().await.len() });
            assert_eq!(after, 0);
            Ok(())
        });
    }

    #[test]
    fn get_hosts_allows_empty_list() {
        with_temp_appdata(|| {
            // Empty dataset should still return an empty list
            write_hosts_sqlite(&[])?;

            let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
            let hosts = rt.block_on(get_hosts())?;
            assert!(hosts.is_empty());
            Ok(())
        });
    }

    #[test]
    fn get_hosts_preserves_notes_with_commas_and_services() {
        with_temp_appdata(|| {
            let initial = vec![HostUpdate {
                name: "app1".to_string(),
                notes: Some("Primary, Site, DC".to_string()),
                group: None,
                services: Some(vec!["WinRM".to_string(), "DFSR".to_string()]),
                os_type: Some("Windows".to_string()),
            }];

            write_hosts_sqlite(&initial)?;

            let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
            let hosts = rt.block_on(get_hosts())?;

            assert_eq!(hosts.len(), 1);
            assert_eq!(hosts[0].notes.as_deref(), Some("Primary, Site, DC"));
            assert_eq!(
                hosts[0].services.as_ref().unwrap(),
                &vec!["WINRM".to_string(), "DFSR".to_string()]
            );
            Ok(())
        });
    }

    #[test]
    fn get_hosts_splits_group_from_notes_column() {
        with_temp_appdata(|| {
            let initial = vec![HostUpdate {
                name: "app1.contoso.com".to_string(),
                notes: Some("Domain Controller".to_string()),
                group: Some("Azure".to_string()),
                services: Some(vec!["WinRM".to_string()]),
                os_type: Some("Windows".to_string()),
            }];

            write_hosts_sqlite(&initial)?;

            let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
            let hosts = rt.block_on(get_hosts())?;

            assert_eq!(hosts.len(), 1);
            assert_eq!(hosts[0].name, "APP1");
            assert_eq!(hosts[0].notes.as_deref(), Some("Domain Controller"));
            assert_eq!(hosts[0].group.as_deref(), Some("Azure"));
            assert_eq!(
                hosts[0].services.as_ref().unwrap(),
                &vec!["WINRM".to_string()]
            );
            Ok(())
        });
    }

    #[test]
    fn sqlite_write_persists_across_reopen() {
        with_temp_appdata(|| {
            with_backend("sqlite", || {
                let hosts = vec![HostUpdate {
                    name: "app1.contoso.com".to_string(),
                    notes: Some("note".to_string()),
                    group: Some("Core".to_string()),
                    services: Some(vec!["winrm".to_string()]),
                    os_type: Some("Windows".to_string()),
                }];
                persist_hosts(&hosts)?;

                let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
                let loaded = rt.block_on(get_hosts())?;
                assert_eq!(loaded.len(), 1);
                assert_eq!(loaded[0].name, "APP1");
                assert_eq!(loaded[0].notes.as_deref(), Some("note"));
                Ok(())
            })
        });
    }

    #[test]
    fn sqlite_edit_normalizes_and_updates() {
        with_temp_appdata(|| {
            with_backend("sqlite", || {
                let initial = vec![HostUpdate {
                    name: "app1".to_string(),
                    notes: Some("old".to_string()),
                    group: Some("dev".to_string()),
                    services: Some(vec!["dns".to_string()]),
                    os_type: Some("linux".to_string()),
                }];
                persist_hosts(&initial)?;

                let updated = vec![HostUpdate {
                    name: "app1.domain.local".to_string(),
                    notes: Some("new note".to_string()),
                    group: Some(" core ".to_string()),
                    services: Some(vec!["winrm".to_string(), "dns".to_string()]),
                    os_type: Some("windows".to_string()),
                }];
                persist_hosts(&updated)?;

                let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
                let loaded = rt.block_on(get_hosts())?;
                assert_eq!(loaded.len(), 1);
                assert_eq!(loaded[0].name, "APP1");
                assert_eq!(loaded[0].notes.as_deref(), Some("new note"));
                assert_eq!(loaded[0].group.as_deref(), Some("core"));
                assert_eq!(
                    loaded[0].services.as_ref().unwrap(),
                    &vec!["WINRM".to_string(), "DNS".to_string()]
                );
                assert_eq!(loaded[0].os_type.as_deref(), Some("Windows"));
                Ok(())
            })
        });
    }

    #[test]
    fn sqlite_delete_removes_host() {
        with_temp_appdata(|| {
            with_backend("sqlite", || {
                let initial = vec![
                    HostUpdate {
                        name: "app1".to_string(),
                        notes: None,
                        group: None,
                        services: None,
                        os_type: None,
                    },
                    HostUpdate {
                        name: "app2".to_string(),
                        notes: None,
                        group: None,
                        services: None,
                        os_type: None,
                    },
                ];
                persist_hosts(&initial)?;

                let updated = vec![HostUpdate {
                    name: "app1".to_string(),
                    notes: Some("stay".to_string()),
                    group: None,
                    services: None,
                    os_type: None,
                }];
                persist_hosts(&updated)?;

                let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
                let loaded = rt.block_on(get_hosts())?;
                assert_eq!(loaded.len(), 1);
                assert_eq!(loaded[0].name, "APP1");
                assert_eq!(loaded[0].notes.as_deref(), Some("stay"));
                Ok(())
            })
        });
    }

    #[test]
    fn sqlite_concurrent_upserts_do_not_busy() {
        with_temp_appdata(|| {
            with_backend("sqlite", || {
                std::thread::scope(|s| {
                    for _ in 0..4 {
                        s.spawn(|| {
                            let hosts = vec![
                                HostUpdate {
                                    name: "app1".to_string(),
                                    notes: Some("note".to_string()),
                                    group: Some("core".to_string()),
                                    services: Some(vec!["winrm".to_string()]),
                                    os_type: Some("Windows".to_string()),
                                },
                                HostUpdate {
                                    name: "db1".to_string(),
                                    notes: Some("db".to_string()),
                                    group: Some("core".to_string()),
                                    services: Some(vec!["sql".to_string()]),
                                    os_type: Some("Windows".to_string()),
                                },
                            ];
                            persist_hosts(&hosts).expect("persist ok");
                        });
                    }
                });

                let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
                let loaded = rt.block_on(get_hosts())?;
                assert_eq!(loaded.len(), 2);
                Ok(())
            })
        });
    }

    #[test]
    fn kv_defaults_match_ui_expectations() {
        with_temp_appdata(|| {
            with_backend("sqlite", || {
                let settings = kv_get_value("qp_settings")?;
                assert_eq!(settings, Some(default_qp_settings_json()));
                let server_order = kv_get_value("qp_server_order")?;
                assert_eq!(server_order.as_deref(), Some("[]"));
                let host_view_mode = kv_get_value("qp_host_view_mode")?;
                assert_eq!(host_view_mode.as_deref(), Some("cards"));
                let hosts_changed = kv_get_value("qp_hosts_changed")?;
                assert!(hosts_changed.is_none());
                Ok(())
            })
        });
    }

    #[test]
    fn kv_round_trips_for_known_keys() {
        with_temp_appdata(|| {
            with_backend("sqlite", || {
                kv_set_value("qp_settings", r#"{"theme":"dark"}"#)?;
                kv_set_value("qp_server_order", r#"["A","B"]"#)?;
                kv_set_value("qp_host_view_mode", "groups")?;
                kv_set_value("qp_hosts_changed", "12345")?;

                assert_eq!(
                    kv_get_value("qp_settings")?,
                    Some(r#"{"theme":"dark"}"#.to_string())
                );
                assert_eq!(
                    kv_get_value("qp_server_order")?,
                    Some(r#"["A","B"]"#.to_string())
                );
                assert_eq!(
                    kv_get_value("qp_host_view_mode")?,
                    Some("groups".to_string())
                );
                assert_eq!(kv_get_value("qp_hosts_changed")?, Some("12345".to_string()));
                Ok(())
            })
        });
    }

    #[test]
    fn settings_get_all_returns_defaults_when_empty() {
        with_temp_appdata(|| {
            let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
            let bundle = rt.block_on(settings_get_all())?;
            let expected_settings: serde_json::Value =
                serde_json::from_str(&default_qp_settings_json()).unwrap();
            assert_eq!(bundle.qp_settings, expected_settings);
            assert_eq!(bundle.qp_server_order, serde_json::json!([]));
            assert_eq!(bundle.qp_host_view_mode, serde_json::json!("cards"));
            assert!(bundle.qp_hosts_changed.is_none());
            Ok(())
        });
    }

    #[test]
    fn settings_set_all_round_trips_values() {
        with_temp_appdata(|| {
            let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
            let payload = SettingsSetPayload {
                qp_settings: serde_json::json!({
                    "probeTimeoutSeconds": 45,
                    "infoTimeoutMs": 3100,
                    "warningTimeoutMs": 4200,
                    "errorTimeoutMs": 1,
                    "locationMappings": [{"range":"10.0.0.0/8","label":"LAN"}],
                    "theme": "dark"
                }),
                qp_server_order: serde_json::json!(["B", "A"]),
                qp_host_view_mode: serde_json::json!("groups"),
                qp_hosts_changed: Some(serde_json::json!("12345")),
            };
            rt.block_on(settings_set_all(payload))?;

            let bundle = rt.block_on(settings_get_all())?;
            assert_eq!(
                bundle.qp_settings.get("theme"),
                Some(&serde_json::json!("dark"))
            );
            assert_eq!(
                bundle.qp_settings.get("probeTimeoutSeconds"),
                Some(&serde_json::json!(45))
            );
            assert_eq!(bundle.qp_server_order, serde_json::json!(["B", "A"]));
            assert_eq!(bundle.qp_host_view_mode, serde_json::json!("groups"));
            assert_eq!(bundle.qp_hosts_changed, Some(serde_json::json!("12345")));
            Ok(())
        });
    }

    #[test]
    fn settings_set_all_preserves_hosts_changed_when_missing() {
        with_temp_appdata(|| {
            let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
            let initial = SettingsSetPayload {
                qp_settings: serde_json::json!({
                    "probeTimeoutSeconds": 60,
                    "infoTimeoutMs": 3500,
                    "warningTimeoutMs": 4500,
                    "errorTimeoutMs": 0,
                    "locationMappings": [],
                    "theme": "light"
                }),
                qp_server_order: serde_json::json!(["A"]),
                qp_host_view_mode: serde_json::json!("cards"),
                qp_hosts_changed: Some(serde_json::json!("original")),
            };
            rt.block_on(settings_set_all(initial))?;

            let update_without_hosts_changed = SettingsSetPayload {
                qp_settings: serde_json::json!({
                    "probeTimeoutSeconds": 30,
                    "infoTimeoutMs": 2000,
                    "warningTimeoutMs": 3000,
                    "errorTimeoutMs": 0,
                    "locationMappings": [],
                    "theme": "dark"
                }),
                qp_server_order: serde_json::json!(["A", "B"]),
                qp_host_view_mode: serde_json::json!("groups"),
                qp_hosts_changed: None,
            };
            rt.block_on(settings_set_all(update_without_hosts_changed))?;

            let bundle = rt.block_on(settings_get_all())?;
            assert_eq!(bundle.qp_hosts_changed, Some(serde_json::json!("original")));
            assert_eq!(bundle.qp_server_order, serde_json::json!(["A", "B"]));
            assert_eq!(bundle.qp_host_view_mode, serde_json::json!("groups"));
            Ok(())
        });
    }

    #[test]
    fn dashboard_cache_round_trips_to_local_file() {
        with_temp_appdata(|| {
            let payload = serde_json::json!({
                "cachedAt":"2024-02-01T00:00:00Z",
                "serversData":[
                    {
                        "name":"APP1",
                        "online":true,
                        "data":{"os_info":{"hostname":"APP1"}},
                        "error":null
                    },
                    {
                        "name":"APP2",
                        "online":false,
                        "data":{},
                        "error":"Timeout after 60000ms"
                    }
                ],
                "hostsSignature":"abc"
            });
            cache_set_dashboard(payload.clone())?;
            let loaded = cache_get_dashboard()?;
            assert_eq!(loaded, Some(payload));
            Ok(())
        });
    }

    #[test]
    fn export_backup_captures_sqlite_state() {
        with_temp_appdata(|| {
            persist_hosts(&[HostUpdate {
                name: "app1".to_string(),
                notes: Some("note".to_string()),
                group: Some("ops".to_string()),
                services: Some(vec!["winrm".to_string()]),
                os_type: Some("Windows".to_string()),
            }])?;
            kv_set_value("qp_settings", r#"{"theme":"light"}"#)?;
            let temp = tempdir().expect("tempdir");
            let dest = temp.path().join("backup.zip");

            export_backup(&dest, "Test1234")?;
            let payload = read_backup_payload(&dest, "Test1234")?.expect("payload exists");
            assert_eq!(payload.hosts.len(), 1);
            assert_eq!(payload.hosts[0].server_name, "APP1");
            assert_eq!(
                payload.kv.get("qp_settings").cloned().flatten(),
                Some(r#"{"theme":"light"}"#.to_string())
            );
            Ok(())
        });
    }

    #[test]
    fn restore_backup_normalizes_hosts_and_sets_flag() {
        with_temp_appdata(|| {
            with_backend("sqlite", || {
                persist_hosts(&[HostUpdate {
                    name: "old".to_string(),
                    notes: None,
                    group: None,
                    services: None,
                    os_type: Some("Windows".to_string()),
                }])?;

                let mut kv_map = std::collections::BTreeMap::new();
                kv_map.insert(
                    "qp_settings".to_string(),
                    Some(r#"{"theme":"dark"}"#.to_string()),
                );

                let payload = BackupPayload {
                    schema_version: BACKUP_SCHEMA_VERSION,
                    exported_at: Utc::now().to_rfc3339(),
                    app_version: env!("CARGO_PKG_VERSION").to_string(),
                    mode: compute_runtime_mode_info()?,
                    hosts: vec![HostBackupRow {
                        server_name: "app1.contoso.com".to_string(),
                        notes: Some("note".to_string()),
                        group: Some("core".to_string()),
                        os_type: "windows".to_string(),
                        services: Some("winrm;sql".to_string()),
                    }],
                    kv: kv_map,
                };

                let temp = tempdir().expect("tempdir");
                let dest = temp.path().join("restore.zip");
                write_encrypted_backup(&dest, "Test1234", &payload)?;

                let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
                rt.block_on(import_backup_encrypted(
                    dest.to_string_lossy().to_string(),
                    "Test1234".to_string(),
                ))?;

                let hosts = read_hosts_from_sqlite()?;
                assert_eq!(hosts.len(), 1);
                assert_eq!(hosts[0].name, "APP1");
                assert_eq!(
                    hosts[0].services.as_ref().unwrap(),
                    &vec!["WINRM".to_string(), "SQL".to_string()]
                );

                let hosts_changed = kv_get_value("qp_hosts_changed")?;
                assert!(hosts_changed.is_some());

                let app_dir = get_app_data_dir()?;
                let pre_backups: Vec<_> = std::fs::read_dir(app_dir)
                    .unwrap()
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        let name = e.file_name().to_string_lossy().to_string();
                        let lower = name.to_lowercase();
                        lower.starts_with("quickprobe-pre-restore-")
                    })
                    .collect();
                assert!(!pre_backups.is_empty());
                Ok(())
            })
        });
    }

    #[test]
    fn restore_backup_is_atomic_on_failure() {
        with_temp_appdata(|| {
            persist_hosts(&[HostUpdate {
                name: "good".to_string(),
                notes: None,
                group: None,
                services: None,
                os_type: Some("Windows".to_string()),
            }])?;

            let payload = BackupPayload {
                schema_version: BACKUP_SCHEMA_VERSION,
                exported_at: Utc::now().to_rfc3339(),
                app_version: env!("CARGO_PKG_VERSION").to_string(),
                mode: compute_runtime_mode_info()?,
                hosts: vec![HostBackupRow {
                    server_name: "".to_string(),
                    notes: None,
                    group: None,
                    os_type: "Windows".to_string(),
                    services: None,
                }],
                kv: std::collections::BTreeMap::new(),
            };

            let temp = tempdir().expect("tempdir");
            let dest = temp.path().join("invalid.zip");
            write_encrypted_backup(&dest, "Test1234", &payload)?;

            let rt = Runtime::new().map_err(|e| format!("rt build: {}", e))?;
            let result = rt.block_on(import_backup_encrypted(
                dest.to_string_lossy().to_string(),
                "Test1234".to_string(),
            ));
            assert!(result.is_err());

            let hosts = read_hosts_from_sqlite()?;
            assert_eq!(hosts.len(), 1);
            assert_eq!(hosts[0].name, "GOOD");
            Ok(())
        });
    }

    // ── Login-mode KV helpers ────────────────────────────────────────

    #[test]
    fn login_mode_defaults_to_none() {
        with_temp_appdata(|| {
            let mode = read_login_mode();
            assert_eq!(mode, "none");
            Ok(())
        });
    }

    #[test]
    fn set_and_read_login_mode_domain() {
        with_temp_appdata(|| {
            set_login_mode("domain")?;
            assert_eq!(read_login_mode(), "domain");
            Ok(())
        });
    }

    #[test]
    fn set_and_read_login_mode_local() {
        with_temp_appdata(|| {
            set_login_mode("local")?;
            assert_eq!(read_login_mode(), "local");
            Ok(())
        });
    }

    #[test]
    fn clear_login_mode_resets_to_none() {
        with_temp_appdata(|| {
            set_login_mode("local")?;
            assert_eq!(read_login_mode(), "local");
            clear_login_mode()?;
            assert_eq!(read_login_mode(), "none");
            Ok(())
        });
    }

    #[test]
    fn login_mode_survives_multiple_changes() {
        with_temp_appdata(|| {
            set_login_mode("domain")?;
            assert_eq!(read_login_mode(), "domain");
            set_login_mode("local")?;
            assert_eq!(read_login_mode(), "local");
            clear_login_mode()?;
            assert_eq!(read_login_mode(), "none");
            set_login_mode("domain")?;
            assert_eq!(read_login_mode(), "domain");
            Ok(())
        });
    }
}
