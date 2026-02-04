//! Windows Registry integration for platform-specific settings.
//!
//! This module provides minimal safe wrappers around Windows Registry APIs
//! to support features like autostart without leaking `unsafe` usage into
//! the rest of the codebase.

use std::ffi::OsStr;
use std::iter;
use std::os::windows::ffi::OsStrExt;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
};

/// Thin wrapper around Windows Registry APIs for per-user settings.
pub struct WindowsRegistry;

impl WindowsRegistry {
    /// Creates a new registry helper.
    pub fn new() -> Self {
        WindowsRegistry
    }

    /// Checks whether the specified value exists under the given key.
    pub fn value_exists(&self, key_path: &str, value_name: &str) -> Result<bool, String> {
        // SAFETY: Windows registry APIs require raw UTF-16 pointers; the buffers created
        // in this scope remain valid for the duration of each call.
        unsafe {
            let key_path_w = to_wide(key_path);
            let mut hkey = HKEY::default();

            match RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR::from_raw(key_path_w.as_ptr()),
                0,
                KEY_READ,
                &mut hkey,
            )
            .ok()
            {
                Ok(_) => {}
                Err(e) => {
                    if e == ERROR_FILE_NOT_FOUND.into() || e == ERROR_PATH_NOT_FOUND.into() {
                        return Ok(false);
                    }
                    return Err(format!(
                        "Failed to open registry key '{}': {:?}",
                        key_path, e
                    ));
                }
            }

            let value_w = to_wide(value_name);
            let mut data_size: u32 = 0;
            let query = RegQueryValueExW(
                hkey,
                PCWSTR::from_raw(value_w.as_ptr()),
                None,
                None,
                None,
                Some(&mut data_size),
            )
            .ok();

            let _ = RegCloseKey(hkey);

            match query {
                Ok(_) => Ok(true),
                Err(e) => {
                    if e == ERROR_FILE_NOT_FOUND.into() {
                        Ok(false)
                    } else {
                        Err(format!(
                            "Failed to query registry value '{}': {:?}",
                            value_name, e
                        ))
                    }
                }
            }
        }
    }

    /// Writes a string value (REG_SZ) to the registry, creating the key if needed.
    pub fn write_string(
        &self,
        key_path: &str,
        value_name: &str,
        value: &str,
    ) -> Result<(), String> {
        // SAFETY: All UTF-16 buffers live for the duration of the Win32 API calls and the
        // handles are closed explicitly after use.
        unsafe {
            let key_path_w = to_wide(key_path);
            let mut hkey = HKEY::default();

            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR::from_raw(key_path_w.as_ptr()),
                0,
                PWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                None,
                &mut hkey,
                None,
            )
            .ok()
            .map_err(|e| format!("Failed to create/open registry key '{}': {:?}", key_path, e))?;

            let value_w = to_wide(value_name);
            let data_w = to_wide(value);
            let value_bytes = data_w.align_to::<u8>().1;

            RegSetValueExW(
                hkey,
                PCWSTR::from_raw(value_w.as_ptr()),
                0,
                REG_SZ,
                Some(value_bytes),
            )
            .ok()
            .map_err(|e| format!("Failed to write registry value '{}': {:?}", value_name, e))?;

            let _ = RegCloseKey(hkey);
            Ok(())
        }
    }

    /// Deletes the specified value if it exists. Missing values are treated as success.
    pub fn delete_value(&self, key_path: &str, value_name: &str) -> Result<(), String> {
        // SAFETY: Windows registry APIs operate on raw handles and UTF-16 pointers; the
        // backing buffers outlive the calls and the handle is closed afterwards.
        unsafe {
            let key_path_w = to_wide(key_path);
            let mut hkey = HKEY::default();

            match RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR::from_raw(key_path_w.as_ptr()),
                0,
                KEY_SET_VALUE,
                &mut hkey,
            )
            .ok()
            {
                Ok(_) => {}
                Err(e) => {
                    if e == ERROR_FILE_NOT_FOUND.into() || e == ERROR_PATH_NOT_FOUND.into() {
                        return Ok(());
                    }
                    return Err(format!(
                        "Failed to open registry key '{}': {:?}",
                        key_path, e
                    ));
                }
            }

            let value_w = to_wide(value_name);
            let delete_result = RegDeleteValueW(hkey, PCWSTR::from_raw(value_w.as_ptr())).ok();
            let _ = RegCloseKey(hkey);

            match delete_result {
                Ok(_) => Ok(()),
                Err(e) => {
                    if e == ERROR_FILE_NOT_FOUND.into() {
                        Ok(())
                    } else {
                        Err(format!(
                            "Failed to delete registry value '{}': {:?}",
                            value_name, e
                        ))
                    }
                }
            }
        }
    }
}

impl Default for WindowsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn to_wide(input: &str) -> Vec<u16> {
    OsStr::new(input)
        .encode_wide()
        .chain(iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str = "Software\\QuickProbe\\Tests\\Autostart";
    const TEST_VALUE: &str = "SampleValue";

    #[test]
    fn write_and_delete_string_roundtrip() {
        let registry = WindowsRegistry::new();

        registry
            .write_string(TEST_KEY, TEST_VALUE, "hello-world")
            .expect("write string");

        assert!(registry
            .value_exists(TEST_KEY, TEST_VALUE)
            .expect("value exists"));

        registry
            .delete_value(TEST_KEY, TEST_VALUE)
            .expect("delete value");

        assert!(!registry
            .value_exists(TEST_KEY, TEST_VALUE)
            .expect("value removed"));

        cleanup_test_key(TEST_KEY);
    }

    fn cleanup_test_key(key_path: &str) {
        // SAFETY: This test cleanup deletes only the test key created under HKCU.
        unsafe {
            use windows::Win32::System::Registry::RegDeleteTreeW;

            let key_path_w = to_wide(key_path);
            let _ = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR::from_raw(key_path_w.as_ptr()));
        }
    }
}
