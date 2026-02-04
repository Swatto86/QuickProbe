//! Auto-update functionality for QuickProbe.
//!
//! Provides commands to check for updates from GitHub releases and initiate
//! the update process.

use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

/// GitHub repository owner
const GITHUB_OWNER: &str = "Swatto86";
/// GitHub repository name  
const GITHUB_REPO: &str = "QuickProbe";

/// Information about an available update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    /// Whether an update is available
    pub available: bool,
    /// The latest version available (e.g., "1.2.0")
    pub version: String,
    /// Release notes/body from the GitHub release
    pub body: String,
    /// Current application version
    pub current_version: String,
    /// URL to the GitHub release page
    pub release_url: String,
    /// URL to download the installer directly (MSI or setup.exe)
    pub installer_url: Option<String>,
}

/// Response from GitHub releases API
#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    body: Option<String>,
    html_url: String,
    assets: Vec<GitHubAsset>,
}

/// Asset attached to a GitHub release
#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

/// Parse a semantic version string into (major, minor, patch) tuple.
fn parse_semver(version: &str) -> Option<(u32, u32, u32)> {
    // Strip leading 'v' if present
    let v = version.strip_prefix('v').unwrap_or(version);
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    let major = parts[0].parse::<u32>().ok()?;
    let minor = parts[1].parse::<u32>().ok()?;
    let patch = parts[2].parse::<u32>().ok()?;

    Some((major, minor, patch))
}

/// Compare two semantic versions. Returns:
/// - `1` if a > b
/// - `-1` if a < b  
/// - `0` if a == b
fn compare_versions(a: &str, b: &str) -> i32 {
    let a_parts = match parse_semver(a) {
        Some(p) => p,
        None => return 0,
    };
    let b_parts = match parse_semver(b) {
        Some(p) => p,
        None => return 0,
    };

    if a_parts.0 > b_parts.0 {
        return 1;
    }
    if a_parts.0 < b_parts.0 {
        return -1;
    }
    if a_parts.1 > b_parts.1 {
        return 1;
    }
    if a_parts.1 < b_parts.1 {
        return -1;
    }
    if a_parts.2 > b_parts.2 {
        return 1;
    }
    if a_parts.2 < b_parts.2 {
        return -1;
    }

    0
}

/// Find the Windows installer asset from a list of release assets.
/// Prefers .msi files, falls back to *-setup.exe or *.exe.
fn find_installer_asset(assets: &[GitHubAsset]) -> Option<String> {
    // First, look for .msi files
    for asset in assets {
        let name_lower = asset.name.to_lowercase();
        if name_lower.ends_with(".msi") {
            return Some(asset.browser_download_url.clone());
        }
    }

    // Then look for NSIS installers (*-setup.exe or *_setup.exe)
    for asset in assets {
        let name_lower = asset.name.to_lowercase();
        if name_lower.ends_with("-setup.exe") || name_lower.ends_with("_setup.exe") {
            return Some(asset.browser_download_url.clone());
        }
    }

    // Finally, any .exe that isn't a portable version
    for asset in assets {
        let name_lower = asset.name.to_lowercase();
        if name_lower.ends_with(".exe") && !name_lower.contains("portable") {
            return Some(asset.browser_download_url.clone());
        }
    }

    None
}

/// Check for updates by querying the GitHub releases API.
///
/// Returns information about whether an update is available and details
/// about the latest release.
pub async fn check_for_update_impl() -> Result<UpdateInfo, String> {
    let current_version = env!("CARGO_PKG_VERSION");
    let api_url = format!(
        "https://api.github.com/repos/{}/{}/releases/latest",
        GITHUB_OWNER, GITHUB_REPO
    );

    crate::logger::log_info(&format!("Checking for updates at: {}", api_url));

    // Create HTTP client with appropriate headers
    let client = reqwest::Client::builder()
        .user_agent(format!("QuickProbe/{}", current_version))
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // Fetch latest release info
    let response = client
        .get(&api_url)
        .header("Accept", "application/vnd.github.v3+json")
        .send()
        .await
        .map_err(|e| format!("Failed to fetch release info: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        // Handle 404 specifically - usually means no releases exist yet
        if status == reqwest::StatusCode::NOT_FOUND {
            crate::logger::log_info(
                "No releases found on GitHub - repository may not have any published releases yet",
            );
            // Return "no update available" instead of an error when there are no releases
            return Ok(UpdateInfo {
                available: false,
                version: current_version.to_string(),
                body: String::new(),
                current_version: current_version.to_string(),
                release_url: format!(
                    "https://github.com/{}/{}/releases",
                    GITHUB_OWNER, GITHUB_REPO
                ),
                installer_url: None,
            });
        }

        return Err(format!("GitHub API returned error {}: {}", status, body));
    }

    let release: GitHubRelease = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse release JSON: {}", e))?;

    // Extract version from tag (strip 'v' prefix if present)
    let latest_version = release
        .tag_name
        .strip_prefix('v')
        .unwrap_or(&release.tag_name)
        .to_string();

    // Compare versions
    let is_newer = compare_versions(&latest_version, current_version) > 0;

    crate::logger::log_info(&format!(
        "Current version: {}, Latest version: {}, Update available: {}",
        current_version, latest_version, is_newer
    ));

    let installer_url = find_installer_asset(&release.assets);

    Ok(UpdateInfo {
        available: is_newer,
        version: latest_version,
        body: release.body.unwrap_or_default(),
        current_version: current_version.to_string(),
        release_url: release.html_url,
        installer_url,
    })
}

/// Download the installer and launch it, or open the release page as fallback.
///
/// The installer is downloaded to the system temp directory and then launched.
/// After launching, the application should exit to allow the installer to run.
pub async fn download_and_install_impl(update_info: UpdateInfo) -> Result<(), String> {
    // If we have a direct installer URL, try to download and run it
    if let Some(installer_url) = &update_info.installer_url {
        crate::logger::log_info(&format!("Downloading installer from: {}", installer_url));

        match download_and_launch_installer(installer_url).await {
            Ok(_) => {
                crate::logger::log_info("Installer launched successfully");
                return Ok(());
            }
            Err(e) => {
                crate::logger::log_warn(&format!(
                    "Failed to download/launch installer: {}. Falling back to browser.",
                    e
                ));
            }
        }
    }

    // Fallback: open the release page in the default browser
    crate::logger::log_info(&format!(
        "Opening release page in browser: {}",
        update_info.release_url
    ));

    open_url_in_browser(&update_info.release_url)?;

    Ok(())
}

/// Download an installer from URL and launch it.
async fn download_and_launch_installer(url: &str) -> Result<(), String> {
    let current_version = env!("CARGO_PKG_VERSION");

    // Create HTTP client
    let client = reqwest::Client::builder()
        .user_agent(format!("QuickProbe/{}", current_version))
        .timeout(std::time::Duration::from_secs(300)) // 5 minute timeout for download
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // Start download
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Failed to start download: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Download failed with status: {}",
            response.status()
        ));
    }

    // Determine filename from URL
    let filename = url
        .split('/')
        .next_back()
        .unwrap_or("quickprobe-setup.exe")
        .to_string();

    // Get temp directory
    let temp_dir = env::temp_dir();
    let installer_path: PathBuf = temp_dir.join(&filename);

    crate::logger::log_info(&format!("Downloading to: {}", installer_path.display()));

    // Download the file
    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to download file: {}", e))?;

    // Write to temp file
    std::fs::write(&installer_path, &bytes)
        .map_err(|e| format!("Failed to write installer: {}", e))?;

    crate::logger::log_info(&format!(
        "Download complete ({} bytes). Launching installer...",
        bytes.len()
    ));

    // Launch the installer using cmd /C start
    // This detaches the process so it continues after we exit
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        const DETACHED_PROCESS: u32 = 0x00000008;

        std::process::Command::new("cmd")
            .args(["/C", "start", "", installer_path.to_str().unwrap_or("")])
            .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS)
            .spawn()
            .map_err(|e| format!("Failed to launch installer: {}", e))?;
    }

    #[cfg(not(windows))]
    {
        // On non-Windows, just open the file
        open_url_in_browser(installer_path.to_str().unwrap_or(""))?;
    }

    Ok(())
}

/// Open a URL in the default browser.
fn open_url_in_browser(url: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| format!("Failed to open URL: {}", e))?;
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .spawn()
            .map_err(|e| format!("Failed to open URL: {}", e))?;
    }

    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .spawn()
            .map_err(|e| format!("Failed to open URL: {}", e))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_semver() {
        assert_eq!(parse_semver("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_semver("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_semver("0.0.1"), Some((0, 0, 1)));
        assert_eq!(parse_semver("10.20.30"), Some((10, 20, 30)));
        assert_eq!(parse_semver("invalid"), None);
        assert_eq!(parse_semver("1.2"), None);
        assert_eq!(parse_semver("1.2.3.4"), None);
    }

    #[test]
    fn test_compare_versions() {
        assert_eq!(compare_versions("1.0.0", "1.0.0"), 0);
        assert_eq!(compare_versions("1.0.1", "1.0.0"), 1);
        assert_eq!(compare_versions("1.0.0", "1.0.1"), -1);
        assert_eq!(compare_versions("2.0.0", "1.9.9"), 1);
        assert_eq!(compare_versions("1.9.9", "2.0.0"), -1);
        assert_eq!(compare_versions("v1.2.3", "1.2.3"), 0);
    }
}
