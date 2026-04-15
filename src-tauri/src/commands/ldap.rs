//! Active Directory / LDAP scanning commands.

use ldap3::{LdapConnAsync, Scope, SearchEntry};
use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

use quickprobe::models::CredentialProfile;
use quickprobe::platform::WindowsCredentialManager;
use quickprobe::CredentialStore;

use super::helpers::normalize_host_name;
use super::hosts::*;
use super::state::clear_session_cache;
use super::types::*;

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

/// Scan Active Directory for Windows hosts and merge into the hosts database using LDAP (no PowerShell)
#[tauri::command]
pub(crate) async fn scan_domain(
    domain: Option<String>,
    server: Option<String>,
    skip_delete: Option<bool>,
    include_windows_clients: Option<bool>,
) -> Result<ScanResult, String> {
    let start = SystemTime::now();
    let domain = domain.unwrap_or_default().trim().to_string();
    let server = server.unwrap_or_default().trim().to_string();
    let skip_delete = skip_delete.unwrap_or(false);
    let include_windows_clients = include_windows_clients.unwrap_or(false);

    crate::logger::log_info(&format!(
        "scan_domain: domain='{}' dc='{}' skip_delete={} include_windows_clients={}",
        domain, server, skip_delete, include_windows_clients
    ));

    if domain.is_empty() {
        return Err("Domain is required".to_string());
    }
    if server.is_empty() {
        return Err("Domain controller is required".to_string());
    }

    // Retrieve stored credentials
    let credential_store = WindowsCredentialManager::new();
    let profile = CredentialProfile::default();

    let credentials = credential_store
        .retrieve(&profile)
        .await
        .map_err(|e| format!("Failed to retrieve credentials: {}", e))?
        .ok_or_else(|| "No credentials stored. Please log in first.".to_string())?;

    let username = credentials.username().as_str();
    let password = credentials.password().as_str();

    let discovered = ldap_search_windows_servers(
        &domain,
        &server,
        username,
        password,
        include_windows_clients,
    )
    .await?;
    let discovered_count = discovered.len();
    crate::logger::log_debug(&format!("scan_domain: LDAP found {}", discovered_count));

    let discovered_keys: HashSet<String> = discovered
        .iter()
        .filter_map(|entry| normalize_host_name(&entry.fqdn).ok())
        .map(|n| n.to_lowercase())
        .collect();

    // Merge with existing hosts while preserving notes/services
    let existing = get_hosts().await?;
    let existing_windows: HashSet<String> = existing
        .iter()
        .filter(|h| {
            h.os_type
                .as_ref()
                .map(|os| !os.eq_ignore_ascii_case("linux"))
                .unwrap_or(true)
        })
        .filter_map(|h| normalize_host_name(&h.name).ok())
        .map(|n| n.to_lowercase())
        .collect();

    let created = discovered_keys.difference(&existing_windows).count();

    let mut merged = merge_hosts(existing, discovered, !skip_delete)?;

    let mut removed = 0usize;
    if !skip_delete {
        let discovered_lower: HashSet<String> = discovered_keys.iter().cloned().collect();

        let before = merged.len();
        merged.retain(|h| {
            let is_windows = h
                .os_type
                .as_ref()
                .map(|os| !os.eq_ignore_ascii_case("linux"))
                .unwrap_or(true);
            if !is_windows {
                return true;
            }
            match normalize_host_name(&h.name) {
                Ok(name) => discovered_lower.contains(&name.to_lowercase()),
                Err(_) => true,
            }
        });
        removed = existing_windows
            .difference(&discovered_keys)
            .count()
            .max(before.saturating_sub(merged.len()));
        crate::logger::log_debug(&format!("scan_domain: {} hosts removed", removed));
    }

    persist_hosts(&merged)?;
    // Scan may add/remove many hosts; clear cached sessions so probes align with new inventory.
    clear_session_cache().await;

    let elapsed_ms = start.elapsed().unwrap_or_default().as_millis();
    crate::logger::log_info(&format!(
        "scan_domain: SUCCESS {}ms found={} created={} removed={} total={}",
        elapsed_ms,
        discovered_count,
        created,
        removed,
        merged.len()
    ));

    Ok(ScanResult {
        found: discovered_count,
        total: merged.len(),
        created,
        removed,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format a domain like "contoso.com" into "DC=contoso,DC=com"
fn format_base_dn(domain: &str) -> Result<String, String> {
    let parts: Vec<&str> = domain.split('.').filter(|p| !p.trim().is_empty()).collect();
    if parts.is_empty() {
        return Err("Domain is required".to_string());
    }
    Ok(parts
        .into_iter()
        .map(|p| format!("DC={}", p))
        .collect::<Vec<String>>()
        .join(","))
}

fn build_bind_username(username: &str, domain: &str) -> String {
    if username.contains('@') || username.contains('\\') {
        username.to_string()
    } else {
        format!("{}@{}", username, domain)
    }
}

pub(crate) fn ldap_windows_filter(include_windows_clients: bool) -> &'static str {
    if include_windows_clients {
        "(&(objectClass=computer)(operatingSystem=Windows*))"
    } else {
        "(&(objectClass=computer)(operatingSystem=Windows Server*))"
    }
}

fn ldap_attr_first_nonempty(attrs: &HashMap<String, Vec<String>>, key: &str) -> Option<String> {
    attrs.get(key).and_then(|vals| {
        vals.iter()
            .map(|v| v.trim())
            .find(|v| !v.is_empty())
            .map(|v| v.to_string())
    })
}

pub(crate) fn ldap_host_identifier(attrs: &HashMap<String, Vec<String>>) -> Option<String> {
    // Prefer FQDN, then fall back to AD computer name if DNS host is not yet populated.
    ldap_attr_first_nonempty(attrs, "dNSHostName")
        .or_else(|| ldap_attr_first_nonempty(attrs, "name"))
        .or_else(|| ldap_attr_first_nonempty(attrs, "cn"))
}

async fn ldap_search_windows_servers(
    domain: &str,
    server: &str,
    username: &str,
    password: &str,
    include_windows_clients: bool,
) -> Result<Vec<AdComputer>, String> {
    let base_dn = format_base_dn(domain)?;
    let url = format!("ldap://{}:389", server);

    let (conn, mut ldap) = LdapConnAsync::new(&url)
        .await
        .map_err(|e| format!("Failed to connect LDAP: {}", e))?;
    ldap3::drive!(conn);

    let bind_user = build_bind_username(username, domain);
    ldap.simple_bind(&bind_user, password)
        .await
        .map_err(|e| format!("LDAP bind failed: {}", e))?
        .success()
        .map_err(|e| format!("LDAP bind rejected: {}", e))?;

    let filter = ldap_windows_filter(include_windows_clients);
    let attrs = vec![
        "dNSHostName",
        "name",
        "cn",
        "description",
        "operatingSystem",
    ];
    let (entries, _res) = ldap
        .search(&base_dn, Scope::Subtree, filter, attrs)
        .await
        .map_err(|e| format!("LDAP search failed: {}", e))?
        .success()
        .map_err(|e| format!("LDAP search error: {}", e))?;

    let mut computers = Vec::new();
    let mut seen = HashSet::new();

    for entry in entries {
        let se = SearchEntry::construct(entry);
        let host = match ldap_host_identifier(&se.attrs) {
            Some(h) => h,
            None => continue,
        };

        // Deduplicate using normalized host keys so FQDN/short-name forms collapse.
        let key = match normalize_host_name(&host) {
            Ok(n) => n.to_lowercase(),
            Err(_) => continue,
        };
        if !seen.insert(key) {
            continue;
        }

        let description = se
            .attrs
            .get("description")
            .and_then(|vals| vals.first())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        computers.push(AdComputer {
            fqdn: host,
            description,
        });
    }

    ldap.unbind().await.ok();

    computers.sort_by(|a, b| a.fqdn.to_lowercase().cmp(&b.fqdn.to_lowercase()));
    if computers.is_empty() {
        let scope = if include_windows_clients {
            "Windows hosts"
        } else {
            "Windows Server hosts"
        };
        return Err(format!("No {} found", scope));
    }
    Ok(computers)
}

/// Merges Active Directory discovered computers with existing host inventory.
///
/// ## Merge Strategy
///
/// This function performs a three-way merge:
/// 1. **Linux hosts** from existing inventory are preserved (AD doesn't contain Linux)
/// 2. **Windows hosts found in AD** are updated:
///    - User-provided `notes` and `group` are preserved (not overwritten by AD description)
///    - AD description is used only if notes are empty
///    - Services list is preserved from existing inventory
/// 3. **New Windows hosts from AD** are added with AD description as initial notes
/// 4. **Windows hosts removed from AD**:
///    - If `remove_missing_windows = false`: Preserved (default, safer)
///    - If `remove_missing_windows = true`: Removed from inventory
pub(crate) fn merge_hosts(
    existing: Vec<ServerInfo>,
    discovered: Vec<AdComputer>,
    remove_missing_windows: bool,
) -> Result<Vec<HostUpdate>, String> {
    let mut existing_map = std::collections::HashMap::new();
    let mut merged: Vec<HostUpdate> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for host in existing {
        let normalized_name = normalize_host_name(&host.name)?;
        let key = normalized_name.to_lowercase();
        let os_label = host
            .os_type
            .clone()
            .unwrap_or_else(|| "Windows".to_string());
        let is_windows = !os_label.eq_ignore_ascii_case("linux");

        if is_windows {
            // keep the first occurrence after normalization
            existing_map.entry(key).or_insert(host);
        } else if seen.insert(key.clone()) {
            merged.push(HostUpdate {
                name: normalized_name,
                notes: host.notes,
                group: host.group,
                services: host.services,
                os_type: Some(os_label),
            });
        }
    }

    for entry in discovered {
        let normalized_name = normalize_host_name(&entry.fqdn)?;
        let key = normalized_name.to_lowercase();
        if !seen.insert(key.clone()) {
            continue;
        }

        if let Some(existing) = existing_map.get(&key) {
            merged.push(HostUpdate {
                name: normalized_name,
                notes: existing
                    .notes
                    .clone()
                    .or_else(|| entry.description.clone())
                    .or_else(|| Some("No Description Specified".to_string())),
                group: existing.group.clone(),
                services: existing.services.clone(),
                os_type: existing
                    .os_type
                    .clone()
                    .or_else(|| Some("Windows".to_string())),
            });
        } else {
            let notes = entry
                .description
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "No Description Specified".to_string());

            merged.push(HostUpdate {
                name: normalized_name,
                notes: Some(notes),
                group: None,
                services: None,
                os_type: Some("Windows".to_string()),
            });
        }
    }

    if !remove_missing_windows {
        for (key, host) in existing_map.into_iter() {
            if seen.contains(&key) {
                continue;
            }
            let normalized_name = normalize_host_name(&host.name)?;
            merged.push(HostUpdate {
                name: normalized_name,
                notes: host.notes.clone(),
                group: host.group.clone(),
                services: host.services.clone(),
                os_type: host.os_type.clone().or_else(|| Some("Windows".to_string())),
            });
        }
    }

    Ok(merged)
}
