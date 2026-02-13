//! Input normalisation helpers for host names, service names, and OS types.
//!
//! Every user-supplied string passes through one of these functions before
//! reaching the database, ensuring a single canonical representation
//! (uppercase, trimmed, deduplicated) across the application.

use std::collections::HashSet;

/// Normalise a server name: trim whitespace, strip FQDN domain, and uppercase.
///
/// Returns an error if the resulting name is empty.
pub fn normalize_server_name(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Host name cannot be empty".to_string());
    }

    let short = trimmed.split('.').next().unwrap_or(trimmed).trim();
    if short.is_empty() {
        return Err("Host name cannot be empty".to_string());
    }

    Ok(short.to_uppercase())
}

/// Normalise a single Windows/Linux service name.
///
/// Trims whitespace, enforces a 64-character limit, validates allowed characters
/// (`A-Z 0-9 - _ $ <space>`), and uppercases the result.
pub fn normalize_service_name(raw: &str) -> Result<String, String> {
    const MAX_LEN: usize = 64;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Service name cannot be empty".to_string());
    }

    if trimmed.len() > MAX_LEN {
        return Err(format!(
            "Service name '{}' exceeds {} characters",
            trimmed, MAX_LEN
        ));
    }

    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '$' || c == ' ')
    {
        return Err(format!(
            "Service name '{}' contains invalid characters (allowed: A-Z, 0-9, '-', '_', '$', space)",
            trimmed
        ));
    }

    Ok(trimmed.to_uppercase())
}

fn normalize_services_iter<I, S>(services: I) -> Result<String, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen = HashSet::new();
    let mut cleaned = Vec::new();
    for svc in services {
        let normalized = normalize_service_name(svc.as_ref())?;
        if seen.insert(normalized.clone()) {
            cleaned.push(normalized);
        }
    }
    Ok(cleaned.join(";"))
}

/// Normalise a semicolon-delimited service list string.
///
/// Splits on `;`, normalises each name, deduplicates, and rejoins with `;`.
#[allow(dead_code)]
pub fn normalize_services(input: &str) -> Result<String, String> {
    normalize_services_iter(input.split(';').map(|s| s.trim()).filter(|s| !s.is_empty()))
}

/// Normalise an iterator of individual service names into a canonical semicolon-separated string.
pub fn normalize_services_list<I, S>(services: I) -> Result<String, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    normalize_services_iter(services)
}

/// Normalise an OS type string to either `"Windows"` or `"Linux"`.
///
/// Defaults to `"Windows"` for empty, missing, or unrecognised values.
pub fn normalize_os_type(input: Option<&str>) -> String {
    let trimmed = input.map(|raw| raw.trim()).unwrap_or("");
    if trimmed.is_empty() {
        return "Windows".to_string();
    }

    let lower = trimmed.to_lowercase();
    match lower.as_str() {
        "windows" | "win" => "Windows".to_string(),
        "linux" | "lin" => "Linux".to_string(),
        _ => "Windows".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_server_name_handles_fqdn_and_whitespace() {
        assert_eq!(normalize_server_name("dc01").unwrap(), "DC01");
        assert_eq!(normalize_server_name("dc01.domain.local").unwrap(), "DC01");
        assert_eq!(normalize_server_name("  dc01  ").unwrap(), "DC01");
        assert!(normalize_server_name("   ").is_err());
    }

    #[test]
    fn normalize_services_trims_dedupes_and_uppercases() {
        let normalized =
            normalize_services("WinRM;dns;DNS;  kdc ").expect("normalize services succeeded");
        assert_eq!(normalized, "WINRM;DNS;KDC");

        let extra_separators = normalize_services(";;WinRM;; ;kdc;;")
            .expect("normalize services with empties succeeded");
        assert_eq!(extra_separators, "WINRM;KDC");
    }

    #[test]
    fn normalize_service_name_allows_spaces() {
        // Windows services can have spaces in their names
        let result = normalize_service_name("Windows Update").expect("service with space");
        assert_eq!(result, "WINDOWS UPDATE");

        let result2 = normalize_service_name("SQL Server Agent").expect("multi-word service");
        assert_eq!(result2, "SQL SERVER AGENT");

        let result3 = normalize_service_name("Print Spooler").expect("another service with space");
        assert_eq!(result3, "PRINT SPOOLER");
    }

    #[test]
    fn normalize_services_handles_names_with_spaces() {
        let normalized =
            normalize_services("Windows Update;Print Spooler;WinRM").expect("services with spaces");
        assert_eq!(normalized, "WINDOWS UPDATE;PRINT SPOOLER;WINRM");
    }

    #[test]
    fn normalize_os_type_defaults_and_maps() {
        assert_eq!(normalize_os_type(None), "Windows");
        assert_eq!(normalize_os_type(Some("")), "Windows");
        assert_eq!(normalize_os_type(Some("   ")), "Windows");
        assert_eq!(normalize_os_type(Some("Linux")), "Linux");
        assert_eq!(normalize_os_type(Some("win")), "Windows");
    }
}
