//! Session pool, credential resolution, OS type detection, and connection management.

use quickprobe::constants::*;
use quickprobe::core::session::{OsInfo, RemoteSession};
use quickprobe::core::SystemHealthSummary;
use quickprobe::models::{CredentialProfile, Credentials};
use quickprobe::platform::{LinuxRemoteSession, WindowsCredentialManager, WindowsRemoteSession};
use quickprobe::CredentialStore;
use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;
use tokio::sync::RwLock;

use super::helpers::normalize_host_name;
use super::hosts::read_hosts_from_sqlite;

// ---------------------------------------------------------------------------
// Session pool: cache WindowsRemoteSession per server to avoid redundant
// credential resolution and construction on every heartbeat/probe cycle.
// ---------------------------------------------------------------------------

/// Maximum age of a cached session before it is evicted (seconds).
pub(crate) const SESSION_CACHE_TTL_SECS: u64 = 300; // 5 minutes

pub(crate) struct CachedSession {
    pub session: Arc<WindowsRemoteSession>,
    pub created_at: SystemTime,
}

/// Global session pool keyed by normalised server name.
pub(crate) fn session_pool() -> &'static RwLock<HashMap<String, CachedSession>> {
    static POOL: OnceLock<RwLock<HashMap<String, CachedSession>>> = OnceLock::new();
    POOL.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Remove a specific server from the session cache (e.g. after credential changes).
pub(crate) async fn invalidate_session_cache(server_name: &str) {
    let key = server_name.to_ascii_lowercase();
    session_pool().write().await.remove(&key);
}

/// Clear the entire session cache.
#[allow(dead_code)]
pub(crate) async fn clear_session_cache() {
    session_pool().write().await.clear();
}

/// Sanitize TCP port list ensuring uniqueness and valid range.
pub(crate) fn sanitize_tcp_ports(ports: &[u16]) -> Vec<u16> {
    let mut seen = std::collections::HashSet::new();
    let mut cleaned = Vec::new();
    for &p in ports {
        if p == 0 {
            continue;
        }
        if seen.insert(p) {
            cleaned.push(p);
        }
    }
    if cleaned.is_empty() {
        cleaned.extend_from_slice(DEFAULT_TCP_PORTS);
    }
    cleaned
}

// ---------------------------------------------------------------------------
// Credential resolution
// ---------------------------------------------------------------------------

pub(crate) fn build_rdp_profile_candidates(server: &str) -> Vec<CredentialProfile> {
    let mut profiles = Vec::new();
    let trimmed = server.trim();
    if trimmed.is_empty() {
        return profiles;
    }

    let (host_no_port, port_opt) = trimmed
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
        .map(|(host, port)| (host, Some(port)))
        .unwrap_or((trimmed, None));

    let short = host_no_port.split('.').next().unwrap_or(host_no_port);

    let mut seen = HashSet::new();
    let push_profile =
        |target: String, seen: &mut HashSet<String>, profiles: &mut Vec<CredentialProfile>| {
            if seen.insert(target.clone()) {
                profiles.push(CredentialProfile::new(target));
            }
        };

    push_profile(format!("TERMSRV/{}", trimmed), &mut seen, &mut profiles);

    if let Some(port) = port_opt {
        push_profile(
            format!("TERMSRV/{}:{}", host_no_port, port),
            &mut seen,
            &mut profiles,
        );
    }

    if host_no_port != trimmed {
        push_profile(
            format!("TERMSRV/{}", host_no_port),
            &mut seen,
            &mut profiles,
        );
    }

    push_profile(
        format!("TERMSRV/{}:3389", host_no_port),
        &mut seen,
        &mut profiles,
    );

    if short != host_no_port {
        push_profile(format!("TERMSRV/{}", short), &mut seen, &mut profiles);
        push_profile(format!("TERMSRV/{}:3389", short), &mut seen, &mut profiles);
    }

    profiles
}

pub(crate) async fn resolve_host_credentials_with_store(
    store: &impl CredentialStore,
    server_name: &str,
) -> Result<(Credentials, String), String> {
    let normalized = normalize_host_name(server_name)?;
    let host_profile = CredentialProfile::new(format!("QuickProbe:HOST/{}", normalized));

    // First try host-specific credentials
    if let Some(creds) = store
        .retrieve(&host_profile)
        .await
        .map_err(|e| format!("Failed to retrieve credentials: {}", e))?
    {
        crate::logger::log_debug(&format!(
            "resolve_credentials: using host-specific creds for '{}' (profile: {})",
            server_name,
            host_profile.as_str()
        ));
        return Ok((creds, host_profile.as_str().to_string()));
    }

    // Fall back to RDP/TERMSRV profiles
    let mut picked: Option<(Credentials, String)> = None;
    for profile in build_rdp_profile_candidates(server_name) {
        if let Some(creds) = store
            .retrieve(&profile)
            .await
            .map_err(|e| format!("Failed to retrieve credentials: {}", e))?
        {
            picked = Some((creds, profile.as_str().to_string()));
            break;
        }
    }

    // Fall back to default profile
    if picked.is_none() {
        let default_profile = CredentialProfile::default();
        if let Some(creds) = store
            .retrieve(&default_profile)
            .await
            .map_err(|e| format!("Failed to retrieve credentials: {}", e))?
        {
            picked = Some((creds, default_profile.as_str().to_string()));
        }
    }

    let (creds, used_profile) = picked.ok_or_else(|| {
        format!(
            "No credentials found for '{}'. Tried: {}, TERMSRV/*, QuickProbe:DEFAULT. Please set host credentials or log in.",
            server_name,
            host_profile.as_str()
        )
    })?;

    crate::logger::log_debug(&format!(
        "resolve_credentials: using fallback creds for '{}' (profile: {})",
        server_name, used_profile
    ));

    // Opportunistically store under the host profile for reuse
    if host_profile.as_str() != used_profile {
        let _ = store.store(&host_profile, &creds).await;
    }

    Ok((creds, used_profile))
}

pub(crate) async fn resolve_host_credentials(
    server_name: &str,
) -> Result<(Credentials, String), String> {
    let store = WindowsCredentialManager::new();
    resolve_host_credentials_with_store(&store, server_name).await
}

// ---------------------------------------------------------------------------
// SessionKind — wrapper for Windows / Linux sessions
// ---------------------------------------------------------------------------

/// Wrapper to hold either Windows or Linux remote session
pub(crate) enum SessionKind {
    Windows(Arc<WindowsRemoteSession>),
    Linux(LinuxRemoteSession),
}

impl SessionKind {
    pub fn as_remote(&self) -> &dyn RemoteSession {
        match self {
            SessionKind::Windows(s) => s.as_ref(),
            SessionKind::Linux(s) => s,
        }
    }

    pub fn is_windows(&self) -> bool {
        matches!(self, SessionKind::Windows(_))
    }

    /// Borrow the inner WindowsRemoteSession if this is a Windows session.
    #[allow(dead_code)]
    pub fn as_windows(&self) -> Option<&WindowsRemoteSession> {
        match self {
            SessionKind::Windows(s) => Some(s.as_ref()),
            _ => None,
        }
    }
}

/// Determine the declared OS type for a host (defaults to Windows).
pub(crate) async fn resolve_host_os_type(server_name: &str) -> String {
    let normalized = match normalize_host_name(server_name) {
        Ok(n) => n,
        Err(_) => return "Windows".to_string(),
    };

    if let Ok(hosts) = read_hosts_from_sqlite() {
        for host in hosts {
            if host.name.eq_ignore_ascii_case(&normalized) {
                if let Some(os) = host.os_type {
                    if os.eq_ignore_ascii_case("linux") {
                        return "Linux".to_string();
                    } else if os.eq_ignore_ascii_case("windows") {
                        return "Windows".to_string();
                    }
                }
            }
        }
    }

    "Windows".to_string()
}

/// Connect to a remote session based on host OS.
///
/// For Windows hosts the session is served from a per-server cache so that
/// repeated heartbeat/probe cycles don't pay credential resolution or retry
/// overhead. Cached entries expire after `SESSION_CACHE_TTL_SECS`.
pub(crate) async fn connect_remote_session(
    server_name: String,
    credentials: Credentials,
    os_hint: &str,
) -> Result<SessionKind, String> {
    use quickprobe::utils::{is_transient_error, retry_with_backoff, RetryConfig};

    crate::logger::log_debug(&format!(
        "connect_remote_session: START '{}' os='{}'",
        server_name, os_hint
    ));

    // --- Windows session cache path ---
    if !os_hint.eq_ignore_ascii_case("linux") {
        let cache_key = server_name.to_ascii_lowercase();

        // Check cache (read lock – fast, non-exclusive)
        {
            let pool = session_pool().read().await;
            if let Some(cached) = pool.get(&cache_key) {
                let age = cached.created_at.elapsed().unwrap_or_default().as_secs();
                if age < SESSION_CACHE_TTL_SECS {
                    crate::logger::log_debug_verbose(&format!(
                        "connect_remote_session: CACHE HIT '{}' (age {}s)",
                        server_name, age
                    ));
                    return Ok(SessionKind::Windows(Arc::clone(&cached.session)));
                }
            }
        }

        // Cache miss or stale – create a new session
        let server_clone = server_name.clone();
        let creds_clone = credentials.clone();

        let result = retry_with_backoff(
            RetryConfig::default(),
            || async {
                WindowsRemoteSession::connect(server_clone.clone(), creds_clone.clone()).await
            },
            |err: &String| is_transient_error(err.as_str()),
        )
        .await;

        match result {
            Ok(session) => {
                let arc = Arc::new(session);
                {
                    let mut pool = session_pool().write().await;
                    pool.insert(
                        cache_key,
                        CachedSession {
                            session: Arc::clone(&arc),
                            created_at: SystemTime::now(),
                        },
                    );
                }
                crate::logger::log_debug_verbose(&format!(
                    "connect_remote_session: OK '{}' (cached)",
                    server_name
                ));
                return Ok(SessionKind::Windows(arc));
            }
            Err(e) => {
                crate::logger::log_error(&format!(
                    "connect_remote_session: FAILED '{}': {}",
                    server_name, e
                ));
                return Err(e);
            }
        }
    }

    // --- Linux (SSH) session – not cached (stateful TCP connection) ---
    let server_clone = server_name.clone();
    let creds_clone = credentials.clone();

    let result = retry_with_backoff(
        quickprobe::utils::RetryConfig::default(),
        || async {
            LinuxRemoteSession::connect(server_clone.clone(), creds_clone.clone())
                .await
                .map(SessionKind::Linux)
        },
        |err: &String| quickprobe::utils::is_transient_error(err.as_str()),
    )
    .await;

    match &result {
        Ok(_) => crate::logger::log_debug_verbose(&format!(
            "connect_remote_session: OK '{}'",
            server_name
        )),
        Err(e) => crate::logger::log_error(&format!(
            "connect_remote_session: FAILED '{}': {}",
            server_name, e
        )),
    }

    result
}

// ---------------------------------------------------------------------------
// String helpers used by launchers / credential handling
// ---------------------------------------------------------------------------

/// Escape a string for use with `System.Windows.Forms.SendKeys`.
///
/// Characters that SendKeys interprets as modifiers or grouping (+ ^ % ~ ( ) [ ] { })
/// must be wrapped in braces to be sent as literal keystrokes.
pub(crate) fn escape_sendkeys(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for ch in input.chars() {
        match ch {
            '+' | '^' | '%' | '~' | '(' | ')' | '[' | ']' => {
                out.push('{');
                out.push(ch);
                out.push('}');
            }
            '{' => out.push_str("{{}"),
            '}' => out.push_str("{}}"),
            _ => out.push(ch),
        }
    }
    out
}

pub(crate) fn split_domain_username(raw: &str) -> (String, String) {
    if let Some((domain, user)) = raw.split_once('\\') {
        if !domain.is_empty() && !user.is_empty() {
            return (domain.to_string(), user.to_string());
        }
    }

    if let Some((user, domain)) = raw.split_once('@') {
        if !user.is_empty() && !domain.is_empty() {
            return (domain.to_string(), user.to_string());
        }
    }

    (String::new(), raw.to_string())
}

// ---------------------------------------------------------------------------
// Ping / degraded-summary helpers
// ---------------------------------------------------------------------------

/// Lightweight ping check to see if the host is reachable at the network level.
pub(crate) async fn ping_host(server_name: &str) -> Result<bool, String> {
    #[cfg(windows)]
    use quickprobe::constants::CREATE_NO_WINDOW;

    let host = server_name.to_string();
    let output = tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new("ping");
        cmd.arg("-n").arg("1").arg("-w").arg("800").arg(host);

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        cmd.output()
    })
    .await
    .map_err(|e| format!("Failed to spawn ping: {}", e))?
    .map_err(|e| format!("Ping execution failed: {}", e))?;

    Ok(output.status.success())
}

/// Build a minimal health summary when WinRM is unavailable but the host responds to ping.
pub(crate) async fn degraded_summary_or_error(
    server_name: &str,
    winrm_error: String,
    ping_checked: bool,
    ping_ok: bool,
) -> Result<SystemHealthSummary, String> {
    let reachable = if ping_checked {
        ping_ok
    } else {
        ping_host(server_name).await.unwrap_or(false)
    };

    if reachable {
        Ok(SystemHealthSummary {
            server_name: server_name.to_string(),
            winrm_issue: true,
            winrm_error: Some(winrm_error.clone()),
            os_info: OsInfo {
                hostname: server_name.to_string(),
                os_version: "Unknown".to_string(),
                build_number: "-".to_string(),
                product_type: "WinRM unavailable".to_string(),
                install_date: "-".to_string(),
            },
            disk_alerts: Vec::new(),
            total_disks: 0,
            disks: Vec::new(),
            service_alerts: 0,
            service_status: Vec::new(),
            process_count: 0,
            high_cpu_processes: Vec::new(),
            high_cpu_threshold: 50.0,
            total_memory_mb: 0.0,
            used_memory_mb: 0.0,
            memory_used_percent: 0.0,
            uptime: None,
            pending_reboot: None,
            winrm_listeners: None,
            firewall_profiles: None,
            recent_errors: None,
            net_adapters: None,
            reachability: None,
        })
    } else {
        Err(winrm_error)
    }
}

/// Best-effort minimal health snapshot when the main probe fails.
pub(crate) async fn recover_minimal_health(
    session: &dyn RemoteSession,
) -> Option<SystemHealthSummary> {
    let os_info = session.get_os_info().await.ok()?;
    let memory_info = session.get_memory_info().await.ok();
    let processes = session.get_processes(None).await.ok();

    let (total_memory_mb, used_memory_mb, memory_used_percent) = if let Some(mem) = memory_info {
        let used = (mem.total_mb - mem.free_mb).max(0.0);
        let pct = if mem.total_mb > 0.0 {
            (used / mem.total_mb) * 100.0
        } else {
            0.0
        };
        (mem.total_mb, used, pct)
    } else {
        (0.0, 0.0, 0.0)
    };

    let process_count = processes.as_ref().map(|p| p.len()).unwrap_or(0);

    Some(SystemHealthSummary {
        server_name: os_info.hostname.clone(),
        winrm_issue: true,
        winrm_error: None,
        os_info,
        disk_alerts: Vec::new(),
        total_disks: 0,
        disks: Vec::new(),
        service_alerts: 0,
        service_status: Vec::new(),
        process_count,
        high_cpu_processes: Vec::new(),
        high_cpu_threshold: 50.0,
        total_memory_mb,
        used_memory_mb,
        memory_used_percent,
        uptime: None,
        pending_reboot: None,
        winrm_listeners: None,
        firewall_profiles: None,
        recent_errors: None,
        net_adapters: None,
        reachability: None,
    })
}
