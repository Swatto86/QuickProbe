//! Core business logic (platform-agnostic)
//!
//! CRITICAL: This module MUST NOT import platform-specific code or UI frameworks.

pub mod credential;
pub mod probes;
pub mod session;
pub mod validation;

// Test utilities for mock sessions (tests only)
#[cfg(test)]
pub mod mock_session;

pub use credential::CredentialStore;
pub use probes::{
    disk_alert_probe, service_health_probe, system_health_probe, DiskAlertResult,
    ReachabilitySummary, ServiceHealthResult, SystemHealthSummary, TcpProbeResult,
};
pub use session::{
    DiskInfo, FirewallProfile, MemoryInfo, NetAdapterInfo, OsInfo, PendingRebootStatus,
    ProbeResult, ProcessInfo, QuickProbeSummary, RecentErrorEntry, RemoteSession, ServiceInfo,
    SessionOs, UptimeSnapshot, WinRmListener,
};
pub use validation::{validate_credentials, validate_credentials_basic};
