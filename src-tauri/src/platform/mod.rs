//! Platform-specific implementations (Windows host UI, Windows/SSH remote targets)
//!
//! All platform-specific code is isolated here. The Windows UI can still
//! connect to Linux targets over SSH via the LinuxRemoteSession.

pub mod credman;
pub mod registry;
pub mod ssh;
pub mod winrm;

pub use credman::WindowsCredentialManager;
pub use registry::WindowsRegistry;
pub use ssh::LinuxRemoteSession;
pub use winrm::WindowsRemoteSession;
