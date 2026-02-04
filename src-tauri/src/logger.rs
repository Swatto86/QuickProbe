use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;

struct Logger {
    path: PathBuf,
    verbose: bool,
    enabled: bool,
}

impl Logger {
    fn init() -> Self {
        let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
        let dir = PathBuf::from(base).join("QuickProbe").join("logs");
        let _ = fs::create_dir_all(&dir);

        // Use different log file names for debug vs release
        let filename = if cfg!(debug_assertions) {
            "quickprobe-dev.log"
        } else {
            "quickprobe.log"
        };
        let path = dir.join(filename);

        let verbose = std::env::var("QP_LOG_VERBOSE")
            .map(|v| v == "1")
            .unwrap_or(false);

        // In debug builds, always enable logging
        // In release builds, only enable if QP_ENABLE_LOGGING=1
        let enabled = if cfg!(debug_assertions) {
            true
        } else {
            std::env::var("QP_ENABLE_LOGGING")
                .map(|v| v == "1")
                .unwrap_or(false)
        };

        Self {
            path,
            verbose,
            enabled,
        }
    }

    fn rotate_if_needed(&self) {
        if let Ok(meta) = fs::metadata(&self.path) {
            if meta.len() > MAX_LOG_BYTES {
                let backup = self.path.with_extension("log.bak");
                let _ = fs::remove_file(&backup);
                let _ = fs::rename(&self.path, &backup);
            }
        }
    }

    fn timestamp() -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        format!("{}", now)
    }

    fn log(&self, level: &str, message: &str) {
        // Only write to file if logging is enabled
        if !self.enabled {
            return;
        }

        self.rotate_if_needed();
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(file, "{} [{}] {}", Self::timestamp(), level, message);
        }
    }
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

fn get_logger() -> Option<&'static Logger> {
    Some(LOGGER.get_or_init(Logger::init))
}

pub fn init_dev_logger() {
    // Initialize logger in all builds
    // In debug: always logs to file
    // In release: only logs to file if QP_ENABLE_LOGGING=1
    let _ = get_logger();
}

pub fn log_debug(message: &str) {
    log_internal("DEBUG", message, false);
}

#[allow(dead_code)]
pub fn log_debug_verbose(message: &str) {
    if let Some(logger) = get_logger() {
        if logger.verbose {
            log_internal("DEBUG", message, true);
        }
    }
}

pub fn log_info(message: &str) {
    log_internal("INFO", message, false);
}

pub fn log_warn(message: &str) {
    log_internal("WARN", message, false);
}

pub fn log_error(message: &str) {
    log_internal("ERROR", message, false);
}

fn log_internal(level: &str, message: &str, verbose_only: bool) {
    // Console logging - always enabled in debug builds
    // Use eprintln! (stderr) for immediate, unbuffered output in dev mode
    #[cfg(debug_assertions)]
    {
        // In dev mode, print all messages to console (including verbose)
        // unless verbose is required and QP_LOG_VERBOSE is not set
        let should_print = if verbose_only {
            get_logger().map(|l| l.verbose).unwrap_or(false)
        } else {
            true
        };

        if should_print {
            eprintln!("[{}] {}", level, message);
        }
    }

    // File logging (enabled in debug, or release with QP_ENABLE_LOGGING=1)
    if let Some(logger) = get_logger() {
        if !verbose_only || logger.verbose {
            logger.log(level, message);
        }
    }
}
