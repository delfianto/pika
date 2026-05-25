//! Platform capability checks for process memory access.
//!
//! On Linux, verifies that the current process can use `process_vm_readv`
//! by checking Yama ptrace_scope and `CAP_SYS_PTRACE`.

/// Result of the platform readiness check.
#[derive(Debug)]
pub struct PlatformCheck {
    pub can_scan: bool,
    pub warnings: Vec<String>,
}

/// Check whether pika can access other processes' memory on this platform.
///
/// On Linux: checks `/proc/sys/kernel/yama/ptrace_scope` and whether
/// the current process has `CAP_SYS_PTRACE`.
///
/// On non-Linux: returns a warning that real scanning is unavailable.
#[cfg(target_os = "linux")]
pub fn check_platform() -> PlatformCheck {
    let mut warnings = Vec::new();

    // 1. Check ptrace_scope
    let ptrace_scope = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();

    // 2. Check if running as root
    let is_root = nix::unistd::geteuid().is_root();

    // 3. Check for CAP_SYS_PTRACE capability
    let has_cap = check_cap_sys_ptrace();

    match ptrace_scope.as_str() {
        "0" => {
            // Classic mode: same-UID access is unrestricted
            // No warnings needed
        }
        "1" => {
            // Restricted: need CAP_SYS_PTRACE or parent relationship
            if !is_root && !has_cap {
                warnings.push(format!(
                    "ptrace_scope=1 (restricted). pika needs CAP_SYS_PTRACE to scan.\n\
                     Fix with:  sudo setcap cap_sys_ptrace=eip {}\n\
                     Or:        sudo sysctl kernel.yama.ptrace_scope=0",
                    std::env::current_exe()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|_| "pika".to_string())
                ));
            }
        }
        "2" => {
            if !is_root && !has_cap {
                warnings.push(
                    "ptrace_scope=2 (admin-only). CAP_SYS_PTRACE is required.\n\
                     Fix with:  sudo setcap cap_sys_ptrace=eip $(which pika)"
                        .to_string(),
                );
            }
        }
        "3" => {
            warnings.push(
                "ptrace_scope=3 (no-attach). Memory scanning is completely disabled \
                 by the kernel. A reboot with a different setting is required."
                    .to_string(),
            );
        }
        "unknown" => {
            // Yama not loaded (some minimal kernels) — likely permissive
        }
        other => {
            warnings.push(format!("unexpected ptrace_scope value: {other}"));
        }
    }

    // 4. Check /proc is mounted (sanity)
    if !std::path::Path::new("/proc/self/maps").exists() {
        warnings.push("/proc is not mounted. pika requires procfs.".to_string());
    }

    let can_scan = warnings.is_empty();
    PlatformCheck { can_scan, warnings }
}

/// Attempt to detect CAP_SYS_PTRACE on the current process.
///
/// Reads `/proc/self/status` and checks the CapEff bitmask.
/// `CAP_SYS_PTRACE` is capability bit 19.
#[cfg(target_os = "linux")]
fn check_cap_sys_ptrace() -> bool {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return false,
    };

    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:\t") {
            let hex = hex.trim();
            if let Ok(caps) = u64::from_str_radix(hex, 16) {
                // CAP_SYS_PTRACE = bit 19
                return caps & (1 << 19) != 0;
            }
        }
    }

    false
}

#[cfg(not(target_os = "linux"))]
pub fn check_platform() -> PlatformCheck {
    PlatformCheck {
        can_scan: false,
        warnings: vec![
            "Not running on Linux. Memory scanning requires Linux with process_vm_readv.\n\
             pika is running in mock mode (no real process access)."
                .to_string(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_check_returns_result() {
        let check = check_platform();
        // On any platform, the check should run without panicking
        // and return a valid struct
        assert!(!check.warnings.is_empty() || check.can_scan);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cap_sys_ptrace_check_does_not_panic() {
        // Just verify it doesn't crash -- actual result depends on environment
        let _ = check_cap_sys_ptrace();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_reports_mock_mode() {
        let check = check_platform();
        assert!(!check.can_scan);
        assert!(check.warnings[0].contains("Not running on Linux"));
    }
}
