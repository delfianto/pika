use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Information about a discovered Wine/Proton game process.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
}

/// Wine infrastructure process names that should be excluded from game search.
const WINE_INFRASTRUCTURE: &[&str] = &[
    "services.exe",
    "winedevice.exe",
    "explorer.exe",
    "plugplay.exe",
    "svchost.exe",
    "conhost.exe",
    "rpcss.exe",
    "tabtip.exe",
    "start.exe",
    "winedbg.exe",
    "winemenubuilder.exe",
    "steam.exe",
    "xalia.exe",
    "crashpad_handler.exe",
    "steamwebhelper.exe",
];

/// Check if a process name is a known Wine/Proton infrastructure process.
#[must_use]
pub fn is_wine_infrastructure(name: &str) -> bool {
    let name_lower = name.to_ascii_lowercase();
    WINE_INFRASTRUCTURE
        .iter()
        .any(|infra| name_lower.ends_with(infra))
}

/// Check if a binary path looks like a Wine loader/preloader.
/// This is how we distinguish actual Wine-hosted processes from Linux processes
/// that merely have `.exe` somewhere in their command line arguments.
#[must_use]
pub fn is_wine_binary(exe_path: &str) -> bool {
    let basename = exe_path.rsplit('/').next().unwrap_or(exe_path);
    matches!(
        basename,
        "wine" | "wine64" | "wine-preloader" | "wine64-preloader"
    )
}

/// Extract the .exe filename from a cmdline string.
/// Only considers the FIRST argument (argv[0]) — the actual program being run.
/// This prevents matching `.exe` paths that appear as arguments to launcher processes
/// like systemd-inhibit, reaper, pressure-vessel, python3, etc.
#[must_use]
pub fn extract_exe_name(cmdline: &str) -> Option<String> {
    // /proc/[pid]/cmdline is NUL-separated. argv[0] is the first segment.
    let argv0 = cmdline.split('\0').next().unwrap_or(cmdline);

    // For Wine processes, argv[0] is typically the full Windows-style or Unix path
    // to the .exe, e.g.:
    //   "C:\\path\\to\\Game.exe"
    //   "/home/user/.steam/.../Game.exe"
    //   "\\?\Z:\home\user\...\xalia.exe"  (Proton Z: drive mapping)
    if !argv0.to_ascii_lowercase().ends_with(".exe") {
        return None;
    }

    let filename = argv0.rsplit(['/', '\\']).next().unwrap_or(argv0);
    Some(filename.to_string())
}

/// List all Wine/Proton game processes.
///
/// Only returns processes that are actually hosted by Wine (verified by checking
/// that `/proc/[pid]/exe` points to a Wine binary like `wine-preloader`).
/// Excludes known Wine infrastructure (services.exe, explorer.exe, etc.).
#[cfg(target_os = "linux")]
pub fn list_wine_processes() -> Result<Vec<ProcessInfo>> {
    let mut processes = Vec::new();

    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only numeric directories (PIDs)
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Check /proc/[pid]/exe — must point to a Wine binary
        let exe_link = format!("/proc/{pid}/exe");
        let real_exe = match std::fs::read_link(&exe_link) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => continue, // permission denied or process exited
        };

        if !is_wine_binary(&real_exe) {
            continue;
        }

        // Read cmdline — the .exe name comes from argv[0]
        let cmdline_path = format!("/proc/{pid}/cmdline");
        let cmdline = match std::fs::read_to_string(&cmdline_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Extract .exe name from argv[0] only
        let exe_name = match extract_exe_name(&cmdline) {
            Some(name) => name,
            None => continue,
        };

        // Skip Wine infrastructure
        if is_wine_infrastructure(&exe_name) {
            continue;
        }

        processes.push(ProcessInfo {
            pid,
            name: exe_name,
            exe_path: cmdline.replace('\0', " ").trim().to_string(),
        });
    }

    Ok(processes)
}

#[cfg(not(target_os = "linux"))]
pub fn list_wine_processes() -> Result<Vec<ProcessInfo>> {
    Ok(Vec::new())
}

/// Find a Wine/Proton game process by name substring.
#[cfg(target_os = "linux")]
pub fn find_process(name_substr: &str) -> Result<Vec<ProcessInfo>> {
    let all = list_wine_processes()?;
    let lower = name_substr.to_ascii_lowercase();
    Ok(all
        .into_iter()
        .filter(|p| p.name.to_ascii_lowercase().contains(&lower))
        .collect())
}

#[cfg(not(target_os = "linux"))]
pub fn find_process(_name_substr: &str) -> Result<Vec<ProcessInfo>> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── extract_exe_name (argv[0] only) ────────────────────────────────

    #[test]
    fn extract_from_wine_windows_path() {
        // Wine argv[0] with Windows-style path
        let cmdline = "C:\\Program Files\\Game\\Game.exe\0--fullscreen\0-dx11";
        assert_eq!(extract_exe_name(cmdline), Some("Game.exe".to_string()));
    }

    #[test]
    fn extract_from_wine_unix_path() {
        // Wine argv[0] with Unix path (common in Proton)
        let cmdline = "/home/user/.steam/compatdata/12345/pfx/drive_c/game/Game.exe\0--arg";
        assert_eq!(extract_exe_name(cmdline), Some("Game.exe".to_string()));
    }

    #[test]
    fn extract_from_proton_z_drive() {
        // Proton Z: drive mapping style
        let cmdline = "\\\\?\\Z:\\home\\geist\\.local\\share\\Steam\\xalia.exe\0";
        assert_eq!(extract_exe_name(cmdline), Some("xalia.exe".to_string()));
    }

    #[test]
    fn rejects_launcher_with_exe_in_args() {
        // systemd-inhibit has .exe in args but argv[0] is not an .exe
        let cmdline = "systemd-inhibit\0--why\0game-running\0/path/to/proton\0waitforexitandrun\0/path/to/Game.exe";
        assert_eq!(extract_exe_name(cmdline), None);
    }

    #[test]
    fn rejects_python_proton_launcher() {
        // python3 running the Proton script — .exe is in args, not argv[0]
        let cmdline = "python3\0/path/to/proton\0waitforexitandrun\0/path/to/Game.exe";
        assert_eq!(extract_exe_name(cmdline), None);
    }

    #[test]
    fn rejects_reaper_with_exe_in_args() {
        let cmdline = "/home/user/.steam/ubuntu12_32/reaper\0SteamLaunch\0AppId=12345\0--\0/path/to/Game.exe";
        assert_eq!(extract_exe_name(cmdline), None);
    }

    #[test]
    fn rejects_pressure_vessel() {
        let cmdline = "/path/to/srt-bwrap\0--args\026\0/path/to/pv-adverb\0--\0/path/to/proton\0waitforexitandrun\0/path/to/Game.exe";
        assert_eq!(extract_exe_name(cmdline), None);
    }

    #[test]
    fn extract_none_without_exe() {
        let cmdline = "/usr/bin/wineserver\0--foreground";
        assert_eq!(extract_exe_name(cmdline), None);
    }

    #[test]
    fn extract_case_insensitive() {
        let cmdline = "C:\\GAME\\GAME.EXE\0";
        assert_eq!(extract_exe_name(cmdline), Some("GAME.EXE".to_string()));
    }

    // ─── is_wine_binary ─────────────────────────────────────────────────

    #[test]
    fn wine_binary_detection() {
        assert!(is_wine_binary("/usr/bin/wine"));
        assert!(is_wine_binary("/usr/bin/wine64"));
        assert!(is_wine_binary("/path/to/proton/files/bin/wine-preloader"));
        assert!(is_wine_binary("/path/to/proton/files/bin/wine64-preloader"));
        assert!(!is_wine_binary("/usr/bin/python3"));
        assert!(!is_wine_binary("/usr/bin/systemd-inhibit"));
        assert!(!is_wine_binary("/usr/bin/reaper"));
        assert!(!is_wine_binary("/usr/bin/wineserver")); // server, not a hosted process
    }

    // ─── is_wine_infrastructure ─────────────────────────────────────────

    #[test]
    fn wine_infrastructure_detection() {
        assert!(is_wine_infrastructure("services.exe"));
        assert!(is_wine_infrastructure("explorer.exe"));
        assert!(is_wine_infrastructure("steam.exe"));
        assert!(is_wine_infrastructure("xalia.exe"));
        assert!(!is_wine_infrastructure("Game.exe"));
        assert!(!is_wine_infrastructure("Avowed-Win64-Shipping.exe"));
    }
}
