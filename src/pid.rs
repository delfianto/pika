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
];

/// Check if a process name is a known Wine infrastructure process.
#[must_use]
pub fn is_wine_infrastructure(name: &str) -> bool {
    let name_lower = name.to_ascii_lowercase();
    WINE_INFRASTRUCTURE
        .iter()
        .any(|infra| name_lower.ends_with(infra))
}

/// Extract the .exe filename from a cmdline string.
/// Returns `None` if no .exe is found.
#[must_use]
pub fn extract_exe_name(cmdline: &str) -> Option<String> {
    // cmdline may contain: "C:\\path\\to\\Game.exe" or "/path/to/Game.exe" or just "Game.exe"
    // Split by common separators and find the .exe part
    for part in cmdline.split(['\0', ' ']) {
        let part = part.trim();
        if part.to_ascii_lowercase().ends_with(".exe") {
            // Extract just the filename
            let filename = part
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(part);
            return Some(filename.to_string());
        }
    }
    None
}

/// List all Wine/Proton game processes.
/// On non-Linux platforms, returns an empty list.
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

        // Read cmdline
        let cmdline_path = format!("/proc/{pid}/cmdline");
        let cmdline = match std::fs::read_to_string(&cmdline_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Look for .exe in cmdline
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

    #[test]
    fn extract_exe_from_wine_cmdline() {
        let cmdline = "C:\\Program Files\\Game\\Game.exe\0--fullscreen\0-dx11";
        assert_eq!(extract_exe_name(cmdline), Some("Game.exe".to_string()));
    }

    #[test]
    fn extract_exe_from_linux_path() {
        let cmdline = "/home/user/.steam/compatdata/12345/pfx/drive_c/game/Game.exe";
        assert_eq!(extract_exe_name(cmdline), Some("Game.exe".to_string()));
    }

    #[test]
    fn extract_exe_none_without_exe() {
        let cmdline = "/usr/bin/wineserver --foreground";
        assert_eq!(extract_exe_name(cmdline), None);
    }

    #[test]
    fn wine_infrastructure_detection() {
        assert!(is_wine_infrastructure("services.exe"));
        assert!(is_wine_infrastructure("C:\\windows\\system32\\services.exe"));
        assert!(is_wine_infrastructure("explorer.exe"));
        assert!(!is_wine_infrastructure("Game.exe"));
        assert!(!is_wine_infrastructure("DarkSouls3.exe"));
    }

    #[test]
    fn extract_exe_case_insensitive() {
        let cmdline = "C:\\GAME\\GAME.EXE";
        assert_eq!(extract_exe_name(cmdline), Some("GAME.EXE".to_string()));
    }

    #[test]
    fn extract_exe_with_spaces_in_path() {
        // NUL-separated cmdline with spaces in path
        let cmdline = "/path/to/Program Files/My Game.exe\0--arg1";
        // The space splits "My" and "Game.exe", so we should find "Game.exe"
        assert_eq!(extract_exe_name(cmdline), Some("Game.exe".to_string()));
    }
}
