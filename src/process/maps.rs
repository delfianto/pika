use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Safety classification for a memory region.
/// Determines whether scanning and/or writing is allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegionSafety {
    /// Windows heap, PE data sections -- scan and write OK.
    Safe,
    /// PE code sections, read-only data -- scan OK, never write.
    ReadOnly,
    /// DXVK internal heaps, driver data -- scan with low confidence, never write.
    Risky,
    /// GPU driver mappings, wineserver shm, /dev/* -- skip entirely.
    NeverTouch,
}

impl RegionSafety {
    #[must_use]
    pub const fn can_scan(self) -> bool {
        matches!(self, Self::Safe | Self::ReadOnly | Self::Risky)
    }

    #[must_use]
    pub const fn can_write(self) -> bool {
        matches!(self, Self::Safe)
    }
}

/// Parsed permission bits from a `/proc/[pid]/maps` line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    /// `true` = shared (`s`), `false` = private (`p`).
    pub shared: bool,
}

impl Permissions {
    fn parse(s: &str) -> Result<Self> {
        if s.len() < 4 {
            anyhow::bail!("permissions string too short: '{s}'");
        }
        let bytes = s.as_bytes();
        Ok(Self {
            read: bytes[0] == b'r',
            write: bytes[1] == b'w',
            execute: bytes[2] == b'x',
            shared: bytes[3] == b's',
        })
    }

    /// Format string like "rw-p" or "r-xp".
    #[must_use]
    pub fn as_str(&self) -> String {
        format!(
            "{}{}{}{}",
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.execute { 'x' } else { '-' },
            if self.shared { 's' } else { 'p' },
        )
    }
}

/// A single memory region from `/proc/[pid]/maps`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapRegion {
    /// Start address of the region.
    pub start: u64,
    /// End address of the region (exclusive).
    pub end: u64,
    /// Permission bits.
    pub permissions: Permissions,
    /// File offset.
    pub offset: u64,
    /// Device (major:minor).
    pub device: String,
    /// Inode number.
    pub inode: u64,
    /// File path or label (may be empty for anonymous regions).
    pub pathname: String,
    /// Safety classification (computed by `classify_region`).
    pub safety: RegionSafety,
}

impl MapRegion {
    /// Size of the region in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end - self.start
    }

    /// Whether the region is anonymous (no file backing).
    #[must_use]
    pub fn is_anonymous(&self) -> bool {
        self.pathname.is_empty()
    }
}

/// Parse a complete `/proc/[pid]/maps` file content into classified regions.
pub fn parse_maps(content: &str) -> Result<Vec<MapRegion>> {
    content
        .lines()
        .filter(|line| !line.is_empty())
        .map(parse_maps_line)
        .collect()
}

/// Parse a single line from `/proc/[pid]/maps`.
fn parse_maps_line(line: &str) -> Result<MapRegion> {
    // Format: address_start-address_end perms offset dev inode pathname
    // Example: 7f8a00000000-7f8a00010000 rw-s 00000000 00:06 1234 /dev/nvidiactl
    let parts: Vec<&str> = line.splitn(6, ' ').collect();
    if parts.len() < 5 {
        anyhow::bail!("malformed maps line: '{line}'");
    }

    let (addr_start, addr_end) = parts[0]
        .split_once('-')
        .context("missing '-' in address range")?;

    let start = u64::from_str_radix(addr_start, 16)
        .with_context(|| format!("invalid start address: '{addr_start}'"))?;
    let end = u64::from_str_radix(addr_end, 16)
        .with_context(|| format!("invalid end address: '{addr_end}'"))?;
    let permissions = Permissions::parse(parts[1])?;
    let offset = u64::from_str_radix(parts[2], 16)
        .with_context(|| format!("invalid offset: '{}'", parts[2]))?;

    let device = parts[3].to_string();

    // Inode might be followed by spaces and then pathname
    let inode_str = parts[4].trim();
    let (inode_str, extra_path) = if let Some(idx) = inode_str.find(' ') {
        (&inode_str[..idx], inode_str[idx..].trim())
    } else {
        (inode_str, "")
    };
    let inode = inode_str
        .parse::<u64>()
        .with_context(|| format!("invalid inode: '{inode_str}'"))?;

    // Pathname is optional, may be in parts[5] or embedded after inode
    let pathname = if parts.len() > 5 {
        parts[5].trim().to_string()
    } else if !extra_path.is_empty() {
        extra_path.to_string()
    } else {
        String::new()
    };

    let safety = classify_region(&permissions, &pathname, end - start);

    Ok(MapRegion {
        start,
        end,
        permissions,
        offset,
        device,
        inode,
        pathname,
        safety,
    })
}

/// Classify a memory region's safety level based on its permissions, pathname, and size.
///
/// Implements the decision tree from docs/ANALYSIS.md Section 6.1.
/// Order matters: earlier rules take priority.
fn classify_region(perms: &Permissions, path: &str, size: u64) -> RegionSafety {
    let path_lower = path.to_ascii_lowercase();

    // Rule 1: Any shared mapping -> NeverTouch
    // GPU drivers and wineserver communicate via shared memory.
    if perms.shared {
        return RegionSafety::NeverTouch;
    }

    // Rule 2: /dev/* -> NeverTouch (GPU devices, input, sound)
    if path.starts_with("/dev/") {
        return RegionSafety::NeverTouch;
    }

    // Rule 3: /dev/shm/* -> NeverTouch (IPC shared memory)
    // Note: already caught by rule 2, but explicit for clarity
    // This also catches paths like "/dev/shm/wine-*"

    // Rule 4: wineserver -> NeverTouch
    if path_lower.contains("wineserver") {
        return RegionSafety::NeverTouch;
    }

    // Rule 5: No write permission -> ReadOnly
    if !perms.write {
        return RegionSafety::ReadOnly;
    }

    // Rule 6: DXVK / VKD3D / D3D translation layers -> Risky
    if is_dxvk_or_d3d_path(&path_lower) {
        return RegionSafety::Risky;
    }

    // Rule 7: Vulkan / Mesa / GPU driver userspace libraries -> Risky
    if is_gpu_driver_lib(&path_lower) {
        return RegionSafety::Risky;
    }

    // Rule 8: Wine system DLLs -> Risky
    if is_wine_system_dll(&path_lower) {
        return RegionSafety::Risky;
    }

    // Rule 9: Anonymous rw-p regions
    if path.is_empty() || path.starts_with('[') {
        return classify_anonymous_region(path, size);
    }

    // Rule 10: rw-p with game DLL/EXE path -> Safe
    // If we got here, it's a writable file-backed region that isn't a system DLL or GPU lib.
    // This covers game .exe/.dll data sections.
    if perms.write && !perms.shared {
        return RegionSafety::Safe;
    }

    RegionSafety::ReadOnly
}

/// Classify an anonymous `rw-p` region by its label and size.
fn classify_anonymous_region(label: &str, size: u64) -> RegionSafety {
    // Thread stacks: labeled [stack] or [stack:<tid>]
    if label.starts_with("[stack") {
        return RegionSafety::Risky;
    }

    // Kernel-provided regions
    if label == "[vdso]" || label == "[vvar]" || label == "[vsyscall]" {
        return RegionSafety::ReadOnly;
    }

    // glibc heap label
    if label == "[heap]" {
        return RegionSafety::Safe;
    }

    // Guard pages (0 size or very small with no permissions -- already filtered by !write)
    // But we still skip tiny regions
    if size < 4096 {
        return RegionSafety::Risky;
    }

    // Very large anonymous regions (> 1GB) are likely DXVK shader cache or GPU staging
    if size > 1_073_741_824 {
        return RegionSafety::Risky;
    }

    // Default for anonymous rw-p: Safe (Windows heap, VirtualAlloc regions)
    RegionSafety::Safe
}

/// Check if a path refers to DXVK, VKD3D, or D3D translation layer files.
fn is_dxvk_or_d3d_path(path_lower: &str) -> bool {
    path_lower.contains("dxvk")
        || path_lower.contains("vkd3d")
        || path_lower.contains("d3d9")
        || path_lower.contains("d3d10")
        || path_lower.contains("d3d11")
        || path_lower.contains("d3d12")
        || path_lower.contains("dxgi")
}

/// Check if a path refers to GPU driver userspace libraries.
fn is_gpu_driver_lib(path_lower: &str) -> bool {
    // Only match .so files (not /dev/ paths which are already caught)
    let is_shared_lib = path_lower.ends_with(".so") || path_lower.contains(".so.");
    if !is_shared_lib {
        return false;
    }
    path_lower.contains("vulkan")
        || path_lower.contains("mesa")
        || path_lower.contains("radeonsi")
        || path_lower.contains("amdgpu")
        || path_lower.contains("nvidia")
        || path_lower.contains("libvulkan")
}

/// Check if a path refers to a Wine system DLL (not a game DLL).
fn is_wine_system_dll(path_lower: &str) -> bool {
    // Wine system DLLs live under wine's lib directory and are well-known names
    let wine_dlls = [
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "user32.dll",
        "gdi32.dll",
        "advapi32.dll",
        "msvcrt.dll",
        "ucrtbase.dll",
        "ws2_32.dll",
        "ole32.dll",
        "oleaut32.dll",
        "rpcrt4.dll",
        "combase.dll",
        "sechost.dll",
        "bcrypt.dll",
        "crypt32.dll",
        "setupapi.dll",
        "version.dll",
        "imm32.dll",
        "winmm.dll",
        "dbghelp.dll",
        "xinput",
        "xaudio",
        "wined3d",
        "winevulkan",
        "winex11",
        "winewayland",
    ];
    wine_dlls
        .iter()
        .any(|dll| path_lower.contains(dll))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Permissions parsing ─────────────────────────────────────────────────

    #[test]
    fn parse_permissions_rwxp() {
        let p = Permissions::parse("rwxp").unwrap();
        assert!(p.read);
        assert!(p.write);
        assert!(p.execute);
        assert!(!p.shared);
    }

    #[test]
    fn parse_permissions_r_xp() {
        let p = Permissions::parse("r-xp").unwrap();
        assert!(p.read);
        assert!(!p.write);
        assert!(p.execute);
        assert!(!p.shared);
    }

    #[test]
    fn parse_permissions_rw_s() {
        let p = Permissions::parse("rw-s").unwrap();
        assert!(p.read);
        assert!(p.write);
        assert!(!p.execute);
        assert!(p.shared);
    }

    #[test]
    fn permissions_display() {
        let p = Permissions {
            read: true,
            write: false,
            execute: true,
            shared: false,
        };
        assert_eq!(p.as_str(), "r-xp");
    }

    // ─── Line parsing ────────────────────────────────────────────────────────

    #[test]
    fn parse_basic_anonymous_region() {
        let line = "140000000-150000000 rw-p 00000000 00:00 0";
        let region = parse_maps_line(line).unwrap();
        assert_eq!(region.start, 0x1_4000_0000);
        assert_eq!(region.end, 0x1_5000_0000);
        assert!(region.permissions.write);
        assert!(!region.permissions.shared);
        assert!(region.pathname.is_empty());
        assert_eq!(region.safety, RegionSafety::Safe);
    }

    #[test]
    fn parse_file_backed_region() {
        let line = "7f8a00000000-7f8a00010000 r-xp 00001000 08:02 12345 /usr/lib/libc.so.6";
        let region = parse_maps_line(line).unwrap();
        assert_eq!(region.start, 0x7f8a_0000_0000);
        assert_eq!(region.pathname, "/usr/lib/libc.so.6");
        assert_eq!(region.offset, 0x1000);
        assert_eq!(region.inode, 12345);
    }

    #[test]
    fn parse_device_region() {
        let line = "7f2000000000-7f2100000000 rw-s 00000000 00:06 1111 /dev/nvidia0";
        let region = parse_maps_line(line).unwrap();
        assert_eq!(region.safety, RegionSafety::NeverTouch);
        assert!(region.permissions.shared);
    }

    #[test]
    fn parse_stack_label() {
        let line = "7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0 [stack]";
        let region = parse_maps_line(line).unwrap();
        assert_eq!(region.pathname, "[stack]");
        assert_eq!(region.safety, RegionSafety::Risky);
    }

    #[test]
    fn parse_vdso() {
        let line = "7ffff7fc4000-7ffff7fc6000 r-xp 00000000 00:00 0 [vdso]";
        let region = parse_maps_line(line).unwrap();
        assert_eq!(region.safety, RegionSafety::ReadOnly);
    }

    // ─── Classification tests ────────────────────────────────────────────────

    #[test]
    fn classify_shared_mapping_is_never_touch() {
        // ANY shared mapping = NeverTouch, regardless of path
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: true },
            "",
            65536,
        );
        assert_eq!(safety, RegionSafety::NeverTouch);
    }

    #[test]
    fn classify_nvidia_device() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: true },
            "/dev/nvidia0",
            268_435_456,
        );
        assert_eq!(safety, RegionSafety::NeverTouch);
    }

    #[test]
    fn classify_nvidia_uvm() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: true },
            "/dev/nvidia-uvm",
            4_294_967_296,
        );
        assert_eq!(safety, RegionSafety::NeverTouch);
    }

    #[test]
    fn classify_amd_render_node() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: true },
            "/dev/dri/renderD128",
            268_435_456,
        );
        assert_eq!(safety, RegionSafety::NeverTouch);
    }

    #[test]
    fn classify_wine_shared_memory() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: true },
            "/dev/shm/wine-abcdef123456",
            65536,
        );
        assert_eq!(safety, RegionSafety::NeverTouch);
    }

    #[test]
    fn classify_wineserver_path() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "/tmp/.wine-1000/server-xxxxx/wineserver",
            4096,
        );
        assert_eq!(safety, RegionSafety::NeverTouch);
    }

    #[test]
    fn classify_code_section() {
        let safety = classify_region(
            &Permissions { read: true, write: false, execute: true, shared: false },
            "/path/to/Game.exe",
            1_048_576,
        );
        assert_eq!(safety, RegionSafety::ReadOnly);
    }

    #[test]
    fn classify_dxvk_dll_data() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "/path/to/proton/lib/wine/dxvk/d3d11.dll",
            131_072,
        );
        assert_eq!(safety, RegionSafety::Risky);
    }

    #[test]
    fn classify_vkd3d_dll() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "/path/to/proton/lib64/wine/vkd3d-proton/d3d12.dll",
            65536,
        );
        assert_eq!(safety, RegionSafety::Risky);
    }

    #[test]
    fn classify_dxgi_dll() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "/path/to/proton/lib/wine/dxvk/dxgi.dll",
            32768,
        );
        assert_eq!(safety, RegionSafety::Risky);
    }

    #[test]
    fn classify_vulkan_driver_lib() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "/usr/lib/x86_64-linux-gnu/libvulkan_radeon.so",
            131_072,
        );
        assert_eq!(safety, RegionSafety::Risky);
    }

    #[test]
    fn classify_mesa_lib() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "/usr/lib/x86_64-linux-gnu/dri/radeonsi_dri.so",
            262_144,
        );
        assert_eq!(safety, RegionSafety::Risky);
    }

    #[test]
    fn classify_nvidia_userspace_lib() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "/usr/lib/x86_64-linux-gnu/libnvidia-glcore.so.535.129.03",
            524_288,
        );
        assert_eq!(safety, RegionSafety::Risky);
    }

    #[test]
    fn classify_ntdll() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "/path/to/proton/dist/lib64/wine/x86_64-windows/ntdll.dll",
            65536,
        );
        assert_eq!(safety, RegionSafety::Risky);
    }

    #[test]
    fn classify_kernel32() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "/path/to/proton/lib64/wine/x86_64-windows/kernel32.dll",
            32768,
        );
        assert_eq!(safety, RegionSafety::Risky);
    }

    #[test]
    fn classify_anonymous_safe_heap() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "",
            16_777_216, // 16MB - typical game heap region
        );
        assert_eq!(safety, RegionSafety::Safe);
    }

    #[test]
    fn classify_anonymous_small_region_risky() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "",
            2048, // < 4KB bookkeeping
        );
        assert_eq!(safety, RegionSafety::Risky);
    }

    #[test]
    fn classify_anonymous_huge_region_risky() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "",
            2_147_483_648, // 2GB - likely DXVK shader cache
        );
        assert_eq!(safety, RegionSafety::Risky);
    }

    #[test]
    fn classify_heap_label() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "[heap]",
            1_048_576,
        );
        assert_eq!(safety, RegionSafety::Safe);
    }

    #[test]
    fn classify_stack_label() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "[stack]",
            8_388_608, // 8MB default stack
        );
        assert_eq!(safety, RegionSafety::Risky);
    }

    #[test]
    fn classify_game_exe_data_section() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "/path/to/game/Game.exe",
            65536,
        );
        // Game .exe data section = Safe (not a Wine system DLL, not DXVK)
        assert_eq!(safety, RegionSafety::Safe);
    }

    #[test]
    fn classify_game_dll_data_section() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "/path/to/game/GameLogic.dll",
            131_072,
        );
        assert_eq!(safety, RegionSafety::Safe);
    }

    #[test]
    fn classify_guard_page_no_perms() {
        let safety = classify_region(
            &Permissions { read: false, write: false, execute: false, shared: false },
            "",
            4096,
        );
        // No write permission -> ReadOnly (guard pages have no perms)
        assert_eq!(safety, RegionSafety::ReadOnly);
    }

    #[test]
    fn classify_pulseaudio_shm() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: true },
            "/dev/shm/pulse-shm-12345",
            262_144,
        );
        assert_eq!(safety, RegionSafety::NeverTouch);
    }

    // ─── Full maps parsing ───────────────────────────────────────────────────

    #[test]
    fn parse_realistic_maps_output() {
        let maps = "\
140000000-140001000 r--p 00000000 00:00 0 /home/user/game/Game.exe
140001000-142000000 r-xp 00001000 00:00 0 /home/user/game/Game.exe
142000000-142800000 r--p 02000000 00:00 0 /home/user/game/Game.exe
142800000-142900000 rw-p 02800000 00:00 0 /home/user/game/Game.exe
142900000-14a000000 rw-p 00000000 00:00 0
7bc400000-7bc800000 r-xp 00000000 00:00 0 /path/to/dxvk/d3d11.dll
7bc800000-7bc820000 rw-p 00400000 00:00 0 /path/to/dxvk/d3d11.dll
7f2000000000-7f2100000000 rw-s 00000000 00:06 1111 /dev/nvidia0
7f4000000000-7f4000010000 rw-s 00000000 00:01 3333 /dev/shm/wine-abc123
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0 [stack]";

        let regions = parse_maps(maps).unwrap();
        assert_eq!(regions.len(), 10);

        // PE headers - ReadOnly
        assert_eq!(regions[0].safety, RegionSafety::ReadOnly);
        // .text - ReadOnly
        assert_eq!(regions[1].safety, RegionSafety::ReadOnly);
        // .rdata - ReadOnly
        assert_eq!(regions[2].safety, RegionSafety::ReadOnly);
        // .data/.bss - Safe (game exe)
        assert_eq!(regions[3].safety, RegionSafety::Safe);
        // Anonymous heap - Safe
        assert_eq!(regions[4].safety, RegionSafety::Safe);
        // DXVK code - ReadOnly (r-xp)
        assert_eq!(regions[5].safety, RegionSafety::ReadOnly);
        // DXVK data - Risky
        assert_eq!(regions[6].safety, RegionSafety::Risky);
        // NVIDIA GPU - NeverTouch
        assert_eq!(regions[7].safety, RegionSafety::NeverTouch);
        // Wine shm - NeverTouch
        assert_eq!(regions[8].safety, RegionSafety::NeverTouch);
        // Stack - Risky
        assert_eq!(regions[9].safety, RegionSafety::Risky);
    }

    #[test]
    fn parse_maps_empty_input() {
        let regions = parse_maps("").unwrap();
        assert!(regions.is_empty());
    }

    #[test]
    fn region_safety_flags() {
        assert!(RegionSafety::Safe.can_scan());
        assert!(RegionSafety::Safe.can_write());
        assert!(RegionSafety::ReadOnly.can_scan());
        assert!(!RegionSafety::ReadOnly.can_write());
        assert!(RegionSafety::Risky.can_scan());
        assert!(!RegionSafety::Risky.can_write());
        assert!(!RegionSafety::NeverTouch.can_scan());
        assert!(!RegionSafety::NeverTouch.can_write());
    }

    #[test]
    fn region_size_calculation() {
        let r = MapRegion {
            start: 0x1000,
            end: 0x2000,
            permissions: Permissions { read: true, write: true, execute: false, shared: false },
            offset: 0,
            device: "00:00".to_string(),
            inode: 0,
            pathname: String::new(),
            safety: RegionSafety::Safe,
        };
        assert_eq!(r.size(), 0x1000);
        assert!(r.is_anonymous());
    }

    // ─── Edge cases: Intel / AMD DRI paths ───────────────────────────────────

    #[test]
    fn classify_intel_gpu() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: true },
            "/dev/dri/card0",
            65536,
        );
        assert_eq!(safety, RegionSafety::NeverTouch);
    }

    #[test]
    fn classify_amd_card() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: true },
            "/dev/dri/card1",
            1_048_576,
        );
        assert_eq!(safety, RegionSafety::NeverTouch);
    }

    // ─── Edge cases: paths that should NOT match ─────────────────────────────

    #[test]
    fn unity_game_assembly_is_safe() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "/path/to/game/GameAssembly.dll",
            2_097_152,
        );
        assert_eq!(safety, RegionSafety::Safe);
    }

    #[test]
    fn unreal_engine_dll_is_safe() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "/path/to/game/Engine/Binaries/Win64/UnrealEngine.dll",
            4_194_304,
        );
        assert_eq!(safety, RegionSafety::Safe);
    }

    #[test]
    fn anonymous_256mb_is_safe() {
        // 256MB anonymous region is large but under the 1GB threshold
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "",
            268_435_456,
        );
        assert_eq!(safety, RegionSafety::Safe);
    }

    #[test]
    fn anonymous_exactly_1gb_is_safe() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "",
            1_073_741_824, // exactly 1GB -- not > 1GB
        );
        assert_eq!(safety, RegionSafety::Safe);
    }

    #[test]
    fn anonymous_over_1gb_is_risky() {
        let safety = classify_region(
            &Permissions { read: true, write: true, execute: false, shared: false },
            "",
            1_073_741_825, // 1GB + 1 byte
        );
        assert_eq!(safety, RegionSafety::Risky);
    }
}
