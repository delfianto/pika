use crate::maps::{MapRegion, RegionSafety};
use crate::memory::MemoryAccess;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// A single link in a pointer chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PointerLink {
    /// Address where this pointer was found.
    pub address: u64,
    /// Offset added after dereferencing: `[address] + offset -> next`.
    pub offset: i64,
}

/// A complete pointer chain from a stable module base to a target address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PointerChain {
    /// Module name (e.g., "Game.exe").
    pub base_module: String,
    /// Offset from module base to the first pointer.
    pub base_offset: u64,
    /// Chain of dereferences.
    pub links: Vec<PointerLink>,
}

/// Parameters for a pointer chain scan.
pub struct PointerScanParams {
    /// Maximum struct offset when searching for pointers.
    pub max_offset: i64,
    /// Maximum chain depth (number of dereferences).
    pub max_depth: usize,
}

impl Default for PointerScanParams {
    fn default() -> Self {
        Self {
            max_offset: 0x1000,
            max_depth: 5,
        }
    }
}

/// Find pointer chains from module bases to a target address.
///
/// This is a computationally expensive BFS operation.
/// Implementation uses the algorithm described in docs/ANALYSIS.md Section 7.5.
pub fn find_pointer_chains(
    _mem: &dyn MemoryAccess,
    _pid: u32,
    _target_address: u64,
    _regions: &[MapRegion],
    _params: &PointerScanParams,
) -> Result<Vec<PointerChain>> {
    // TODO: Implement BFS pointer chain discovery
    // 1. Scan all Safe/ReadOnly regions for pointer-sized values
    //    that fall within [target - max_offset, target + max_offset]
    // 2. For each found pointer, check if it's in a module (chain complete)
    // 3. If not, recurse: search for pointers to this pointer's address
    // 4. BFS ensures shortest chains are found first
    // 5. Depth-limited to prevent explosion

    tracing::warn!("pointer chain scanning not yet implemented");
    Ok(Vec::new())
}

/// Extract module base addresses from the memory map.
/// Modules are identified as the first mapping of each unique pathname.
#[must_use]
pub fn extract_module_bases(regions: &[MapRegion]) -> Vec<(String, u64, u64)> {
    let mut modules: Vec<(String, u64, u64)> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for region in regions {
        if region.pathname.is_empty() || region.pathname.starts_with('[') {
            continue;
        }
        // Skip known non-game paths
        if region.pathname.starts_with("/dev/")
            || region.pathname.starts_with("/dev/shm/")
            || region.safety == RegionSafety::NeverTouch
        {
            continue;
        }

        if seen.insert(region.pathname.clone()) {
            // Find the extent of this module (all contiguous regions with the same path)
            let module_end = regions
                .iter()
                .filter(|r| r.pathname == region.pathname)
                .map(|r| r.end)
                .max()
                .unwrap_or(region.end);

            modules.push((region.pathname.clone(), region.start, module_end));
        }
    }

    modules
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maps::{Permissions, RegionSafety};

    fn make_region(start: u64, end: u64, path: &str, safety: RegionSafety) -> MapRegion {
        MapRegion {
            start,
            end,
            permissions: Permissions { read: true, write: false, execute: true, shared: false },
            offset: 0,
            device: "00:00".to_string(),
            inode: 0,
            pathname: path.to_string(),
            safety,
        }
    }

    #[test]
    fn extract_modules_from_maps() {
        let regions = vec![
            make_region(0x14000_0000, 0x14000_1000, "/path/to/Game.exe", RegionSafety::ReadOnly),
            make_region(0x14000_1000, 0x14200_0000, "/path/to/Game.exe", RegionSafety::ReadOnly),
            make_region(0x14200_0000, 0x14280_0000, "/path/to/Game.exe", RegionSafety::ReadOnly),
            make_region(0x18000_0000, 0x18020_0000, "/path/to/GameLogic.dll", RegionSafety::ReadOnly),
            make_region(0x7f00_0000, 0x7f00_1000, "/dev/nvidia0", RegionSafety::NeverTouch),
            make_region(0x1000, 0x2000, "", RegionSafety::Safe), // anonymous
        ];

        let modules = extract_module_bases(&regions);
        assert_eq!(modules.len(), 2);

        // Game.exe should span the full range
        let game = modules.iter().find(|(name, _, _)| name.contains("Game.exe"));
        assert!(game.is_some());
        let (_, start, end) = game.unwrap();
        assert_eq!(*start, 0x14000_0000);
        assert_eq!(*end, 0x14280_0000);
    }

    #[test]
    fn extract_modules_skips_anonymous() {
        let regions = vec![make_region(0x1000, 0x2000, "", RegionSafety::Safe)];
        let modules = extract_module_bases(&regions);
        assert!(modules.is_empty());
    }

    #[test]
    fn extract_modules_skips_special_labels() {
        let regions = vec![
            make_region(0x1000, 0x2000, "[stack]", RegionSafety::Risky),
            make_region(0x3000, 0x4000, "[heap]", RegionSafety::Safe),
            make_region(0x5000, 0x6000, "[vdso]", RegionSafety::ReadOnly),
        ];
        let modules = extract_module_bases(&regions);
        assert!(modules.is_empty());
    }

    #[test]
    fn default_params() {
        let params = PointerScanParams::default();
        assert_eq!(params.max_offset, 0x1000);
        assert_eq!(params.max_depth, 5);
    }
}
