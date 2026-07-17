use crate::mem::access::MemoryAccess;
use crate::process::maps::{MapRegion, RegionSafety};
use anyhow::Result;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};

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
    /// Chain of dereferences. Follow: read [module_base + base_offset], add links[0].offset,
    /// dereference, add links[1].offset, etc.
    pub links: Vec<PointerLink>,
}

/// Parameters for a pointer chain scan.
pub struct PointerScanParams {
    /// Maximum struct offset when searching for pointers.
    pub max_offset: i64,
    /// Maximum chain depth (number of dereferences).
    pub max_depth: usize,
    /// Maximum results to return.
    pub max_results: usize,
}

impl Default for PointerScanParams {
    fn default() -> Self {
        Self {
            max_offset: 0x1000,
            max_depth: 5,
            max_results: 100,
        }
    }
}

/// Find pointer chains from module bases to a target address via BFS.
///
/// Algorithm:
/// 1. Scan all scannable regions for 8-byte-aligned values that point near the target
/// 2. For each found pointer, check if it lives in a known module (chain complete)
/// 3. If not, add to the BFS queue and search for pointers to it
/// 4. Repeat up to `max_depth` levels
pub fn find_pointer_chains(
    mem: &dyn MemoryAccess,
    pid: u32,
    target_address: u64,
    regions: &[MapRegion],
    params: &PointerScanParams,
) -> Result<Vec<PointerChain>> {
    let modules = extract_module_bases(regions);
    let scannable: Vec<&MapRegion> = regions
        .iter()
        .filter(|r| {
            r.permissions.read && matches!(r.safety, RegionSafety::Safe | RegionSafety::ReadOnly)
        })
        .collect();

    let total_bytes: u64 = scannable.iter().map(|r| r.size()).sum();
    tracing::debug!(
        pid,
        target = format_args!("{target_address:#x}"),
        modules = modules.len(),
        scannable_regions = scannable.len(),
        scan_bytes = total_bytes,
        max_depth = params.max_depth,
        max_offset = params.max_offset,
        "pointer scan starting, {:.1} MB to search",
        total_bytes as f64 / 1_048_576.0,
    );
    let ptr_start = std::time::Instant::now();

    // Build a sorted list of mapped ranges for pointer validity checking
    let mapped_ranges: Vec<(u64, u64)> = regions.iter().map(|r| (r.start, r.end)).collect();

    let mut chains: Vec<PointerChain> = Vec::new();
    let mut visited: HashSet<u64> = HashSet::new();
    let mut queue: VecDeque<(u64, Vec<PointerLink>)> = VecDeque::new();

    queue.push_back((target_address, Vec::new()));
    visited.insert(target_address);

    while let Some((target, chain_so_far)) = queue.pop_front() {
        if chain_so_far.len() >= params.max_depth || chains.len() >= params.max_results {
            continue;
        }

        // Scan for pointers to this target
        let pointers = scan_for_pointers_to(
            mem,
            pid,
            &scannable,
            target,
            params.max_offset,
            &mapped_ranges,
        );

        for (ptr_addr, offset) in pointers {
            // Build the chain link
            let mut new_chain = chain_so_far.clone();
            new_chain.push(PointerLink {
                address: ptr_addr,
                offset,
            });

            // Check if this pointer is inside a known module
            if let Some((module_name, module_base)) = find_containing_module(ptr_addr, &modules) {
                chains.push(PointerChain {
                    base_module: module_name,
                    base_offset: ptr_addr - module_base,
                    links: new_chain,
                });
                if chains.len() >= params.max_results {
                    break;
                }
                continue;
            }

            // Not in a module -- continue BFS if not visited and within depth
            if new_chain.len() < params.max_depth && visited.insert(ptr_addr) {
                queue.push_back((ptr_addr, new_chain));
            }
        }
    }

    // Sort by chain length (shorter = more stable)
    chains.sort_by_key(|c| c.links.len());
    chains.truncate(params.max_results);

    tracing::debug!(
        chains_found = chains.len(),
        visited = visited.len(),
        elapsed_ms = ptr_start.elapsed().as_millis(),
        "pointer scan complete",
    );

    Ok(chains)
}

/// Scan all scannable regions for 8-byte-aligned pointer values that point
/// within `max_offset` of the target address.
fn scan_for_pointers_to(
    mem: &dyn MemoryAccess,
    pid: u32,
    regions: &[&MapRegion],
    target: u64,
    max_offset: i64,
    mapped_ranges: &[(u64, u64)],
) -> Vec<(u64, i64)> {
    let low = target.saturating_sub(max_offset.unsigned_abs());
    let high = target.saturating_add(max_offset.unsigned_abs());

    regions
        .par_iter()
        .flat_map(|region| {
            scan_region_for_pointers(mem, pid, region, low, high, target, mapped_ranges)
                .unwrap_or_default()
        })
        .collect()
}

/// Scan a single region for pointer-sized values in the given range.
fn scan_region_for_pointers(
    mem: &dyn MemoryAccess,
    pid: u32,
    region: &MapRegion,
    low: u64,
    high: u64,
    target: u64,
    _mapped_ranges: &[(u64, u64)],
) -> Result<Vec<(u64, i64)>> {
    let size = region.size() as usize;
    if size < 8 {
        return Ok(Vec::new());
    }

    let chunk_size = size.min(4 * 1024 * 1024);
    let mut results = Vec::new();
    let mut buffer = vec![0u8; chunk_size];
    let mut offset = 0usize;

    while offset < size {
        let read_len = chunk_size.min(size - offset);
        let base_addr = region.start + offset as u64;

        let Ok(bytes_read) = mem.read(pid, base_addr, &mut buffer[..read_len]) else {
            break;
        };
        if bytes_read < 8 {
            break;
        }

        // Check every 8-byte-aligned position
        for pos in (0..bytes_read.saturating_sub(7)).step_by(8) {
            let val = u64::from_le_bytes(buffer[pos..pos + 8].try_into().unwrap());
            if val >= low && val <= high && val != 0 {
                let ptr_addr = base_addr + pos as u64;
                let off = target as i64 - val as i64;
                results.push((ptr_addr, off));
            }
        }

        offset += bytes_read;
    }

    Ok(results)
}

/// Check if an address falls within a known module.
fn find_containing_module(address: u64, modules: &[(String, u64, u64)]) -> Option<(String, u64)> {
    modules
        .iter()
        .find(|(_, start, end)| address >= *start && address < *end)
        .map(|(name, start, _)| (name.clone(), *start))
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
        if region.pathname.starts_with("/dev/")
            || region.pathname.starts_with("/dev/shm/")
            || region.safety == RegionSafety::NeverTouch
        {
            continue;
        }

        if seen.insert(region.pathname.clone()) {
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
    use crate::mem::access::MockMemoryAccess;
    use crate::process::maps::Permissions;

    fn rw_perms() -> Permissions {
        Permissions {
            read: true,
            write: true,
            execute: false,
            shared: false,
        }
    }

    fn make_region(start: u64, end: u64, path: &str, safety: RegionSafety) -> MapRegion {
        MapRegion {
            start,
            end,
            permissions: Permissions {
                read: true,
                write: false,
                execute: true,
                shared: false,
            },
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
            make_region(
                0x0001_4000_0000,
                0x0001_4000_1000,
                "/path/to/Game.exe",
                RegionSafety::ReadOnly,
            ),
            make_region(
                0x0001_4000_1000,
                0x0001_4200_0000,
                "/path/to/Game.exe",
                RegionSafety::ReadOnly,
            ),
            make_region(
                0x0001_4200_0000,
                0x0001_4280_0000,
                "/path/to/Game.exe",
                RegionSafety::ReadOnly,
            ),
            make_region(
                0x0001_8000_0000,
                0x0001_8020_0000,
                "/path/to/GameLogic.dll",
                RegionSafety::ReadOnly,
            ),
            make_region(
                0x7f00_0000,
                0x7f00_1000,
                "/dev/nvidia0",
                RegionSafety::NeverTouch,
            ),
            make_region(0x1000, 0x2000, "", RegionSafety::Safe),
        ];

        let modules = extract_module_bases(&regions);
        assert_eq!(modules.len(), 2);
        let game = modules
            .iter()
            .find(|(name, _, _)| name.contains("Game.exe"));
        assert!(game.is_some());
        let (_, start, end) = game.unwrap();
        assert_eq!(*start, 0x0001_4000_0000);
        assert_eq!(*end, 0x0001_4280_0000);
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

    #[test]
    fn find_direct_pointer_chain() {
        // Layout:
        // Module "Game.exe" at 0x14000_0000 - 0x14000_2000
        //   At offset 0x100 in the module, a pointer to the target address
        // Heap at 0x2000_0000 - 0x2000_1000
        //   Target value at 0x2000_0500

        let mock = MockMemoryAccess::new(1);

        // Module region: write a pointer at 0x14000_0100 that points to 0x2000_0500
        let mut module_data = vec![0u8; 0x2000];
        let target_addr: u64 = 0x2000_0500;
        module_data[0x100..0x108].copy_from_slice(&target_addr.to_le_bytes());
        mock.add_region(0x0001_4000_0000, module_data);

        // Heap region: target value lives here
        let heap_data = vec![0u8; 0x1000];
        mock.add_region(0x2000_0000, heap_data);

        let regions = vec![
            MapRegion {
                start: 0x0001_4000_0000,
                end: 0x0001_4000_2000,
                permissions: rw_perms(),
                offset: 0,
                device: "00:00".to_string(),
                inode: 0,
                pathname: "/path/to/Game.exe".to_string(),
                safety: RegionSafety::Safe,
            },
            MapRegion {
                start: 0x2000_0000,
                end: 0x2000_1000,
                permissions: rw_perms(),
                offset: 0,
                device: "00:00".to_string(),
                inode: 0,
                pathname: String::new(),
                safety: RegionSafety::Safe,
            },
        ];
        mock.set_maps(regions.clone());

        let params = PointerScanParams {
            max_offset: 0x100,
            max_depth: 3,
            max_results: 10,
        };

        let chains = find_pointer_chains(&mock, 1, target_addr, &regions, &params).unwrap();
        assert!(!chains.is_empty(), "should find at least one chain");

        let chain = &chains[0];
        assert!(chain.base_module.contains("Game.exe"));
        assert_eq!(chain.base_offset, 0x100);
        assert_eq!(chain.links.len(), 1); // direct pointer, depth 1
        assert_eq!(chain.links[0].offset, 0); // exact pointer, no offset
    }

    #[test]
    fn find_chain_with_offset() {
        // Module has a pointer to (target - 0x10), so offset is 0x10
        let mock = MockMemoryAccess::new(1);

        let target_addr: u64 = 0x2000_0510;
        let pointer_value: u64 = 0x2000_0500; // points 0x10 before target

        let mut module_data = vec![0u8; 0x1000];
        module_data[0x80..0x88].copy_from_slice(&pointer_value.to_le_bytes());
        mock.add_region(0x0001_4000_0000, module_data);
        mock.add_region(0x2000_0000, vec![0u8; 0x1000]);

        let regions = vec![
            MapRegion {
                start: 0x0001_4000_0000,
                end: 0x0001_4000_1000,
                permissions: rw_perms(),
                offset: 0,
                device: "00:00".to_string(),
                inode: 0,
                pathname: "/Game.exe".to_string(),
                safety: RegionSafety::Safe,
            },
            MapRegion {
                start: 0x2000_0000,
                end: 0x2000_1000,
                permissions: rw_perms(),
                offset: 0,
                device: "00:00".to_string(),
                inode: 0,
                pathname: String::new(),
                safety: RegionSafety::Safe,
            },
        ];
        mock.set_maps(regions.clone());

        let params = PointerScanParams {
            max_offset: 0x100,
            max_depth: 3,
            max_results: 10,
        };

        let chains = find_pointer_chains(&mock, 1, target_addr, &regions, &params).unwrap();
        assert!(!chains.is_empty());
        // The offset should be 0x10 (target - pointer_value)
        assert_eq!(chains[0].links[0].offset, 0x10);
    }

    #[test]
    fn depth_limit_respected() {
        // Create a chain: module -> A -> B -> target (depth 3)
        // With max_depth=1, only direct pointers should be found
        let mock = MockMemoryAccess::new(1);
        let target: u64 = 0x3000_0100;

        // B points to target (at 0x2000_0000)
        let mut b_data = vec![0u8; 0x1000];
        b_data[0..8].copy_from_slice(&target.to_le_bytes());
        mock.add_region(0x2000_0000, b_data);

        // Module does NOT point to target directly
        let module_data = vec![0u8; 0x1000];
        mock.add_region(0x0001_4000_0000, module_data);

        // Target region
        mock.add_region(0x3000_0000, vec![0u8; 0x1000]);

        let regions = vec![
            MapRegion {
                start: 0x0001_4000_0000,
                end: 0x0001_4000_1000,
                permissions: rw_perms(),
                offset: 0,
                device: "00:00".to_string(),
                inode: 0,
                pathname: "/Game.exe".to_string(),
                safety: RegionSafety::Safe,
            },
            MapRegion {
                start: 0x2000_0000,
                end: 0x2000_1000,
                permissions: rw_perms(),
                offset: 0,
                device: "00:00".to_string(),
                inode: 0,
                pathname: String::new(),
                safety: RegionSafety::Safe,
            },
            MapRegion {
                start: 0x3000_0000,
                end: 0x3000_1000,
                permissions: rw_perms(),
                offset: 0,
                device: "00:00".to_string(),
                inode: 0,
                pathname: String::new(),
                safety: RegionSafety::Safe,
            },
        ];
        mock.set_maps(regions.clone());

        // With depth 1, no chains found (module doesn't directly point to target)
        let params = PointerScanParams {
            max_offset: 0x100,
            max_depth: 1,
            max_results: 10,
        };
        let chains = find_pointer_chains(&mock, 1, target, &regions, &params).unwrap();
        // B points to target but B is not in a module, and depth=1 doesn't allow further search
        assert!(chains.is_empty());
    }

    #[test]
    fn two_level_chain() {
        // Module at 0x14000_0000 has pointer to 0x2000_0000 (an intermediate struct)
        // 0x2000_0000 has pointer to 0x3000_0100 (target)
        let mock = MockMemoryAccess::new(1);
        let target: u64 = 0x3000_0100;
        let intermediate: u64 = 0x2000_0000;

        // Module -> intermediate
        let mut module_data = vec![0u8; 0x1000];
        module_data[0x200..0x208].copy_from_slice(&intermediate.to_le_bytes());
        mock.add_region(0x0001_4000_0000, module_data);

        // Intermediate -> target
        let mut inter_data = vec![0u8; 0x1000];
        inter_data[0x50..0x58].copy_from_slice(&target.to_le_bytes());
        mock.add_region(0x2000_0000, inter_data);

        mock.add_region(0x3000_0000, vec![0u8; 0x1000]);

        let regions = vec![
            MapRegion {
                start: 0x0001_4000_0000,
                end: 0x0001_4000_1000,
                permissions: rw_perms(),
                offset: 0,
                device: "00:00".to_string(),
                inode: 0,
                pathname: "/Game.exe".to_string(),
                safety: RegionSafety::Safe,
            },
            MapRegion {
                start: 0x2000_0000,
                end: 0x2000_1000,
                permissions: rw_perms(),
                offset: 0,
                device: "00:00".to_string(),
                inode: 0,
                pathname: String::new(),
                safety: RegionSafety::Safe,
            },
            MapRegion {
                start: 0x3000_0000,
                end: 0x3000_1000,
                permissions: rw_perms(),
                offset: 0,
                device: "00:00".to_string(),
                inode: 0,
                pathname: String::new(),
                safety: RegionSafety::Safe,
            },
        ];
        mock.set_maps(regions.clone());

        let params = PointerScanParams {
            max_offset: 0x100,
            max_depth: 3,
            max_results: 10,
        };

        let chains = find_pointer_chains(&mock, 1, target, &regions, &params).unwrap();
        assert!(!chains.is_empty(), "should find the 2-level chain");
        // The chain should have 2 links
        let chain = chains.iter().find(|c| c.links.len() == 2);
        assert!(chain.is_some(), "should have a depth-2 chain");
    }

    #[test]
    fn no_chains_when_no_pointers() {
        let mock = MockMemoryAccess::new(1);
        mock.add_region(0x0001_4000_0000, vec![0u8; 0x1000]);
        mock.add_region(0x2000_0000, vec![0u8; 0x1000]);

        let regions = vec![
            MapRegion {
                start: 0x0001_4000_0000,
                end: 0x0001_4000_1000,
                permissions: rw_perms(),
                offset: 0,
                device: "00:00".to_string(),
                inode: 0,
                pathname: "/Game.exe".to_string(),
                safety: RegionSafety::Safe,
            },
            MapRegion {
                start: 0x2000_0000,
                end: 0x2000_1000,
                permissions: rw_perms(),
                offset: 0,
                device: "00:00".to_string(),
                inode: 0,
                pathname: String::new(),
                safety: RegionSafety::Safe,
            },
        ];
        mock.set_maps(regions.clone());

        let params = PointerScanParams::default();
        let chains = find_pointer_chains(&mock, 1, 0x2000_0500, &regions, &params).unwrap();
        assert!(chains.is_empty());
    }
}
