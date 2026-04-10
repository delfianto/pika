use anyhow::Result;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use crate::maps::MapRegion;

/// Abstraction over process memory access.
/// Real implementation uses `process_vm_readv`/`writev` on Linux.
/// Mock implementation uses an in-memory buffer for testing on any platform.
pub trait MemoryAccess: Send + Sync {
    /// Read `buffer.len()` bytes from `address` in process `pid`.
    /// Returns the number of bytes actually read (may be less on partial reads).
    fn read(&self, pid: u32, address: u64, buffer: &mut [u8]) -> Result<usize>;

    /// Write `data` to `address` in process `pid`.
    /// Returns the number of bytes actually written.
    fn write(&self, pid: u32, address: u64, data: &[u8]) -> Result<usize>;

    /// Read the memory map for process `pid`.
    fn read_maps(&self, pid: u32) -> Result<Vec<MapRegion>>;
}

// ─── Linux implementation ────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;
    use nix::sys::uio::{process_vm_readv, process_vm_writev, RemoteIoVec};
    use nix::unistd::Pid;
    use std::io::IoSliceMut;

    /// Real memory access via Linux `process_vm_readv` / `process_vm_writev`.
    pub struct LinuxMemoryAccess;

    impl MemoryAccess for LinuxMemoryAccess {
        fn read(&self, pid: u32, address: u64, buffer: &mut [u8]) -> Result<usize> {
            let remote = RemoteIoVec {
                base: address as usize,
                len: buffer.len(),
            };
            let mut local = [IoSliceMut::new(buffer)];
            let n = process_vm_readv(Pid::from_raw(pid as i32), &mut local, &[remote])?;
            Ok(n)
        }

        fn write(&self, pid: u32, address: u64, data: &[u8]) -> Result<usize> {
            let remote = RemoteIoVec {
                base: address as usize,
                len: data.len(),
            };
            let local = [std::io::IoSlice::new(data)];
            let n = process_vm_writev(Pid::from_raw(pid as i32), &local, &[remote])?;
            Ok(n)
        }

        fn read_maps(&self, pid: u32) -> Result<Vec<MapRegion>> {
            let content = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
            crate::maps::parse_maps(&content)
        }
    }
}

// ─── Mock implementation (available on all platforms) ────────────────────────

/// Simulated process memory for testing.
/// Stores memory as a map of (base_address -> Vec<u8>) regions,
/// plus a configurable set of map regions for classification testing.
#[derive(Clone)]
pub struct MockMemoryAccess {
    /// The mock PID this instance responds to.
    pub pid: u32,
    /// Memory regions: base_address -> data.
    regions: Arc<RwLock<BTreeMap<u64, Vec<u8>>>>,
    /// Mock /proc/[pid]/maps content.
    maps: Arc<RwLock<Vec<MapRegion>>>,
}

impl MockMemoryAccess {
    /// Create a new mock with the given PID.
    #[must_use]
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            regions: Arc::new(RwLock::new(BTreeMap::new())),
            maps: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add a memory region with the given data.
    pub fn add_region(&self, base: u64, data: Vec<u8>) {
        self.regions.write().unwrap().insert(base, data);
    }

    /// Set the mock maps output.
    pub fn set_maps(&self, regions: Vec<MapRegion>) {
        *self.maps.write().unwrap() = regions;
    }

    /// Write a typed value at a specific address (convenience for test setup).
    pub fn write_value<T: bytemuck::Pod>(&self, address: u64, value: T) {
        let bytes = bytemuck::bytes_of(&value);
        let regions = self.regions.read().unwrap();
        for (&base, data) in &*regions {
            let end = base + data.len() as u64;
            if address >= base && address + bytes.len() as u64 <= end {
                drop(regions);
                let mut regions = self.regions.write().unwrap();
                let data = regions.get_mut(&base).unwrap();
                let offset = (address - base) as usize;
                data[offset..offset + bytes.len()].copy_from_slice(bytes);
                return;
            }
        }
        panic!(
            "write_value: address {address:#x} not within any mock region"
        );
    }

    /// Read a typed value from a specific address (convenience for test assertions).
    pub fn read_value<T: bytemuck::Pod + Copy>(&self, address: u64) -> T {
        let size = std::mem::size_of::<T>();
        let mut buf = vec![0u8; size];
        self.read(self.pid, address, &mut buf).unwrap();
        *bytemuck::from_bytes(&buf)
    }
}

impl MemoryAccess for MockMemoryAccess {
    fn read(&self, pid: u32, address: u64, buffer: &mut [u8]) -> Result<usize> {
        if pid != self.pid {
            anyhow::bail!("ESRCH: mock process {pid} not found (expected {})", self.pid);
        }
        let regions = self.regions.read().unwrap();
        let mut bytes_read = 0usize;
        for (&base, data) in &*regions {
            let end = base + data.len() as u64;
            let req_end = address + buffer.len() as u64;
            if address >= base && address < end {
                let offset = (address - base) as usize;
                let available = data.len() - offset;
                let to_copy = available.min(buffer.len());
                let actual_end = if req_end > end {
                    (end - address) as usize
                } else {
                    to_copy
                };
                buffer[..actual_end].copy_from_slice(&data[offset..offset + actual_end]);
                bytes_read = actual_end;
                break;
            }
        }
        if bytes_read == 0 {
            anyhow::bail!("EFAULT: address {address:#x} not mapped in mock process");
        }
        Ok(bytes_read)
    }

    fn write(&self, pid: u32, address: u64, data: &[u8]) -> Result<usize> {
        if pid != self.pid {
            anyhow::bail!("ESRCH: mock process {pid} not found");
        }
        let mut regions = self.regions.write().unwrap();
        for (&base, region_data) in &mut *regions {
            let end = base + region_data.len() as u64;
            if address >= base && address + data.len() as u64 <= end {
                let offset = (address - base) as usize;
                region_data[offset..offset + data.len()].copy_from_slice(data);
                return Ok(data.len());
            }
        }
        anyhow::bail!("EFAULT: address {address:#x} not mapped in mock process");
    }

    fn read_maps(&self, pid: u32) -> Result<Vec<MapRegion>> {
        if pid != self.pid {
            anyhow::bail!("ESRCH: mock process {pid} not found");
        }
        Ok(self.maps.read().unwrap().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maps::{MapRegion, Permissions, RegionSafety};

    fn make_mock() -> MockMemoryAccess {
        let mock = MockMemoryAccess::new(1234);
        // Add a 4KB region at address 0x1000
        mock.add_region(0x1000, vec![0u8; 4096]);
        mock
    }

    #[test]
    fn mock_read_write_basic() {
        let mock = make_mock();
        // Write some bytes
        mock.write(1234, 0x1000, &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        // Read them back
        let mut buf = [0u8; 4];
        let n = mock.read(1234, 0x1000, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn mock_read_wrong_pid() {
        let mock = make_mock();
        let mut buf = [0u8; 4];
        let result = mock.read(9999, 0x1000, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn mock_read_unmapped_address() {
        let mock = make_mock();
        let mut buf = [0u8; 4];
        let result = mock.read(1234, 0xDEAD_0000, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn mock_write_typed_value() {
        let mock = make_mock();
        mock.write_value::<i32>(0x1000, 42);
        let val: i32 = mock.read_value(0x1000);
        assert_eq!(val, 42);
    }

    #[test]
    fn mock_write_float() {
        let mock = make_mock();
        mock.write_value::<f32>(0x1000, 3.14);
        let val: f32 = mock.read_value(0x1000);
        assert!((val - 3.14).abs() < 1e-6);
    }

    #[test]
    fn mock_maps() {
        let mock = make_mock();
        let regions = vec![MapRegion {
            start: 0x1000,
            end: 0x2000,
            permissions: Permissions {
                read: true,
                write: true,
                execute: false,
                shared: false,
            },
            offset: 0,
            device: "00:00".to_string(),
            inode: 0,
            pathname: String::new(),
            safety: RegionSafety::Safe,
        }];
        mock.set_maps(regions.clone());
        let read_maps = mock.read_maps(1234).unwrap();
        assert_eq!(read_maps.len(), 1);
        assert_eq!(read_maps[0].start, 0x1000);
    }

    #[test]
    fn mock_partial_read_at_region_boundary() {
        let mock = MockMemoryAccess::new(1);
        mock.add_region(0x1000, vec![0xAA; 64]);
        // Try to read 128 bytes starting at 0x1000, but region is only 64 bytes
        let mut buf = [0u8; 128];
        let n = mock.read(1, 0x1000, &mut buf).unwrap();
        assert_eq!(n, 64);
        assert!(buf[..64].iter().all(|&b| b == 0xAA));
    }
}
