use crate::mem::access::MemoryAccess;
use crate::mem::write::write_value;
use crate::scan::candidate::ValueType;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// Configuration for a frozen value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FreezeEntry {
    pub pid: u32,
    pub address: u64,
    pub value: f64,
    pub dtype: ValueType,
    pub interval: Duration,
}

/// Serialization-friendly freeze entry for JSON-RPC.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FreezeEntryJson {
    pub address: String,
    pub value: f64,
    pub dtype: String,
    pub interval_ms: u64,
    pub active: bool,
}

/// Manages active freeze loops.
/// Each frozen address gets a dedicated thread that writes the value periodically.
pub struct FreezeManager {
    mem: Arc<dyn MemoryAccess>,
    active: Arc<DashMap<u64, FreezeHandle>>,
}

struct FreezeHandle {
    entry: FreezeEntry,
    /// Signal the thread to stop.
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl FreezeManager {
    pub fn new(mem: Arc<dyn MemoryAccess>) -> Self {
        Self {
            mem,
            active: Arc::new(DashMap::new()),
        }
    }

    /// Start a freeze loop for the given address.
    /// If already frozen, updates the value and interval.
    pub fn start(&self, entry: FreezeEntry) -> anyhow::Result<()> {
        let address = entry.address;

        // Stop existing freeze if any
        self.stop(address);

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_clone = stop.clone();
        let mem_clone = self.mem.clone();
        let entry_clone = entry.clone();

        let thread = std::thread::Builder::new()
            .name(format!("freeze-{address:#x}"))
            .spawn(move || {
                freeze_loop(&mem_clone, &entry_clone, &stop_clone);
            })?;

        self.active.insert(
            address,
            FreezeHandle {
                entry,
                stop,
                thread: Some(thread),
            },
        );

        Ok(())
    }

    /// Stop a freeze loop for the given address.
    pub fn stop(&self, address: u64) {
        if let Some((_, mut handle)) = self.active.remove(&address) {
            handle
                .stop
                .store(true, std::sync::atomic::Ordering::Relaxed);
            if let Some(thread) = handle.thread.take() {
                let _ = thread.join();
            }
        }
    }

    /// List all active freezes.
    pub fn list(&self) -> Vec<FreezeEntryJson> {
        self.active
            .iter()
            .map(|entry| {
                let h = entry.value();
                FreezeEntryJson {
                    address: format!("{:#x}", h.entry.address),
                    value: h.entry.value,
                    dtype: h.entry.dtype.to_string(),
                    interval_ms: h.entry.interval.as_millis() as u64,
                    active: !h.stop.load(std::sync::atomic::Ordering::Relaxed),
                }
            })
            .collect()
    }

    /// Stop all active freezes.
    pub fn stop_all(&self) {
        let keys: Vec<u64> = self.active.iter().map(|e| *e.key()).collect();
        for key in keys {
            self.stop(key);
        }
    }
}

impl Drop for FreezeManager {
    fn drop(&mut self) {
        self.stop_all();
    }
}

/// The freeze loop body. Runs in a dedicated std::thread.
/// Re-checks region safety on every write via `write_value`.
fn freeze_loop(
    mem: &Arc<dyn MemoryAccess>,
    entry: &FreezeEntry,
    stop: &std::sync::atomic::AtomicBool,
) {
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        // write_value performs its own pre-flight safety check every time
        if let Err(e) = write_value(
            mem.as_ref(),
            entry.pid,
            entry.address,
            entry.value,
            entry.dtype,
        ) {
            tracing::warn!(
                address = format!("{:#x}", entry.address),
                error = %e,
                "freeze write failed, stopping freeze loop"
            );
            break;
        }
        std::thread::sleep(entry.interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::access::MockMemoryAccess;
    use crate::process::maps::{MapRegion, Permissions, RegionSafety};

    fn mock_with_region() -> Arc<MockMemoryAccess> {
        let mock = MockMemoryAccess::new(1);
        mock.add_region(0x1000, vec![0u8; 4096]);
        mock.set_maps(vec![MapRegion {
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
        }]);
        Arc::new(mock)
    }

    #[test]
    fn freeze_start_and_stop() {
        let mock = mock_with_region();
        let manager = FreezeManager::new(mock.clone());

        manager
            .start(FreezeEntry {
                pid: 1,
                address: 0x1000,
                value: 999.0,
                dtype: ValueType::I32,
                interval: Duration::from_millis(50),
            })
            .unwrap();

        // Let the freeze loop write a few times
        std::thread::sleep(Duration::from_millis(200));

        // Value should have been written
        let val: i32 = mock.read_value(0x1000);
        assert_eq!(val, 999);

        // Stop and verify it's no longer in the list
        manager.stop(0x1000);
        assert!(manager.list().is_empty());
    }

    #[test]
    fn freeze_list_entries() {
        let mock = mock_with_region();
        let manager = FreezeManager::new(mock);

        manager
            .start(FreezeEntry {
                pid: 1,
                address: 0x1000,
                value: 42.0,
                dtype: ValueType::I32,
                interval: Duration::from_millis(100),
            })
            .unwrap();

        let list = manager.list();
        assert_eq!(list.len(), 1);
        assert!((list[0].value - 42.0).abs() < f64::EPSILON);
        assert!(list[0].active);

        manager.stop_all();
    }

    #[test]
    fn freeze_replaces_existing() {
        let mock = mock_with_region();
        let manager = FreezeManager::new(mock.clone());

        manager
            .start(FreezeEntry {
                pid: 1,
                address: 0x1000,
                value: 100.0,
                dtype: ValueType::I32,
                interval: Duration::from_millis(50),
            })
            .unwrap();

        // Replace with different value
        manager
            .start(FreezeEntry {
                pid: 1,
                address: 0x1000,
                value: 200.0,
                dtype: ValueType::I32,
                interval: Duration::from_millis(50),
            })
            .unwrap();

        std::thread::sleep(Duration::from_millis(200));
        let val: i32 = mock.read_value(0x1000);
        assert_eq!(val, 200);

        manager.stop_all();
    }
}
