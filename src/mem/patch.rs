use crate::mem::access::MemoryAccess;
use crate::process::maps::RegionSafety;
use anyhow::Result;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Record of an applied code patch, keyed by the address that was patched.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PatchRecord {
    pub pid: u32,
    pub address: u64,
    pub original_bytes: Vec<u8>,
    pub patched_bytes: Vec<u8>,
    pub description: String,
}

/// JSON-friendly view for listing patches.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PatchRecordJson {
    pub address: String,
    pub original_bytes: String,
    pub patched_bytes: String,
    pub description: String,
}

/// Manages code patches applied to a target process.
///
/// Uses `/proc/pid/mem` to write to executable pages (r-xp) without stopping
/// the process. Keeps a backup of original bytes for restore.
pub struct PatchManager {
    mem: Arc<dyn MemoryAccess>,
    patches: DashMap<u64, PatchRecord>,
    /// Pluggable code-write function for testing on non-Linux.
    #[cfg(test)]
    writer: Option<Box<dyn Fn(u32, u64, &[u8]) -> Result<usize> + Send + Sync>>,
}

impl PatchManager {
    pub fn new(mem: Arc<dyn MemoryAccess>) -> Self {
        Self {
            mem,
            patches: DashMap::new(),
            #[cfg(test)]
            writer: None,
        }
    }

    /// Create a PatchManager with a custom code-write function (for testing).
    #[cfg(test)]
    pub fn new_with_writer(
        mem: Arc<dyn MemoryAccess>,
        writer: Box<dyn Fn(u32, u64, &[u8]) -> Result<usize> + Send + Sync>,
    ) -> Self {
        Self {
            mem,
            patches: DashMap::new(),
            writer: Some(writer),
        }
    }

    /// Write bytes to a code section, dispatching to the configured writer.
    #[allow(clippy::unused_self)]
    fn do_write_code(&self, pid: u32, address: u64, data: &[u8]) -> Result<usize> {
        #[cfg(test)]
        if let Some(ref writer) = self.writer {
            return writer(pid, address, data);
        }
        write_code(pid, address, data)
    }

    /// NOP the instruction(s) at `address`.
    ///
    /// If `size` is `None`, disassembles one instruction to auto-detect its length.
    /// If `size` is `Some(n)`, NOPs exactly `n` bytes (caller must ensure boundary alignment).
    ///
    /// Backs up original bytes for later restore.
    pub fn nop_at(&self, pid: u32, address: u64, size: Option<usize>) -> Result<PatchRecord> {
        let nop_size = match size {
            Some(s) => s,
            None => {
                // Auto-detect instruction length via disassembly
                let insns = crate::mem::disassemble::disassemble_at(self.mem.as_ref(), pid, address, 1)?;
                let insn = insns
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("failed to disassemble instruction at {address:#x}"))?;
                // Byte count from hex string: "48 89 5c" -> 3 tokens -> 3 bytes
                insn.bytes.split_whitespace().count()
            }
        };

        if nop_size == 0 {
            anyhow::bail!("NOP size cannot be zero");
        }

        validate_code_address(self.mem.as_ref(), pid, address, nop_size)?;

        // Back up original bytes
        let mut original = vec![0u8; nop_size];
        let read = self.mem.read(pid, address, &mut original)?;
        original.truncate(read);
        if read < nop_size {
            anyhow::bail!("could only read {read}/{nop_size} bytes at {address:#x}");
        }

        // Write NOP sled
        let nops = vec![0x90u8; nop_size];
        self.do_write_code(pid, address, &nops)?;

        let record = PatchRecord {
            pid,
            address,
            original_bytes: original,
            patched_bytes: nops,
            description: format!("nop {nop_size} bytes"),
        };
        self.patches.insert(address, record.clone());

        tracing::info!(
            address = format_args!("{address:#x}"),
            size = nop_size,
            "instruction NOPed"
        );

        Ok(record)
    }

    /// Write arbitrary bytes at a code address.
    ///
    /// Backs up original bytes for later restore.
    pub fn patch_at(&self, pid: u32, address: u64, bytes: &[u8]) -> Result<PatchRecord> {
        if bytes.is_empty() {
            anyhow::bail!("patch bytes cannot be empty");
        }

        validate_code_address(self.mem.as_ref(), pid, address, bytes.len())?;

        // Back up original bytes
        let mut original = vec![0u8; bytes.len()];
        let read = self.mem.read(pid, address, &mut original)?;
        original.truncate(read);
        if read < bytes.len() {
            anyhow::bail!("could only read {read}/{} bytes at {address:#x}", bytes.len());
        }

        self.do_write_code(pid, address, bytes)?;

        let record = PatchRecord {
            pid,
            address,
            original_bytes: original,
            patched_bytes: bytes.to_vec(),
            description: "custom patch".to_string(),
        };
        self.patches.insert(address, record.clone());

        tracing::info!(
            address = format_args!("{address:#x}"),
            size = bytes.len(),
            "code patched"
        );

        Ok(record)
    }

    /// Restore original bytes at a previously patched address.
    pub fn restore_at(&self, pid: u32, address: u64) -> Result<()> {
        let (_, record) = self
            .patches
            .remove(&address)
            .ok_or_else(|| anyhow::anyhow!("no patch found at {address:#x}"))?;

        if record.pid != pid {
            anyhow::bail!(
                "patch at {address:#x} belongs to pid {} but restore requested for pid {pid}",
                record.pid
            );
        }

        self.do_write_code(pid, address, &record.original_bytes)?;

        tracing::info!(
            address = format_args!("{address:#x}"),
            "original bytes restored"
        );

        Ok(())
    }

    /// List all active patches.
    pub fn list(&self) -> Vec<PatchRecordJson> {
        self.patches
            .iter()
            .map(|entry| {
                let r = entry.value();
                PatchRecordJson {
                    address: format!("{:#x}", r.address),
                    original_bytes: hex_encode(&r.original_bytes),
                    patched_bytes: hex_encode(&r.patched_bytes),
                    description: r.description.clone(),
                }
            })
            .collect()
    }

    /// Restore all active patches (best-effort).
    pub fn restore_all(&self) {
        let keys: Vec<u64> = self.patches.iter().map(|e| *e.key()).collect();
        for addr in keys {
            if let Some((_, record)) = self.patches.remove(&addr) {
                if let Err(e) = write_code(record.pid, record.address, &record.original_bytes) {
                    tracing::warn!(
                        address = format_args!("{:#x}", record.address),
                        error = %e,
                        "failed to restore patch on cleanup"
                    );
                }
            }
        }
    }
}

impl Drop for PatchManager {
    fn drop(&mut self) {
        self.restore_all();
    }
}

// ─── Code write via /proc/pid/mem ───────────────────────────────────────────

/// Write bytes to a code section via `/proc/pid/mem`.
/// This bypasses page protections (can write to r-xp pages) without stopping
/// the process. Requires same-UID or CAP_SYS_PTRACE.
#[cfg(target_os = "linux")]
pub fn write_code(pid: u32, address: u64, data: &[u8]) -> Result<usize> {
    use anyhow::Context as _;
    use std::io::{Seek, SeekFrom, Write};

    let path = format!("/proc/{pid}/mem");
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("failed to open {path} for code write"))?;
    file.seek(SeekFrom::Start(address))?;
    let written = file.write(data)?;
    if written != data.len() {
        anyhow::bail!(
            "partial code write: {written}/{} at {address:#x}",
            data.len()
        );
    }
    Ok(written)
}

#[cfg(not(target_os = "linux"))]
pub fn write_code(_pid: u32, _address: u64, _data: &[u8]) -> Result<usize> {
    anyhow::bail!("code patching requires Linux (/proc/pid/mem)")
}

// ─── Safety validation ──────────────────────────────────────────────────────

/// Verify that `address..address+size` falls in an executable region
/// and is NOT NeverTouch.
fn validate_code_address(
    mem: &dyn MemoryAccess,
    pid: u32,
    address: u64,
    size: usize,
) -> Result<()> {
    let regions = mem.read_maps(pid)?;
    let end = address + size as u64;

    let region = regions
        .iter()
        .find(|r| address >= r.start && end <= r.end)
        .ok_or_else(|| anyhow::anyhow!("address {address:#x} not in any mapped region"))?;

    if region.safety == RegionSafety::NeverTouch {
        anyhow::bail!(
            "ABORT: {address:#x} is in a NeverTouch region ({}) -- cannot patch",
            region.pathname
        );
    }

    if !region.permissions.execute && !region.permissions.write {
        anyhow::bail!(
            "ABORT: {address:#x} is in a non-executable, non-writable region ({}). \
             Code patching targets executable code sections.",
            region.permissions.as_str()
        );
    }

    Ok(())
}

// ─── Hex helpers ────────────────────────────────────────────────────────────

/// Encode bytes as space-separated hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Decode a space-separated hex string into bytes.
pub fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    hex.split_whitespace()
        .map(|s| u8::from_str_radix(s, 16).map_err(|e| anyhow::anyhow!("invalid hex byte '{s}': {e}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::access::MockMemoryAccess;
    use crate::process::maps::{MapRegion, Permissions, RegionSafety};

    fn mock_with_code_region() -> Arc<MockMemoryAccess> {
        let mock = MockMemoryAccess::new(1);
        // Simulate a code section with some x86_64 instructions
        let mut code = vec![0u8; 4096];
        // mov [rax+0x1c], ecx = 89 48 1c (3 bytes)
        code[0] = 0x89;
        code[1] = 0x48;
        code[2] = 0x1c;
        // nop = 90 (fill rest)
        for b in &mut code[3..16] {
            *b = 0x90;
        }
        mock.add_region(0x14000_0000, code);
        mock.set_maps(vec![
            MapRegion {
                start: 0x14000_0000,
                end: 0x14000_1000,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: true,
                    shared: false,
                },
                offset: 0,
                device: "00:00".to_string(),
                inode: 0,
                pathname: "game.exe".to_string(),
                safety: RegionSafety::ReadOnly,
            },
        ]);
        Arc::new(mock)
    }

    fn mock_with_nevertough_region() -> Arc<MockMemoryAccess> {
        let mock = MockMemoryAccess::new(1);
        mock.add_region(0x7000, vec![0u8; 256]);
        mock.set_maps(vec![MapRegion {
            start: 0x7000,
            end: 0x7100,
            permissions: Permissions {
                read: true,
                write: true,
                execute: false,
                shared: true,
            },
            offset: 0,
            device: "00:06".to_string(),
            inode: 1111,
            pathname: "/dev/nvidia0".to_string(),
            safety: RegionSafety::NeverTouch,
        }]);
        Arc::new(mock)
    }

    #[test]
    fn validate_accepts_executable_region() {
        let mock = mock_with_code_region();
        let result = validate_code_address(&*mock, 1, 0x14000_0000, 3);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_rejects_nevertough() {
        let mock = mock_with_nevertough_region();
        let result = validate_code_address(&*mock, 1, 0x7000, 2);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("NeverTouch"));
    }

    #[test]
    fn validate_rejects_unmapped_address() {
        let mock = mock_with_code_region();
        let result = validate_code_address(&*mock, 1, 0xDEAD_0000, 4);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not in any mapped region"));
    }

    #[test]
    fn nop_at_with_mock_writer() {
        let mock = mock_with_code_region();
        let mock_clone = mock.clone();

        // Mock writer: delegate to MockMemoryAccess.write()
        let writer = Box::new(move |pid: u32, address: u64, data: &[u8]| -> Result<usize> {
            mock_clone.write(pid, address, data)
        });

        let manager = PatchManager::new_with_writer(mock.clone(), writer);
        // NOP 3 bytes at 0x14000_0000
        let record = manager.nop_at(1, 0x14000_0000, Some(3)).unwrap();
        assert_eq!(record.original_bytes, vec![0x89, 0x48, 0x1c]);
        assert_eq!(record.patched_bytes, vec![0x90, 0x90, 0x90]);
        assert_eq!(record.description, "nop 3 bytes");

        // Verify the mock memory was actually written
        let mut buf = [0u8; 3];
        mock.read(1, 0x14000_0000, &mut buf).unwrap();
        assert_eq!(buf, [0x90, 0x90, 0x90]);
    }

    #[test]
    fn patch_and_restore_with_mock_writer() {
        let mock = mock_with_code_region();
        let mock_clone = mock.clone();

        let writer = Box::new(move |pid: u32, address: u64, data: &[u8]| -> Result<usize> {
            mock_clone.write(pid, address, data)
        });

        let manager = PatchManager::new_with_writer(mock.clone(), writer);

        // Patch 2 bytes
        let record = manager.patch_at(1, 0x14000_0000, &[0xEB, 0x05]).unwrap();
        assert_eq!(record.original_bytes, vec![0x89, 0x48]);

        // Verify patched
        let mut buf = [0u8; 2];
        mock.read(1, 0x14000_0000, &mut buf).unwrap();
        assert_eq!(buf, [0xEB, 0x05]);

        // Restore
        manager.restore_at(1, 0x14000_0000).unwrap();

        // Verify restored
        mock.read(1, 0x14000_0000, &mut buf).unwrap();
        assert_eq!(buf, [0x89, 0x48]);
    }

    #[test]
    fn list_shows_active_patches() {
        let mock = mock_with_code_region();
        let mock_clone = mock.clone();

        let writer = Box::new(move |pid: u32, address: u64, data: &[u8]| -> Result<usize> {
            mock_clone.write(pid, address, data)
        });

        let manager = PatchManager::new_with_writer(mock, writer);
        manager.nop_at(1, 0x14000_0000, Some(3)).unwrap();

        let list = manager.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].description, "nop 3 bytes");
    }

    #[test]
    fn restore_nonexistent_address_errors() {
        let mock = mock_with_code_region();
        let manager = PatchManager::new(mock);
        let result = manager.restore_at(1, 0xDEAD_BEEF);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no patch found"));
    }

    #[test]
    fn hex_encode_decode_roundtrip() {
        let original = vec![0x48, 0x89, 0x5c, 0x24, 0x08];
        let encoded = hex_encode(&original);
        assert_eq!(encoded, "48 89 5c 24 08");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn hex_decode_invalid() {
        assert!(hex_decode("ZZ FF").is_err());
    }
}
