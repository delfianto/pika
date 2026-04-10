use crate::candidate::ValueType;
use crate::maps::RegionSafety;
use crate::memory::MemoryAccess;
use anyhow::{Context, Result};

/// Encode a numeric value into bytes according to the specified type.
fn encode_value(value: f64, dtype: ValueType) -> Result<Vec<u8>> {
    #[expect(clippy::cast_possible_truncation)]
    match dtype {
        ValueType::I32 => Ok((value as i32).to_le_bytes().to_vec()),
        ValueType::U32 => Ok((value as u32).to_le_bytes().to_vec()),
        ValueType::F32 => Ok((value as f32).to_le_bytes().to_vec()),
        ValueType::I64 => Ok((value as i64).to_le_bytes().to_vec()),
        ValueType::U64 => Ok((value as u64).to_le_bytes().to_vec()),
        ValueType::F64 => Ok(value.to_le_bytes().to_vec()),
        ValueType::Auto => anyhow::bail!("cannot write with Auto type -- specify a concrete type"),
    }
}

/// Write a value to a specific address in a target process.
///
/// **SAFETY**: Performs a pre-flight region safety check by re-reading `/proc/[pid]/maps`
/// and re-classifying the target address. The write is REJECTED if the region is not `Safe`.
///
/// This prevents writing to regions that may have been remapped by DXVK or the Vulkan
/// driver between the scan and this write.
pub fn write_value(
    mem: &dyn MemoryAccess,
    pid: u32,
    address: u64,
    value: f64,
    dtype: ValueType,
) -> Result<()> {
    let data = encode_value(value, dtype)?;

    tracing::debug!(
        pid,
        address = format_args!("{address:#x}"),
        value,
        dtype = %dtype,
        "write requested, running pre-flight check",
    );

    // ── Pre-flight safety check ─────────────────────────────────────────────
    // Re-read /proc/[pid]/maps and re-classify the target address.
    // DXVK can remap regions between scan and write.
    let regions = mem
        .read_maps(pid)
        .context("failed to read maps for pre-flight check")?;

    let containing_region = regions.iter().find(|r| address >= r.start && address + data.len() as u64 <= r.end);

    match containing_region {
        None => anyhow::bail!(
            "ABORT: address {address:#x} is not within any mapped region (may have been unmapped)"
        ),
        Some(region) if region.safety != RegionSafety::Safe => {
            anyhow::bail!(
                "ABORT: address {address:#x} is in a {:?} region ({}). \
                 Only Safe regions can be written to. \
                 Region: {:#x}-{:#x} {}",
                region.safety,
                region.permissions.as_str(),
                region.start,
                region.end,
                region.pathname,
            );
        }
        Some(region) => {
            tracing::debug!(
                address = format_args!("{address:#x}"),
                region = format_args!("{:#x}-{:#x}", region.start, region.end),
                safety = ?region.safety,
                "pre-flight passed",
            );
        }
    }

    // ── Perform the write ───────────────────────────────────────────────────
    let written = mem
        .write(pid, address, &data)
        .context("process_vm_writev failed")?;

    if written != data.len() {
        anyhow::bail!(
            "partial write: wrote {written}/{} bytes at {address:#x}",
            data.len()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maps::{MapRegion, Permissions};
    use crate::memory::MockMemoryAccess;

    fn mock_with_safe_region() -> MockMemoryAccess {
        let mock = MockMemoryAccess::new(1);
        mock.add_region(0x1000, vec![0u8; 4096]);
        mock.set_maps(vec![MapRegion {
            start: 0x1000,
            end: 0x2000,
            permissions: Permissions { read: true, write: true, execute: false, shared: false },
            offset: 0,
            device: "00:00".to_string(),
            inode: 0,
            pathname: String::new(),
            safety: RegionSafety::Safe,
        }]);
        mock
    }

    #[test]
    fn write_i32_value() {
        let mock = mock_with_safe_region();
        write_value(&mock, 1, 0x1000, 42.0, ValueType::I32).unwrap();
        let val: i32 = mock.read_value(0x1000);
        assert_eq!(val, 42);
    }

    #[test]
    fn write_f32_value() {
        let mock = mock_with_safe_region();
        write_value(&mock, 1, 0x1000, 3.14, ValueType::F32).unwrap();
        let val: f32 = mock.read_value(0x1000);
        assert!((val - 3.14).abs() < 0.001);
    }

    #[test]
    fn write_i64_value() {
        let mock = mock_with_safe_region();
        write_value(&mock, 1, 0x1000, 999_999_999.0, ValueType::I64).unwrap();
        let val: i64 = mock.read_value(0x1000);
        assert_eq!(val, 999_999_999);
    }

    #[test]
    fn write_rejects_never_touch_region() {
        let mock = MockMemoryAccess::new(1);
        mock.add_region(0x7f00_0000, vec![0u8; 4096]);
        mock.set_maps(vec![MapRegion {
            start: 0x7f00_0000,
            end: 0x7f00_1000,
            permissions: Permissions { read: true, write: true, execute: false, shared: true },
            offset: 0,
            device: "00:06".to_string(),
            inode: 1111,
            pathname: "/dev/nvidia0".to_string(),
            safety: RegionSafety::NeverTouch,
        }]);

        let result = write_value(&mock, 1, 0x7f00_0000, 42.0, ValueType::I32);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("ABORT"),
            "should abort write to NeverTouch region"
        );
    }

    #[test]
    fn write_rejects_risky_region() {
        let mock = MockMemoryAccess::new(1);
        mock.add_region(0x5000, vec![0u8; 4096]);
        mock.set_maps(vec![MapRegion {
            start: 0x5000,
            end: 0x6000,
            permissions: Permissions { read: true, write: true, execute: false, shared: false },
            offset: 0,
            device: "00:00".to_string(),
            inode: 0,
            pathname: "/path/to/dxvk/d3d11.dll".to_string(),
            safety: RegionSafety::Risky,
        }]);

        let result = write_value(&mock, 1, 0x5000, 42.0, ValueType::I32);
        assert!(result.is_err());
    }

    #[test]
    fn write_rejects_unmapped_address() {
        let mock = mock_with_safe_region();
        let result = write_value(&mock, 1, 0xDEAD_0000, 42.0, ValueType::I32);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not within any mapped region"));
    }

    #[test]
    fn write_rejects_auto_type() {
        let mock = mock_with_safe_region();
        let result = write_value(&mock, 1, 0x1000, 42.0, ValueType::Auto);
        assert!(result.is_err());
    }

    #[test]
    fn write_rejects_readonly_region() {
        let mock = MockMemoryAccess::new(1);
        mock.add_region(0x3000, vec![0u8; 4096]);
        mock.set_maps(vec![MapRegion {
            start: 0x3000,
            end: 0x4000,
            permissions: Permissions { read: true, write: false, execute: true, shared: false },
            offset: 0,
            device: "00:00".to_string(),
            inode: 0,
            pathname: "/path/to/Game.exe".to_string(),
            safety: RegionSafety::ReadOnly,
        }]);

        let result = write_value(&mock, 1, 0x3000, 42.0, ValueType::I32);
        assert!(result.is_err());
    }
}
