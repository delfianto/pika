use crate::candidate::{Candidate, TypeFlags, ValueType, encode_value_patterns};
use crate::memory::MemoryAccess;
use anyhow::Result;

/// Filter mode for narrowing candidates.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FilterMode {
    /// Keep candidates whose current value equals `new_value`.
    Exact(f64),
    /// Keep candidates whose current value does NOT equal `new_value`.
    NotEqual(f64),
    /// Keep candidates whose current value increased (compared to stored snapshot).
    Increased,
    /// Keep candidates whose current value decreased.
    Decreased,
    /// Keep candidates whose current value changed at all.
    Changed,
    /// Keep candidates whose current value stayed the same.
    Unchanged,
}

/// Filter candidates from a previous scan against a new value.
/// Reads the current value at each candidate address and keeps only those that match.
///
/// Returns the number of candidates retained.
pub fn filter_candidates(
    mem: &dyn MemoryAccess,
    pid: u32,
    candidates: &mut Vec<Candidate>,
    new_value: f64,
    _dtype: ValueType,
) -> Result<usize> {
    let patterns = encode_value_patterns(new_value);

    let mut retained = 0;

    for i in 0..candidates.len() {
        let candidate = candidates[i];

        // Determine how many bytes we need to read (max type width for this candidate)
        let read_size = if candidate.types.intersects(TypeFlags::I64 | TypeFlags::U64 | TypeFlags::F64)
        {
            8
        } else {
            4
        };

        let mut buf = vec![0u8; read_size];
        if mem.read(pid, candidate.address, &mut buf).is_err() {
            continue; // Address unmapped, discard candidate
        }

        // Check if any pattern matches the current bytes
        let mut matched_types = TypeFlags::empty();
        for &(ref pat_bytes, pat_flags, pat_size) in &patterns {
            if pat_size <= buf.len() && buf[..pat_size] == pat_bytes[..pat_size] {
                // Intersect with candidate's existing types
                matched_types |= pat_flags & candidate.types;
            }
        }

        if !matched_types.is_empty() {
            candidates[retained] = Candidate {
                address: candidate.address,
                types: matched_types,
                confidence: candidate.confidence.saturating_add(1),
            };
            retained += 1;
        }
    }

    candidates.truncate(retained);
    Ok(retained)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maps::{MapRegion, Permissions, RegionSafety};
    use crate::memory::MockMemoryAccess;

    fn setup_mock_with_values(values: &[(u64, i32)]) -> MockMemoryAccess {
        let mock = MockMemoryAccess::new(1);
        // Create a region that spans all addresses
        let min_addr = values.iter().map(|(a, _)| *a).min().unwrap_or(0x1000);
        let max_addr = values.iter().map(|(a, _)| *a).max().unwrap_or(0x1000) + 8;
        let size = (max_addr - min_addr) as usize;
        let mut data = vec![0u8; size];
        for &(addr, val) in values {
            let offset = (addr - min_addr) as usize;
            data[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
        }
        mock.add_region(min_addr, data);
        mock.set_maps(vec![MapRegion {
            start: min_addr,
            end: max_addr,
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
    fn filter_exact_match() {
        let mock = setup_mock_with_values(&[
            (0x1000, 100),
            (0x1004, 200),
            (0x1008, 100),
            (0x100C, 300),
        ]);

        let mut candidates = vec![
            Candidate::new(0x1000, TypeFlags::I32 | TypeFlags::U32),
            Candidate::new(0x1004, TypeFlags::I32 | TypeFlags::U32),
            Candidate::new(0x1008, TypeFlags::I32 | TypeFlags::U32),
            Candidate::new(0x100C, TypeFlags::I32 | TypeFlags::U32),
        ];

        // Now change value at 0x1000 and 0x1008 to 95, and filter for 95
        mock.write_value::<i32>(0x1000, 95);
        mock.write_value::<i32>(0x1008, 95);

        let retained = filter_candidates(&mock, 1, &mut candidates, 95.0, ValueType::I32).unwrap();
        assert_eq!(retained, 2);
        assert_eq!(candidates[0].address, 0x1000);
        assert_eq!(candidates[1].address, 0x1008);
        // Confidence should have incremented
        assert_eq!(candidates[0].confidence, 1);
    }

    #[test]
    fn filter_removes_unmapped_addresses() {
        let mock = MockMemoryAccess::new(1);
        mock.add_region(0x1000, vec![0u8; 16]);
        mock.set_maps(vec![MapRegion {
            start: 0x1000,
            end: 0x1010,
            permissions: Permissions { read: true, write: true, execute: false, shared: false },
            offset: 0,
            device: "00:00".to_string(),
            inode: 0,
            pathname: String::new(),
            safety: RegionSafety::Safe,
        }]);

        let mut candidates = vec![
            Candidate::new(0x1000, TypeFlags::I32),
            Candidate::new(0xDEAD_0000, TypeFlags::I32), // unmapped
        ];

        let retained = filter_candidates(&mock, 1, &mut candidates, 0.0, ValueType::I32).unwrap();
        assert_eq!(retained, 1);
        assert_eq!(candidates[0].address, 0x1000);
    }

    #[test]
    fn filter_narrows_types() {
        let mock = setup_mock_with_values(&[(0x1000, 100)]);

        // Candidate has both i32 and f32 flags
        let mut candidates = vec![Candidate::new(
            0x1000,
            TypeFlags::I32 | TypeFlags::U32 | TypeFlags::F32,
        )];

        // Filter for 100 as i32 -- f32(100.0) has different bytes, so F32 flag should drop
        let retained = filter_candidates(&mock, 1, &mut candidates, 100.0, ValueType::Auto).unwrap();
        assert_eq!(retained, 1);
        assert!(candidates[0].types.contains(TypeFlags::I32));
        // f32(100.0) = 0x42c80000, which differs from i32(100) = 0x64000000
        assert!(!candidates[0].types.contains(TypeFlags::F32));
    }

    #[test]
    fn filter_empty_candidates() {
        let mock = MockMemoryAccess::new(1);
        let mut candidates: Vec<Candidate> = Vec::new();
        let retained = filter_candidates(&mock, 1, &mut candidates, 42.0, ValueType::I32).unwrap();
        assert_eq!(retained, 0);
    }

    #[test]
    fn filter_confidence_increments() {
        let mock = setup_mock_with_values(&[(0x1000, 42)]);
        let mut candidates = vec![Candidate {
            address: 0x1000,
            types: TypeFlags::I32 | TypeFlags::U32,
            confidence: 5,
        }];

        let retained = filter_candidates(&mock, 1, &mut candidates, 42.0, ValueType::I32).unwrap();
        assert_eq!(retained, 1);
        assert_eq!(candidates[0].confidence, 6);
    }
}
