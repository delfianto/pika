use crate::candidate::{Candidate, TypeFlags, ValueType, encode_value_patterns};
use crate::memory::MemoryAccess;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Filter mode for narrowing candidates.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FilterMode {
    /// Keep candidates whose current value equals `new_value`.
    Exact,
    /// Keep candidates whose current value does NOT equal `new_value`.
    NotEqual,
    /// Keep candidates whose current value increased since last scan.
    Increased,
    /// Keep candidates whose current value decreased since last scan.
    Decreased,
    /// Keep candidates whose current value changed at all since last scan.
    Changed,
    /// Keep candidates whose current value stayed the same since last scan.
    Unchanged,
}

impl FilterMode {
    /// Parse from a string (CLI input).
    pub fn from_str_loose(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().replace('_', "-").as_str() {
            "exact" | "eq" | "=" => Ok(Self::Exact),
            "not-equal" | "ne" | "!=" | "neq" => Ok(Self::NotEqual),
            "increased" | "inc" | ">" | "gt" => Ok(Self::Increased),
            "decreased" | "dec" | "<" | "lt" => Ok(Self::Decreased),
            "changed" | "ch" | "diff" => Ok(Self::Changed),
            "unchanged" | "unch" | "same" => Ok(Self::Unchanged),
            _ => anyhow::bail!(
                "unknown filter mode: '{s}'. \
                 Options: exact, not-equal, increased, decreased, changed, unchanged"
            ),
        }
    }

    /// Whether this mode needs a target value (Exact/NotEqual do, comparison modes don't).
    pub const fn needs_value(self) -> bool {
        matches!(self, Self::Exact | Self::NotEqual)
    }
}

/// Filter candidates from a previous scan.
///
/// For `Exact`/`NotEqual`: compares current memory against `new_value`.
/// For `Increased`/`Decreased`/`Changed`/`Unchanged`: compares current memory
/// against each candidate's stored `last_value`.
///
/// Updates `last_value` on retained candidates for the next filter pass.
/// Returns the number of candidates retained.
pub fn filter_candidates(
    mem: &dyn MemoryAccess,
    pid: u32,
    candidates: &mut Vec<Candidate>,
    new_value: f64,
    _dtype: ValueType,
    mode: FilterMode,
) -> Result<usize> {
    let before = candidates.len();
    tracing::debug!(
        pid,
        mode = ?mode,
        candidates = before,
        new_value,
        "filtering candidates",
    );
    let filter_start = std::time::Instant::now();

    let patterns = encode_value_patterns(new_value);
    let mut retained = 0;
    let mut unmapped = 0usize;

    for i in 0..candidates.len() {
        let candidate = candidates[i];

        // Determine read width from the candidate's remaining types
        let read_size =
            if candidate.types.intersects(TypeFlags::I64 | TypeFlags::U64 | TypeFlags::F64) {
                8
            } else {
                4
            };

        let mut current_bytes = [0u8; 8];
        if mem
            .read(pid, candidate.address, &mut current_bytes[..read_size])
            .is_err()
        {
            unmapped += 1;
            continue; // Address unmapped, discard candidate
        }

        let keep = match mode {
            FilterMode::Exact => {
                check_exact_match(&current_bytes, &patterns, candidate.types)
            }
            FilterMode::NotEqual => {
                !check_exact_match(&current_bytes, &patterns, candidate.types)
            }
            FilterMode::Increased => {
                check_comparison(&current_bytes, &candidate.last_value, candidate.types, |a, b| a > b)
            }
            FilterMode::Decreased => {
                check_comparison(&current_bytes, &candidate.last_value, candidate.types, |a, b| a < b)
            }
            FilterMode::Changed => current_bytes[..read_size] != candidate.last_value[..read_size],
            FilterMode::Unchanged => current_bytes[..read_size] == candidate.last_value[..read_size],
        };

        if keep {
            // For Exact/NotEqual, narrow types to only those that matched the pattern
            let new_types = if mode == FilterMode::Exact {
                narrow_types(&current_bytes, &patterns, candidate.types)
            } else {
                candidate.types
            };

            candidates[retained] = Candidate {
                address: candidate.address,
                types: if new_types.is_empty() {
                    candidate.types
                } else {
                    new_types
                },
                confidence: candidate.confidence.saturating_add(1),
                last_value: current_bytes,
            };
            retained += 1;
        }
    }

    candidates.truncate(retained);

    let elapsed = filter_start.elapsed();
    tracing::debug!(
        retained,
        dropped = before - retained,
        unmapped,
        elapsed_ms = elapsed.as_millis(),
        "filter complete ({before} -> {retained})",
    );

    Ok(retained)
}

/// Check if current bytes match any encoded pattern (for Exact mode).
fn check_exact_match(
    current: &[u8; 8],
    patterns: &[([u8; 8], TypeFlags, usize)],
    candidate_types: TypeFlags,
) -> bool {
    patterns.iter().any(|(pat_bytes, pat_flags, pat_size)| {
        pat_flags.intersects(candidate_types) && current[..*pat_size] == pat_bytes[..*pat_size]
    })
}

/// Narrow candidate types to only those whose pattern matched.
fn narrow_types(
    current: &[u8; 8],
    patterns: &[([u8; 8], TypeFlags, usize)],
    candidate_types: TypeFlags,
) -> TypeFlags {
    let mut matched = TypeFlags::empty();
    for (pat_bytes, pat_flags, pat_size) in patterns {
        if pat_flags.intersects(candidate_types) && current[..*pat_size] == pat_bytes[..*pat_size] {
            matched |= *pat_flags & candidate_types;
        }
    }
    matched
}

/// Typed comparison for Increased/Decreased filters.
/// Returns true if the comparison holds for ANY of the candidate's type flags.
fn check_comparison(
    current: &[u8; 8],
    previous: &[u8; 8],
    types: TypeFlags,
    cmp: fn(f64, f64) -> bool,
) -> bool {
    if types.contains(TypeFlags::I32) {
        let cur = i32::from_le_bytes(current[..4].try_into().unwrap());
        let prev = i32::from_le_bytes(previous[..4].try_into().unwrap());
        if cmp(f64::from(cur), f64::from(prev)) {
            return true;
        }
    }
    if types.contains(TypeFlags::U32) {
        let cur = u32::from_le_bytes(current[..4].try_into().unwrap());
        let prev = u32::from_le_bytes(previous[..4].try_into().unwrap());
        if cmp(f64::from(cur), f64::from(prev)) {
            return true;
        }
    }
    if types.contains(TypeFlags::F32) {
        let cur = f32::from_le_bytes(current[..4].try_into().unwrap());
        let prev = f32::from_le_bytes(previous[..4].try_into().unwrap());
        if cmp(f64::from(cur), f64::from(prev)) {
            return true;
        }
    }
    if types.contains(TypeFlags::I64) {
        let cur = i64::from_le_bytes(*current);
        let prev = i64::from_le_bytes(*previous);
        if cmp(cur as f64, prev as f64) {
            return true;
        }
    }
    if types.contains(TypeFlags::U64) {
        let cur = u64::from_le_bytes(*current);
        let prev = u64::from_le_bytes(*previous);
        if cmp(cur as f64, prev as f64) {
            return true;
        }
    }
    if types.contains(TypeFlags::F64) {
        let cur = f64::from_le_bytes(*current);
        let prev = f64::from_le_bytes(*previous);
        if cmp(cur, prev) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maps::{MapRegion, Permissions, RegionSafety};
    use crate::memory::MockMemoryAccess;

    fn setup_mock_with_values(values: &[(u64, i32)]) -> MockMemoryAccess {
        let mock = MockMemoryAccess::new(1);
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
        mock
    }

    fn make_candidate(addr: u64, value: i32) -> Candidate {
        let mut last_value = [0u8; 8];
        last_value[..4].copy_from_slice(&value.to_le_bytes());
        Candidate {
            address: addr,
            types: TypeFlags::I32 | TypeFlags::U32,
            confidence: 0,
            last_value,
        }
    }

    #[test]
    fn filter_exact_match() {
        let mock = setup_mock_with_values(&[
            (0x1000, 95),
            (0x1004, 200),
            (0x1008, 95),
            (0x100C, 300),
        ]);

        let mut candidates = vec![
            make_candidate(0x1000, 100),
            make_candidate(0x1004, 100),
            make_candidate(0x1008, 100),
            make_candidate(0x100C, 100),
        ];

        let retained =
            filter_candidates(&mock, 1, &mut candidates, 95.0, ValueType::I32, FilterMode::Exact)
                .unwrap();
        assert_eq!(retained, 2);
        assert_eq!(candidates[0].address, 0x1000);
        assert_eq!(candidates[1].address, 0x1008);
    }

    #[test]
    fn filter_not_equal() {
        let mock = setup_mock_with_values(&[
            (0x1000, 95),
            (0x1004, 200),
            (0x1008, 95),
        ]);

        let mut candidates = vec![
            make_candidate(0x1000, 100),
            make_candidate(0x1004, 100),
            make_candidate(0x1008, 100),
        ];

        let retained = filter_candidates(
            &mock, 1, &mut candidates, 95.0, ValueType::I32, FilterMode::NotEqual,
        )
        .unwrap();
        assert_eq!(retained, 1);
        assert_eq!(candidates[0].address, 0x1004); // only 200 != 95
    }

    #[test]
    fn filter_increased() {
        let mock = setup_mock_with_values(&[
            (0x1000, 150), // was 100 -> now 150 (increased)
            (0x1004, 50),  // was 100 -> now 50 (decreased)
            (0x1008, 100), // was 100 -> now 100 (unchanged)
        ]);

        let mut candidates = vec![
            make_candidate(0x1000, 100),
            make_candidate(0x1004, 100),
            make_candidate(0x1008, 100),
        ];

        let retained = filter_candidates(
            &mock, 1, &mut candidates, 0.0, ValueType::I32, FilterMode::Increased,
        )
        .unwrap();
        assert_eq!(retained, 1);
        assert_eq!(candidates[0].address, 0x1000);
    }

    #[test]
    fn filter_decreased() {
        let mock = setup_mock_with_values(&[
            (0x1000, 150), // increased
            (0x1004, 50),  // decreased
            (0x1008, 100), // unchanged
        ]);

        let mut candidates = vec![
            make_candidate(0x1000, 100),
            make_candidate(0x1004, 100),
            make_candidate(0x1008, 100),
        ];

        let retained = filter_candidates(
            &mock, 1, &mut candidates, 0.0, ValueType::I32, FilterMode::Decreased,
        )
        .unwrap();
        assert_eq!(retained, 1);
        assert_eq!(candidates[0].address, 0x1004);
    }

    #[test]
    fn filter_changed() {
        let mock = setup_mock_with_values(&[
            (0x1000, 150), // changed
            (0x1004, 100), // unchanged
            (0x1008, 50),  // changed
        ]);

        let mut candidates = vec![
            make_candidate(0x1000, 100),
            make_candidate(0x1004, 100),
            make_candidate(0x1008, 100),
        ];

        let retained = filter_candidates(
            &mock, 1, &mut candidates, 0.0, ValueType::I32, FilterMode::Changed,
        )
        .unwrap();
        assert_eq!(retained, 2);
        assert_eq!(candidates[0].address, 0x1000);
        assert_eq!(candidates[1].address, 0x1008);
    }

    #[test]
    fn filter_unchanged() {
        let mock = setup_mock_with_values(&[
            (0x1000, 150), // changed
            (0x1004, 100), // unchanged
            (0x1008, 50),  // changed
        ]);

        let mut candidates = vec![
            make_candidate(0x1000, 100),
            make_candidate(0x1004, 100),
            make_candidate(0x1008, 100),
        ];

        let retained = filter_candidates(
            &mock, 1, &mut candidates, 0.0, ValueType::I32, FilterMode::Unchanged,
        )
        .unwrap();
        assert_eq!(retained, 1);
        assert_eq!(candidates[0].address, 0x1004);
    }

    #[test]
    fn filter_changed_plus_unchanged_is_all() {
        let mock = setup_mock_with_values(&[
            (0x1000, 150),
            (0x1004, 100),
            (0x1008, 50),
        ]);

        let base_candidates = vec![
            make_candidate(0x1000, 100),
            make_candidate(0x1004, 100),
            make_candidate(0x1008, 100),
        ];

        let mut changed = base_candidates.clone();
        let n_changed = filter_candidates(
            &mock, 1, &mut changed, 0.0, ValueType::I32, FilterMode::Changed,
        )
        .unwrap();

        let mut unchanged = base_candidates.clone();
        let n_unchanged = filter_candidates(
            &mock, 1, &mut unchanged, 0.0, ValueType::I32, FilterMode::Unchanged,
        )
        .unwrap();

        assert_eq!(n_changed + n_unchanged, base_candidates.len());
    }

    #[test]
    fn filter_updates_last_value() {
        let mock = setup_mock_with_values(&[(0x1000, 200)]);

        let mut candidates = vec![make_candidate(0x1000, 100)];
        filter_candidates(
            &mock, 1, &mut candidates, 0.0, ValueType::I32, FilterMode::Changed,
        )
        .unwrap();

        // last_value should now be 200
        let stored = i32::from_le_bytes(candidates[0].last_value[..4].try_into().unwrap());
        assert_eq!(stored, 200);
    }

    #[test]
    fn filter_removes_unmapped() {
        let mock = MockMemoryAccess::new(1);
        mock.add_region(0x1000, vec![0u8; 16]);
        mock.set_maps(vec![MapRegion {
            start: 0x1000,
            end: 0x1010,
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

        let mut candidates = vec![
            make_candidate(0x1000, 0),
            make_candidate(0xDEAD_0000, 0), // unmapped
        ];

        let retained = filter_candidates(
            &mock, 1, &mut candidates, 0.0, ValueType::I32, FilterMode::Exact,
        )
        .unwrap();
        assert_eq!(retained, 1);
        assert_eq!(candidates[0].address, 0x1000);
    }

    #[test]
    fn filter_exact_narrows_types() {
        let mock = setup_mock_with_values(&[(0x1000, 100)]);

        let mut candidates = vec![Candidate {
            address: 0x1000,
            types: TypeFlags::I32 | TypeFlags::U32 | TypeFlags::F32,
            confidence: 0,
            last_value: [0; 8],
        }];

        filter_candidates(
            &mock, 1, &mut candidates, 100.0, ValueType::Auto, FilterMode::Exact,
        )
        .unwrap();

        assert!(candidates[0].types.contains(TypeFlags::I32));
        // f32(100.0) = 0x42c80000 != i32(100) = 0x64000000
        assert!(!candidates[0].types.contains(TypeFlags::F32));
    }

    #[test]
    fn filter_mode_parsing() {
        assert_eq!(FilterMode::from_str_loose("exact").unwrap(), FilterMode::Exact);
        assert_eq!(FilterMode::from_str_loose("increased").unwrap(), FilterMode::Increased);
        assert_eq!(FilterMode::from_str_loose("inc").unwrap(), FilterMode::Increased);
        assert_eq!(FilterMode::from_str_loose(">").unwrap(), FilterMode::Increased);
        assert_eq!(FilterMode::from_str_loose("not-equal").unwrap(), FilterMode::NotEqual);
        assert_eq!(FilterMode::from_str_loose("unchanged").unwrap(), FilterMode::Unchanged);
        assert!(FilterMode::from_str_loose("bogus").is_err());
    }

    #[test]
    fn filter_confidence_increments() {
        let mock = setup_mock_with_values(&[(0x1000, 42)]);
        let mut candidates = vec![Candidate {
            address: 0x1000,
            types: TypeFlags::I32 | TypeFlags::U32,
            confidence: 5,
            last_value: [0; 8],
        }];

        filter_candidates(
            &mock, 1, &mut candidates, 42.0, ValueType::I32, FilterMode::Exact,
        )
        .unwrap();
        assert_eq!(candidates[0].confidence, 6);
    }
}
