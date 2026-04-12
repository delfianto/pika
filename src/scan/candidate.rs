//! Candidate addresses and value type tracking for memory scans.
//!
//! A [`Candidate`] represents a memory address that matched a scan, along with
//! metadata about which data type interpretations remain valid. The multi-type
//! tracking via [`TypeFlags`] allows pika to search for all plausible types
//! simultaneously and narrow across filter passes without forcing the user to
//! guess the encoding up front.
//!
//! [`ValueType`] is used for explicit type selection in write and freeze operations,
//! while [`encode_value_patterns`] converts a numeric value into all plausible
//! little-endian byte patterns for scanning.

use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use std::fmt;

bitflags! {
    /// Tracks which data type interpretations are still valid for a candidate address.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct TypeFlags: u8 {
        const I32 = 0b0000_0001;
        const U32 = 0b0000_0010;
        const F32 = 0b0000_0100;
        const I64 = 0b0000_1000;
        const U64 = 0b0001_0000;
        const F64 = 0b0010_0000;
    }
}

impl fmt::Display for TypeFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut names = Vec::new();
        if self.contains(Self::I32) {
            names.push("i32");
        }
        if self.contains(Self::U32) {
            names.push("u32");
        }
        if self.contains(Self::F32) {
            names.push("f32");
        }
        if self.contains(Self::I64) {
            names.push("i64");
        }
        if self.contains(Self::U64) {
            names.push("u64");
        }
        if self.contains(Self::F64) {
            names.push("f64");
        }
        write!(f, "{}", names.join("|"))
    }
}

/// Single data type specifier for scan/write operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueType {
    I32,
    U32,
    F32,
    I64,
    U64,
    F64,
    Auto,
}

impl ValueType {
    /// Byte width of this type (Auto returns 0).
    #[must_use]
    pub const fn byte_size(self) -> usize {
        match self {
            Self::I32 | Self::U32 | Self::F32 => 4,
            Self::I64 | Self::U64 | Self::F64 => 8,
            Self::Auto => 0,
        }
    }

    /// Convert to the corresponding `TypeFlags` bit.
    #[must_use]
    pub const fn to_flag(self) -> TypeFlags {
        match self {
            Self::I32 => TypeFlags::I32,
            Self::U32 => TypeFlags::U32,
            Self::F32 => TypeFlags::F32,
            Self::I64 => TypeFlags::I64,
            Self::U64 => TypeFlags::U64,
            Self::F64 => TypeFlags::F64,
            Self::Auto => TypeFlags::all(),
        }
    }
}

impl fmt::Display for ValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::I32 => write!(f, "i32"),
            Self::U32 => write!(f, "u32"),
            Self::F32 => write!(f, "f32"),
            Self::I64 => write!(f, "i64"),
            Self::U64 => write!(f, "u64"),
            Self::F64 => write!(f, "f64"),
            Self::Auto => write!(f, "auto"),
        }
    }
}

/// A memory address that matched a scan, with its candidate types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// Absolute virtual address in the target process.
    pub address: u64,
    /// Which data type interpretations matched.
    pub types: TypeFlags,
    /// How many filter passes have confirmed this candidate.
    pub confidence: u8,
    /// Raw bytes from the last scan/filter pass (for comparison-based filters).
    pub last_value: [u8; 8],
}

impl Candidate {
    /// Create a candidate with the given address and type flags, zero-initialized value.
    #[must_use]
    pub const fn new(address: u64, types: TypeFlags) -> Self {
        Self {
            address,
            types,
            confidence: 0,
            last_value: [0; 8],
        }
    }

    /// Create a candidate with initial value bytes.
    #[must_use]
    pub const fn with_value(address: u64, types: TypeFlags, last_value: [u8; 8]) -> Self {
        Self {
            address,
            types,
            confidence: 0,
            last_value,
        }
    }
}

impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address.cmp(&other.address)
    }
}

/// Serialization-friendly candidate for JSON-RPC responses.
/// Addresses are hex strings because JS `Number` loses precision above 2^53.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateJson {
    pub address: String,
    pub types: Vec<String>,
    pub confidence: u8,
}

impl From<&Candidate> for CandidateJson {
    fn from(c: &Candidate) -> Self {
        let mut types = Vec::new();
        if c.types.contains(TypeFlags::I32) {
            types.push("i32".to_string());
        }
        if c.types.contains(TypeFlags::U32) {
            types.push("u32".to_string());
        }
        if c.types.contains(TypeFlags::F32) {
            types.push("f32".to_string());
        }
        if c.types.contains(TypeFlags::I64) {
            types.push("i64".to_string());
        }
        if c.types.contains(TypeFlags::U64) {
            types.push("u64".to_string());
        }
        if c.types.contains(TypeFlags::F64) {
            types.push("f64".to_string());
        }
        Self {
            address: format!("0x{:x}", c.address),
            types,
            confidence: c.confidence,
        }
    }
}

/// Pattern tuple: (byte_pattern, type_flags, pattern_size, use_epsilon).
/// When `use_epsilon` is true, the scanner uses approximate float comparison
/// instead of exact byte matching.
pub type ValuePattern = ([u8; 8], TypeFlags, usize, bool);

/// Encodes a numeric value into its little-endian byte representation for each type.
/// Returns patterns with their associated type flags.
pub fn encode_value_patterns(value: f64) -> Vec<ValuePattern> {
    let mut patterns: Vec<ValuePattern> = Vec::new();

    // i32 / u32 (same byte pattern for non-negative values)
    if value.fract() == 0.0 && value >= f64::from(i32::MIN) && value <= f64::from(i32::MAX) {
        #[expect(clippy::cast_possible_truncation)]
        let i = value as i32;
        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(&i.to_le_bytes());
        let mut flags = TypeFlags::I32;
        if i >= 0 {
            flags |= TypeFlags::U32;
        }
        patterns.push((bytes, flags, 4, false));
    }

    // f32 -- uses epsilon-based approximate matching to catch frame-delta drift
    #[expect(clippy::cast_possible_truncation)]
    let f = value as f32;
    if (f64::from(f) - value).abs() < 1e-6 {
        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(&f.to_le_bytes());
        // Always add f32 pattern (epsilon scan handles the matching, so
        // even when the bit pattern is identical to i32, the epsilon path
        // catches drifted values that exact byte match would miss)
        patterns.push((bytes, TypeFlags::F32, 4, true));
    }

    // i64 / u64
    if value.fract() == 0.0 && value >= i64::MIN as f64 && value <= i64::MAX as f64 {
        #[expect(clippy::cast_possible_truncation)]
        let i = value as i64;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&i.to_le_bytes());
        let mut flags = TypeFlags::I64;
        if i >= 0 {
            flags |= TypeFlags::U64;
        }
        patterns.push((bytes, flags, 8, false));
    }

    // f64
    {
        let bytes_arr = value.to_le_bytes();
        let dominated = patterns
            .iter()
            .any(|(b, _, sz, _)| *sz == 8 && *b == bytes_arr);
        if !dominated {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&bytes_arr);
            patterns.push((bytes, TypeFlags::F64, 8, false));
        }
    }

    patterns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_flags_display() {
        let flags = TypeFlags::I32 | TypeFlags::U32;
        assert_eq!(flags.to_string(), "i32|u32");
    }

    #[test]
    fn type_flags_empty_display() {
        let flags = TypeFlags::empty();
        assert_eq!(flags.to_string(), "");
    }

    #[test]
    fn value_type_byte_size() {
        assert_eq!(ValueType::I32.byte_size(), 4);
        assert_eq!(ValueType::F64.byte_size(), 8);
        assert_eq!(ValueType::Auto.byte_size(), 0);
    }

    #[test]
    fn candidate_ordering() {
        let a = Candidate::new(0x100, TypeFlags::I32);
        let b = Candidate::new(0x200, TypeFlags::I32);
        assert!(a < b);
    }

    #[test]
    fn candidate_json_conversion() {
        let c = Candidate::new(0xDEAD_BEEF, TypeFlags::I32 | TypeFlags::F32);
        let json: CandidateJson = (&c).into();
        assert_eq!(json.address, "0xdeadbeef");
        assert_eq!(json.types, vec!["i32", "f32"]);
    }

    #[test]
    fn encode_integer_100() {
        let patterns = encode_value_patterns(100.0);
        // Should have: i32|u32 pattern (4 bytes), i64|u64 pattern (8 bytes)
        // f32(100.0) = 0x42c80000, which differs from i32(100) = 0x64000000
        assert!(patterns.len() >= 2, "expected at least 2 patterns, got {}", patterns.len());

        // Check i32 pattern
        let i32_pat = patterns.iter().find(|(_, f, sz, _)| f.contains(TypeFlags::I32) && *sz == 4);
        assert!(i32_pat.is_some());
        let (bytes, flags, _, _) = i32_pat.unwrap();
        assert_eq!(bytes[..4], 100_i32.to_le_bytes());
        assert!(flags.contains(TypeFlags::U32)); // 100 >= 0, so u32 also matches
    }

    #[test]
    fn encode_float_1_5() {
        let patterns = encode_value_patterns(1.5);
        // 1.5 is not a whole number, so no i32/u32/i64/u64 patterns
        // Should have f32 and f64 patterns
        let f32_pat = patterns.iter().find(|(_, f, _, _)| f.contains(TypeFlags::F32));
        assert!(f32_pat.is_some());
        let (bytes, _, sz, _) = f32_pat.unwrap();
        assert_eq!(*sz, 4);
        assert_eq!(bytes[..4], 1.5_f32.to_le_bytes());
    }

    #[test]
    fn encode_zero() {
        let patterns = encode_value_patterns(0.0);
        // i32(0) and f32(0.0) have the same byte pattern: all zeros
        // Should deduplicate
        let four_byte = patterns.iter().filter(|(_, _, sz, _)| *sz == 4).count();
        // i32 pattern (exact) + f32 pattern (epsilon) are now always separate
        assert!(four_byte >= 1, "should have at least one 4-byte pattern");
    }

    #[test]
    fn encode_negative() {
        let patterns = encode_value_patterns(-42.0);
        // i32(-42) should NOT have U32 flag
        let i32_pat = patterns.iter().find(|(_, f, sz, _)| f.contains(TypeFlags::I32) && *sz == 4);
        assert!(i32_pat.is_some());
        let (_, flags, _, _) = i32_pat.unwrap();
        assert!(!flags.contains(TypeFlags::U32));
    }

    #[test]
    fn encode_large_integer() {
        let val = 3_000_000_000.0; // exceeds i32 max
        let patterns = encode_value_patterns(val);
        // Should NOT have i32 pattern (value > i32::MAX)
        let has_i32 = patterns.iter().any(|(_, f, sz, _)| f.contains(TypeFlags::I32) && *sz == 4);
        assert!(!has_i32, "3 billion should not fit in i32");
        // Should have i64/u64 pattern
        let has_i64 = patterns.iter().any(|(_, f, sz, _)| f.contains(TypeFlags::I64) && *sz == 8);
        assert!(has_i64);
    }

    #[test]
    fn candidate_json_serialization_roundtrip() {
        let json = CandidateJson {
            address: "0x140001000".to_string(),
            types: vec!["i32".to_string()],
            confidence: 3,
        };
        let serialized = serde_json::to_string(&json).unwrap();
        let deserialized: CandidateJson = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.address, json.address);
        assert_eq!(deserialized.types, json.types);
        assert_eq!(deserialized.confidence, json.confidence);
    }
}
