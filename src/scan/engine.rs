use crate::scan::candidate::{Candidate, ValuePattern, ValueType, encode_value_patterns};
#[cfg(test)]
use crate::scan::candidate::TypeFlags;
use crate::process::maps::{MapRegion, RegionSafety};
use crate::mem::access::MemoryAccess;
use anyhow::Result;
use dashmap::DashMap;
use rayon::prelude::*;
use nid::Nanoid;
use std::cell::RefCell;

/// Default chunk size for `process_vm_readv` calls (4 MB).
const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

thread_local! {
    /// Per-thread reusable buffer for value scans, avoiding per-region heap allocation.
    static SCAN_BUFFER: RefCell<Vec<u8>> = RefCell::new(vec![0u8; DEFAULT_CHUNK_SIZE]);
}

/// A scan session tracks candidates across multiple scan/filter passes.
pub struct ScanSession {
    pub id: String,
    pub pid: u32,
    pub candidates: Vec<Candidate>,
    pub value: f64,
    pub dtype: ValueType,
}

/// Summary info for a scan session (for listing).
#[derive(Clone, Debug, serde::Serialize)]
pub struct SessionSummary {
    pub id: String,
    pub pid: u32,
    pub candidates: usize,
    pub value: f64,
    pub dtype: ValueType,
}

/// Global registry of active scan sessions.
///
/// Uses `DashMap` for per-shard locking so concurrent access to different
/// sessions never contends.
pub struct SessionRegistry {
    sessions: DashMap<String, ScanSession>,
}

impl SessionRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    pub fn insert(&self, session: ScanSession) {
        self.sessions.insert(session.id.clone(), session);
    }

    pub fn get_candidate_count(&self, session_id: &str) -> Option<usize> {
        self.sessions
            .get(session_id)
            .map(|entry| entry.candidates.len())
    }

    pub fn remove(&self, session_id: &str) -> Option<ScanSession> {
        self.sessions.remove(session_id).map(|(_, v)| v)
    }

    /// Access a session mutably via a closure.
    /// Only the shard containing this key is locked, not the entire registry.
    pub fn with_session<F, R>(&self, session_id: &str, f: F) -> Option<R>
    where
        F: FnOnce(&mut ScanSession) -> R,
    {
        self.sessions
            .get_mut(session_id)
            .map(|mut entry| f(entry.value_mut()))
    }

    /// List all active sessions with summary info.
    pub fn list(&self) -> Vec<SessionSummary> {
        self.sessions
            .iter()
            .map(|entry| {
                let s = entry.value();
                SessionSummary {
                    id: s.id.clone(),
                    pid: s.pid,
                    candidates: s.candidates.len(),
                    value: s.value,
                    dtype: s.dtype,
                }
            })
            .collect()
    }
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Perform a first scan across all Safe regions of a process.
/// Returns a new `ScanSession` with all matching candidates.
pub fn first_scan(
    mem: &dyn MemoryAccess,
    pid: u32,
    value: f64,
    dtype: ValueType,
) -> Result<ScanSession> {
    let regions = mem.read_maps(pid)?;
    let total_regions = regions.len();
    let safe_regions: Vec<&MapRegion> = regions
        .iter()
        .filter(|r| r.safety == RegionSafety::Safe && r.permissions.read)
        .collect();

    let total_scan_bytes: u64 = safe_regions.iter().map(|r| r.size()).sum();
    tracing::debug!(
        pid,
        total_regions,
        safe_regions = safe_regions.len(),
        scan_bytes = total_scan_bytes,
        "maps loaded, {:.1} MB to scan",
        total_scan_bytes as f64 / 1_048_576.0,
    );

    let patterns = encode_value_patterns(value);
    if patterns.is_empty() {
        anyhow::bail!("no valid byte patterns for value {value}");
    }

    // Filter patterns by dtype if not Auto
    let patterns: Vec<_> = if dtype == ValueType::Auto {
        patterns
    } else {
        let flag = dtype.to_flag();
        patterns
            .into_iter()
            .filter(|(_, f, _, _)| f.intersects(flag))
            .collect()
    };

    tracing::debug!(
        value,
        dtype = %dtype,
        patterns = patterns.len(),
        "scanning for value",
    );

    let scan_start = std::time::Instant::now();

    // Scan all safe regions in parallel
    let candidates: Vec<Candidate> = safe_regions
        .par_iter()
        .flat_map(|region| scan_region(mem, pid, region, &patterns).unwrap_or_default())
        .collect();

    let scan_elapsed = scan_start.elapsed();

    let mut sorted = candidates;
    sorted.sort_unstable();
    sorted.dedup_by_key(|c| c.address);

    let session_id = Nanoid::<12>::new().to_string();
    tracing::debug!(
        session_id = %session_id,
        candidates = sorted.len(),
        elapsed_ms = scan_elapsed.as_millis(),
        throughput_mb_s = format_args!("{:.0}", total_scan_bytes as f64 / scan_elapsed.as_secs_f64() / 1_048_576.0),
        "scan complete",
    );

    Ok(ScanSession {
        id: session_id,
        pid,
        candidates: sorted,
        value,
        dtype,
    })
}

/// Scan a single memory region for value patterns.
/// Uses a thread-local buffer to avoid per-region heap allocation.
fn scan_region(
    mem: &dyn MemoryAccess,
    pid: u32,
    region: &MapRegion,
    patterns: &[ValuePattern],
) -> Result<Vec<Candidate>> {
    let size = region.size() as usize;
    let chunk_size = if size <= DEFAULT_CHUNK_SIZE {
        size
    } else {
        DEFAULT_CHUNK_SIZE
    };

    SCAN_BUFFER.with(|cell| {
        match cell.try_borrow_mut() {
            Ok(mut buffer) => {
                if buffer.len() < chunk_size {
                    buffer.resize(chunk_size, 0);
                }
                scan_region_inner(mem, pid, region, patterns, size, chunk_size, &mut buffer)
            }
            Err(_) => {
                // Fallback: allocate a fresh buffer (shouldn't happen with Rayon)
                let mut buffer = vec![0u8; chunk_size];
                scan_region_inner(mem, pid, region, patterns, size, chunk_size, &mut buffer)
            }
        }
    })
}

/// Inner scan loop operating on a borrowed buffer.
fn scan_region_inner(
    mem: &dyn MemoryAccess,
    pid: u32,
    region: &MapRegion,
    patterns: &[ValuePattern],
    size: usize,
    chunk_size: usize,
    buffer: &mut [u8],
) -> Result<Vec<Candidate>> {
    let mut candidates = Vec::new();
    let mut offset = 0usize;

    while offset < size {
        let read_len = chunk_size.min(size - offset);
        let address = region.start + offset as u64;

        let Ok(bytes_read) = mem.read(pid, address, &mut buffer[..read_len]) else {
            break; // Region may have been unmapped
        };

        if bytes_read == 0 {
            break;
        }

        // Search this chunk for all patterns
        for &(ref pattern, flags, pat_size, use_epsilon) in patterns {
            let hits = if use_epsilon && pat_size == 4 {
                let target = f32::from_le_bytes(
                    pattern[..4].try_into().expect("4 bytes for f32"),
                );
                scan_f32_epsilon(&buffer[..bytes_read], target, F32_EPSILON, pat_size)
            } else {
                scan_buffer_for_pattern(&buffer[..bytes_read], &pattern[..pat_size], pat_size)
            };
            for buf_offset in hits {
                // Copy up to 8 bytes at the match position for last_value snapshot
                let mut last_value = [0u8; 8];
                let copy_len = 8.min(bytes_read - buf_offset);
                last_value[..copy_len]
                    .copy_from_slice(&buffer[buf_offset..buf_offset + copy_len]);
                candidates.push(Candidate::with_value(
                    address + buf_offset as u64,
                    flags,
                    last_value,
                ));
            }
        }

        offset += bytes_read;
        if bytes_read < read_len {
            break; // Partial read, rest of region is unmapped
        }
    }

    Ok(candidates)
}

/// Search a byte buffer for all aligned occurrences of a pattern.
/// Returns offsets within the buffer where the pattern was found.
///
/// Uses SIMD acceleration when available (AVX2 or SSE2 on x86_64),
/// falls back to scalar search otherwise.
fn scan_buffer_for_pattern(buffer: &[u8], pattern: &[u8], alignment: usize) -> Vec<usize> {
    match pattern.len() {
        4 => scan_4byte_aligned(buffer, pattern, alignment),
        8 => scan_8byte_aligned(buffer, pattern, alignment),
        _ => scan_generic(buffer, pattern, alignment),
    }
}

/// Scan for a 4-byte pattern at `alignment`-byte boundaries.
fn scan_4byte_aligned(buffer: &[u8], pattern: &[u8], alignment: usize) -> Vec<usize> {
    debug_assert_eq!(pattern.len(), 4);
    let needle = u32::from_le_bytes([pattern[0], pattern[1], pattern[2], pattern[3]]);

    // Try SIMD first, fall back to scalar
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 confirmed available by runtime check
            return unsafe { scan_4byte_avx2(buffer, needle, alignment) };
        }
        // SSE2 is always available on x86_64
        // SAFETY: SSE2 guaranteed on x86_64
        return unsafe { scan_4byte_sse2(buffer, needle, alignment) };
    }

    #[cfg(not(target_arch = "x86_64"))]
    scan_4byte_scalar(buffer, needle, alignment)
}

/// Scan for an 8-byte pattern at `alignment`-byte boundaries.
fn scan_8byte_aligned(buffer: &[u8], pattern: &[u8], alignment: usize) -> Vec<usize> {
    debug_assert_eq!(pattern.len(), 8);
    let needle = u64::from_le_bytes([
        pattern[0], pattern[1], pattern[2], pattern[3], pattern[4], pattern[5], pattern[6],
        pattern[7],
    ]);

    let mut results = Vec::new();
    let mut offset = 0;
    while offset + 8 <= buffer.len() {
        let val = u64::from_le_bytes(
            buffer[offset..offset + 8]
                .try_into()
                .expect("slice length is 8"),
        );
        if val == needle {
            results.push(offset);
        }
        offset += alignment;
    }
    results
}

/// Generic pattern scan (fallback for unusual sizes).
fn scan_generic(buffer: &[u8], pattern: &[u8], alignment: usize) -> Vec<usize> {
    let mut results = Vec::new();
    let pat_len = pattern.len();
    let mut offset = 0;
    while offset + pat_len <= buffer.len() {
        if buffer[offset..offset + pat_len] == *pattern {
            results.push(offset);
        }
        offset += alignment;
    }
    results
}

/// Scalar 4-byte scan (fallback).
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
fn scan_4byte_scalar(buffer: &[u8], needle: u32, alignment: usize) -> Vec<usize> {
    let mut results = Vec::new();
    let mut offset = 0;
    while offset + 4 <= buffer.len() {
        let val = u32::from_le_bytes(
            buffer[offset..offset + 4]
                .try_into()
                .expect("slice length is 4"),
        );
        if val == needle {
            results.push(offset);
        }
        offset += alignment;
    }
    results
}

// ─── x86_64 SIMD implementations ────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// AVX2 scan: processes 32 bytes (8 x i32) per iteration.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_4byte_avx2(buffer: &[u8], needle: u32, alignment: usize) -> Vec<usize> {
    let mut results = Vec::new();
    let len = buffer.len();
    if len < 32 {
        return scan_4byte_scalar(buffer, needle, alignment);
    }

    // AVX2 confirmed available by caller via `is_x86_feature_detected!`.
    let needle_vec = _mm256_set1_epi32(needle as i32);
    let ptr = buffer.as_ptr();
    let end = len.saturating_sub(31);

    let mut offset = 0;
    while offset < end {
        // SAFETY: offset + 32 <= len checked by loop condition; ptr is valid for buffer.
        let chunk = unsafe { _mm256_loadu_si256(ptr.add(offset).cast::<__m256i>()) };
        let cmp = _mm256_cmpeq_epi32(chunk, needle_vec);
        let mask = _mm256_movemask_epi8(cmp) as u32;

        if mask != 0 {
            // Each matching i32 lane produces 4 consecutive 1-bits in the mask.
            for lane in 0..8u32 {
                let lane_bits = 0xFu32 << (lane * 4);
                if mask & lane_bits == lane_bits {
                    let candidate_offset = offset + (lane as usize) * 4;
                    // Only report if aligned
                    if candidate_offset % alignment == 0 {
                        results.push(candidate_offset);
                    }
                }
            }
        }
        // Advance by 32 bytes for aligned-to-32 scanning,
        // but we need to handle alignment properly
        offset += 32;
    }

    // Handle tail bytes with scalar scan
    let mut tail_offset = offset;
    while tail_offset + 4 <= len {
        if tail_offset % alignment == 0 {
            let val = u32::from_le_bytes(
                buffer[tail_offset..tail_offset + 4]
                    .try_into()
                    .expect("4 bytes"),
            );
            if val == needle {
                results.push(tail_offset);
            }
        }
        tail_offset += alignment;
    }

    results
}

/// SSE2 scan: processes 16 bytes (4 x i32) per iteration.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn scan_4byte_sse2(buffer: &[u8], needle: u32, alignment: usize) -> Vec<usize> {
    let mut results = Vec::new();
    let len = buffer.len();
    if len < 16 {
        return scan_4byte_scalar(buffer, needle, alignment);
    }

    // SSE2 always available on x86_64.
    let needle_vec = _mm_set1_epi32(needle as i32);
    let ptr = buffer.as_ptr();
    let end = len.saturating_sub(15);

    let mut offset = 0;
    while offset < end {
        // SAFETY: offset + 16 <= len checked by loop condition; ptr is valid for buffer.
        let chunk = unsafe { _mm_loadu_si128(ptr.add(offset).cast::<__m128i>()) };
        let cmp = _mm_cmpeq_epi32(chunk, needle_vec);
        let mask = _mm_movemask_epi8(cmp) as u32;

        if mask != 0 {
            for lane in 0..4u32 {
                let lane_bits = 0xFu32 << (lane * 4);
                if mask & lane_bits == lane_bits {
                    let candidate_offset = offset + (lane as usize) * 4;
                    if candidate_offset % alignment == 0 {
                        results.push(candidate_offset);
                    }
                }
            }
        }
        offset += 16;
    }

    // Tail
    while offset + 4 <= len {
        if offset % alignment == 0 {
            let val = u32::from_le_bytes(
                buffer[offset..offset + 4]
                    .try_into()
                    .expect("4 bytes"),
            );
            if val == needle {
                results.push(offset);
            }
        }
        offset += alignment;
    }

    results
}

// ─── Float epsilon scanning ──────────────────────────────────────────────────

/// Absolute tolerance for f32 approximate matching.
/// 0.001 catches frame-delta drift (99.999 vs 100.0) without false positives.
const F32_EPSILON: f32 = 0.001;

/// Scan for f32 values within epsilon tolerance.
/// Returns offsets where `|buffer_value - target| <= epsilon` and the value is finite.
fn scan_f32_epsilon(buffer: &[u8], target: f32, epsilon: f32, alignment: usize) -> Vec<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 confirmed available by runtime check
            return unsafe { scan_f32_epsilon_avx2(buffer, target, epsilon, alignment) };
        }
    }
    scan_f32_epsilon_scalar(buffer, target, epsilon, alignment)
}

/// Scalar f32 epsilon scan (fallback for non-x86 or when AVX2 is unavailable).
fn scan_f32_epsilon_scalar(
    buffer: &[u8],
    target: f32,
    epsilon: f32,
    alignment: usize,
) -> Vec<usize> {
    let mut results = Vec::new();
    let mut offset = 0;
    while offset + 4 <= buffer.len() {
        if offset % alignment == 0 {
            let val = f32::from_le_bytes(
                buffer[offset..offset + 4]
                    .try_into()
                    .expect("slice length is 4"),
            );
            if val.is_finite() && (val - target).abs() <= epsilon {
                results.push(offset);
            }
        }
        offset += alignment;
    }
    results
}

/// AVX2 f32 epsilon scan: processes 8 floats (32 bytes) per iteration.
/// Uses `|chunk - target| <= epsilon` with SIMD abs via sign-bit masking.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_f32_epsilon_avx2(
    buffer: &[u8],
    target: f32,
    epsilon: f32,
    alignment: usize,
) -> Vec<usize> {
    let target_vec = _mm256_set1_ps(target);
    let eps_vec = _mm256_set1_ps(epsilon);
    // Sign-bit mask for abs: andnot with -0.0 clears the sign bit
    let sign_mask = _mm256_set1_ps(-0.0_f32);

    let mut results = Vec::new();
    let len = buffer.len();
    if len < 32 {
        return scan_f32_epsilon_scalar(buffer, target, epsilon, alignment);
    }

    let ptr = buffer.as_ptr();
    let end = len.saturating_sub(31);
    let mut offset = 0;

    while offset < end {
        // SAFETY: offset + 32 <= len checked by loop condition
        let chunk = _mm256_loadu_ps(ptr.add(offset).cast::<f32>());
        let diff = _mm256_sub_ps(chunk, target_vec);
        let abs_diff = _mm256_andnot_ps(sign_mask, diff);
        let within = _mm256_cmp_ps::<_CMP_LE_OQ>(abs_diff, eps_vec);
        let mask = _mm256_movemask_ps(within) as u32;

        if mask != 0 {
            for lane in 0..8u32 {
                if mask & (1 << lane) != 0 {
                    let candidate_offset = offset + (lane as usize) * 4;
                    if candidate_offset % alignment == 0 {
                        results.push(candidate_offset);
                    }
                }
            }
        }
        offset += 32;
    }

    // Scalar tail
    while offset + 4 <= len {
        if offset % alignment == 0 {
            let val = f32::from_le_bytes(
                buffer[offset..offset + 4]
                    .try_into()
                    .expect("4 bytes"),
            );
            if val.is_finite() && (val - target).abs() <= epsilon {
                results.push(offset);
            }
        }
        offset += alignment;
    }

    results
}

// ─── AOB / Signature scanning ────────────────────────────────────────────────

/// Parse an AOB pattern string like "48 89 5C 24 ?? 57" into a byte pattern.
/// `??` or `*` are wildcards (match any byte).
pub fn parse_aob_pattern(pattern: &str) -> Result<Vec<Option<u8>>> {
    pattern
        .split_whitespace()
        .map(|token| {
            if token == "??" || token == "?" || token == "*" {
                Ok(None)
            } else {
                u8::from_str_radix(token, 16)
                    .map(Some)
                    .map_err(|_| anyhow::anyhow!("invalid hex byte in AOB pattern: '{token}'"))
            }
        })
        .collect()
}

/// Scan process memory for an AOB (array of bytes) pattern with optional wildcards.
/// Returns matching addresses.
pub fn aob_scan(
    mem: &dyn MemoryAccess,
    pid: u32,
    pattern: &[Option<u8>],
    include_readonly: bool,
) -> Result<Vec<u64>> {
    if pattern.is_empty() {
        anyhow::bail!("AOB pattern is empty");
    }

    let regions = mem.read_maps(pid)?;
    let scan_regions: Vec<&MapRegion> = regions
        .iter()
        .filter(|r| {
            r.permissions.read
                && match r.safety {
                    RegionSafety::Safe => true,
                    RegionSafety::ReadOnly => include_readonly,
                    _ => false,
                }
        })
        .collect();

    let total_bytes: u64 = scan_regions.iter().map(|r| r.size()).sum();
    tracing::debug!(
        pid,
        pattern_len = pattern.len(),
        regions = scan_regions.len(),
        scan_bytes = total_bytes,
        include_readonly,
        "AOB scan starting, {:.1} MB to search",
        total_bytes as f64 / 1_048_576.0,
    );

    let aob_start = std::time::Instant::now();

    // Pick the rarest non-wildcard byte as memchr anchor.
    let anchor = pick_aob_anchor(pattern);

    let results: Vec<u64> = scan_regions
        .par_iter()
        .flat_map(|region| aob_scan_region(mem, pid, region, pattern, anchor).unwrap_or_default())
        .collect();

    tracing::debug!(
        matches = results.len(),
        elapsed_ms = aob_start.elapsed().as_millis(),
        "AOB scan complete",
    );

    Ok(results)
}

/// Scan a single region for an AOB pattern.
///
/// Uses a sliding window to avoid redundant syscalls at chunk boundaries:
/// the last `pat_len - 1` bytes of each chunk are carried over to the front
/// of the buffer for the next read, so matches spanning chunks are found
/// without re-reading from the kernel.
fn aob_scan_region(
    mem: &dyn MemoryAccess,
    pid: u32,
    region: &MapRegion,
    pattern: &[Option<u8>],
    anchor: Option<(usize, u8)>,
) -> Result<Vec<u64>> {
    aob_scan_region_chunked(mem, pid, region, pattern, anchor, DEFAULT_CHUNK_SIZE)
}

/// Inner implementation with configurable chunk size (for testing boundary conditions).
fn aob_scan_region_chunked(
    mem: &dyn MemoryAccess,
    pid: u32,
    region: &MapRegion,
    pattern: &[Option<u8>],
    anchor: Option<(usize, u8)>,
    max_chunk: usize,
) -> Result<Vec<u64>> {
    let size = region.size() as usize;
    let pat_len = pattern.len();
    if size < pat_len {
        return Ok(Vec::new());
    }

    let chunk_size = if size <= max_chunk { size } else { max_chunk };

    SCAN_BUFFER.with(|cell| {
        match cell.try_borrow_mut() {
            Ok(mut buffer) => {
                if buffer.len() < chunk_size {
                    buffer.resize(chunk_size, 0);
                }
                aob_scan_region_inner(mem, pid, region, pattern, anchor, size, pat_len, chunk_size, &mut buffer)
            }
            Err(_) => {
                let mut buffer = vec![0u8; chunk_size];
                aob_scan_region_inner(mem, pid, region, pattern, anchor, size, pat_len, chunk_size, &mut buffer)
            }
        }
    })
}

/// Inner AOB scan loop operating on a borrowed buffer.
#[allow(clippy::too_many_arguments)]
fn aob_scan_region_inner(
    mem: &dyn MemoryAccess,
    pid: u32,
    region: &MapRegion,
    pattern: &[Option<u8>],
    anchor: Option<(usize, u8)>,
    size: usize,
    pat_len: usize,
    chunk_size: usize,
    buffer: &mut [u8],
) -> Result<Vec<u64>> {
    let overlap = pat_len - 1;
    let mut results = Vec::new();
    let mut offset = 0usize;
    let mut prefix_len = 0usize;

    while offset < size {
        let max_new = chunk_size - prefix_len;
        let read_len = max_new.min(size - offset);
        let address = region.start + offset as u64;

        let Ok(bytes_read) = mem.read(pid, address, &mut buffer[prefix_len..prefix_len + read_len]) else {
            break;
        };

        let total = prefix_len + bytes_read;
        if total < pat_len {
            break;
        }

        let base_address = region.start + (offset as u64) - (prefix_len as u64);

        let buf = &buffer[..total];
        match anchor {
            Some((anchor_offset, anchor_byte)) => {
                let mut pos = 0;
                while pos + pat_len <= buf.len() {
                    let search_start = pos + anchor_offset;
                    if search_start >= buf.len() {
                        break;
                    }
                    match memchr::memchr(anchor_byte, &buf[search_start..]) {
                        Some(found) => {
                            let candidate_start = search_start + found - anchor_offset;
                            if candidate_start + pat_len <= buf.len()
                                && aob_matches(&buf[candidate_start..candidate_start + pat_len], pattern)
                            {
                                results.push(base_address + candidate_start as u64);
                            }
                            pos = candidate_start + 1;
                        }
                        None => break,
                    }
                }
            }
            None => {
                for pos in 0..=buf.len() - pat_len {
                    if aob_matches(&buf[pos..pos + pat_len], pattern) {
                        results.push(base_address + pos as u64);
                    }
                }
            }
        }

        offset += bytes_read;

        if offset < size && total >= overlap {
            buffer.copy_within(total - overlap..total, 0);
            prefix_len = overlap;
        } else {
            prefix_len = 0;
        }

        if bytes_read < read_len {
            break;
        }
    }

    Ok(results)
}

/// Pick the best anchor byte for memchr in an AOB pattern.
///
/// Prefers rare bytes (instruction prefixes, high-nibble values) over common
/// ones (0x00, 0xFF) to minimize false hits during memchr scanning.
fn pick_aob_anchor(pattern: &[Option<u8>]) -> Option<(usize, u8)> {
    fn byte_rarity(b: u8) -> u8 {
        match b {
            0x00 | 0xFF => 0,
            0x01..=0x0F | 0xF0..=0xFE => 1,
            0x20..=0x7E => 2,
            _ => 3,
        }
    }

    pattern
        .iter()
        .enumerate()
        .filter_map(|(i, b)| b.map(|byte| (i, byte)))
        .max_by_key(|&(_, byte)| byte_rarity(byte))
}

/// Check if a byte slice matches an AOB pattern (with wildcards).
fn aob_matches(data: &[u8], pattern: &[Option<u8>]) -> bool {
    data.len() == pattern.len()
        && data
            .iter()
            .zip(pattern.iter())
            .all(|(d, p)| match p {
                Some(expected) => *d == *expected,
                None => true, // wildcard
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::maps::{MapRegion, Permissions};
    use crate::mem::access::MockMemoryAccess;

    /// Helper: create a buffer with a known i32 value at specific offsets.
    fn buffer_with_i32(size: usize, value: i32, offsets: &[usize]) -> Vec<u8> {
        let mut buf = vec![0u8; size];
        let bytes = value.to_le_bytes();
        for &off in offsets {
            buf[off..off + 4].copy_from_slice(&bytes);
        }
        buf
    }

    // ─── SIMD scan tests ────────────────────────────────────────────────────

    #[test]
    fn scan_4byte_finds_single_value() {
        let buf = buffer_with_i32(1024, 42, &[100]);
        let results = scan_buffer_for_pattern(&buf, &42_i32.to_le_bytes(), 4);
        assert_eq!(results, vec![100]);
    }

    #[test]
    fn scan_4byte_finds_multiple_values() {
        let buf = buffer_with_i32(1024, 42, &[0, 100, 200, 500, 1000]);
        let results = scan_buffer_for_pattern(&buf, &42_i32.to_le_bytes(), 4);
        assert_eq!(results, vec![0, 100, 200, 500, 1000]);
    }

    #[test]
    fn scan_4byte_no_match() {
        let buf = vec![0u8; 1024];
        let results = scan_buffer_for_pattern(&buf, &42_i32.to_le_bytes(), 4);
        assert!(results.is_empty());
    }

    #[test]
    fn scan_4byte_zero_value() {
        // Buffer is all zeros, searching for 0 should match at every 4-byte offset
        let buf = vec![0u8; 64];
        let results = scan_buffer_for_pattern(&buf, &0_i32.to_le_bytes(), 4);
        assert_eq!(results.len(), 16); // 64 / 4
    }

    #[test]
    fn scan_4byte_at_end_of_buffer() {
        let mut buf = vec![0u8; 36]; // 32 + 4, so the value is in the tail
        let bytes = 99_i32.to_le_bytes();
        buf[32..36].copy_from_slice(&bytes);
        let results = scan_buffer_for_pattern(&buf, &bytes, 4);
        assert!(results.contains(&32));
    }

    #[test]
    fn scan_4byte_small_buffer() {
        let buf = 42_i32.to_le_bytes();
        let results = scan_buffer_for_pattern(&buf, &buf, 4);
        assert_eq!(results, vec![0]);
    }

    #[test]
    fn scan_8byte_finds_value() {
        let mut buf = vec![0u8; 128];
        let val = 123_456_789_i64;
        let bytes = val.to_le_bytes();
        buf[64..72].copy_from_slice(&bytes);
        let results = scan_buffer_for_pattern(&buf, &bytes, 8);
        assert!(results.contains(&64));
    }

    #[test]
    fn scan_f32_value() {
        let mut buf = vec![0u8; 256];
        let val = 3.14_f32;
        let bytes = val.to_le_bytes();
        buf[100..104].copy_from_slice(&bytes);
        let results = scan_buffer_for_pattern(&buf, &bytes, 4);
        assert!(results.contains(&100));
    }

    #[test]
    fn scan_4byte_alignment_4() {
        // Place value at offset 2 (not 4-byte aligned)
        let mut buf = vec![0u8; 64];
        let bytes = 42_i32.to_le_bytes();
        buf[2..6].copy_from_slice(&bytes);
        // With 4-byte alignment, offset 2 should NOT be found
        let results = scan_4byte_aligned(&buf, &bytes, 4);
        assert!(!results.contains(&2));
    }

    // ─── Full scan integration tests ────────────────────────────────────────

    #[test]
    fn first_scan_with_mock_memory() {
        let mock = MockMemoryAccess::new(100);

        // Set up a 16KB safe region
        let mut data = vec![0u8; 16384];
        // Place value 100 (i32) at known offsets
        for offset in [0x100, 0x200, 0x1000] {
            data[offset..offset + 4].copy_from_slice(&100_i32.to_le_bytes());
        }
        mock.add_region(0x14000_0000, data);

        let safe_region = MapRegion {
            start: 0x14000_0000,
            end: 0x14000_4000,
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
        };
        mock.set_maps(vec![safe_region]);

        let session = first_scan(&mock, 100, 100.0, ValueType::I32).unwrap();
        assert!(!session.candidates.is_empty());
        // Should find at least our 3 planted values
        let addresses: Vec<u64> = session.candidates.iter().map(|c| c.address).collect();
        assert!(addresses.contains(&0x14000_0100));
        assert!(addresses.contains(&0x14000_0200));
        assert!(addresses.contains(&0x14000_1000));
    }

    #[test]
    fn first_scan_skips_never_touch_regions() {
        let mock = MockMemoryAccess::new(100);

        // GPU region (NeverTouch)
        mock.add_region(0x7f00_0000_0000, vec![42; 4096]);
        // Safe region
        let mut safe_data = vec![0u8; 4096];
        safe_data[0..4].copy_from_slice(&42_i32.to_le_bytes());
        mock.add_region(0x14000_0000, safe_data);

        mock.set_maps(vec![
            MapRegion {
                start: 0x7f00_0000_0000,
                end: 0x7f00_0000_1000,
                permissions: Permissions { read: true, write: true, execute: false, shared: true },
                offset: 0,
                device: "00:06".to_string(),
                inode: 1111,
                pathname: "/dev/nvidia0".to_string(),
                safety: RegionSafety::NeverTouch,
            },
            MapRegion {
                start: 0x14000_0000,
                end: 0x14000_1000,
                permissions: Permissions { read: true, write: true, execute: false, shared: false },
                offset: 0,
                device: "00:00".to_string(),
                inode: 0,
                pathname: String::new(),
                safety: RegionSafety::Safe,
            },
        ]);

        let session = first_scan(&mock, 100, 42.0, ValueType::I32).unwrap();
        // Should only find the value in the Safe region, not the GPU region
        for c in &session.candidates {
            assert!(c.address < 0x7f00_0000_0000, "found candidate in GPU region!");
        }
    }

    #[test]
    fn first_scan_auto_finds_multiple_types() {
        let mock = MockMemoryAccess::new(100);
        let mut data = vec![0u8; 4096];
        // Place i32 value 100 at offset 0
        data[0..4].copy_from_slice(&100_i32.to_le_bytes());
        // Place f32 value 100.0 at offset 100 (different bit pattern)
        data[100..104].copy_from_slice(&100.0_f32.to_le_bytes());
        mock.add_region(0x1000, data);

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

        let session = first_scan(&mock, 100, 100.0, ValueType::Auto).unwrap();
        // Should find both the i32 and f32 representations
        let has_i32 = session.candidates.iter().any(|c| c.types.contains(TypeFlags::I32));
        let has_f32 = session.candidates.iter().any(|c| c.types.contains(TypeFlags::F32));
        assert!(has_i32, "should find i32 representation of 100");
        assert!(has_f32, "should find f32 representation of 100.0");
    }

    #[test]
    fn session_registry_basic() {
        let registry = SessionRegistry::new();
        let session = ScanSession {
            id: "test-123".to_string(),
            pid: 1,
            candidates: vec![Candidate::new(0x1000, TypeFlags::I32)],
            value: 42.0,
            dtype: ValueType::I32,
        };
        registry.insert(session);

        assert_eq!(registry.get_candidate_count("test-123"), Some(1));
        assert_eq!(registry.get_candidate_count("nonexistent"), None);

        let removed = registry.remove("test-123");
        assert!(removed.is_some());
        assert_eq!(registry.get_candidate_count("test-123"), None);
    }

    // ─── AOB tests ──────────────────────────────────────────────────────

    #[test]
    fn parse_aob_basic() {
        let pat = parse_aob_pattern("48 89 5C 24 08").unwrap();
        assert_eq!(pat, vec![Some(0x48), Some(0x89), Some(0x5C), Some(0x24), Some(0x08)]);
    }

    #[test]
    fn parse_aob_with_wildcards() {
        let pat = parse_aob_pattern("48 ?? 5C ?? 08").unwrap();
        assert_eq!(pat, vec![Some(0x48), None, Some(0x5C), None, Some(0x08)]);
    }

    #[test]
    fn parse_aob_star_wildcard() {
        let pat = parse_aob_pattern("48 * 5C").unwrap();
        assert_eq!(pat, vec![Some(0x48), None, Some(0x5C)]);
    }

    #[test]
    fn parse_aob_invalid_hex() {
        let result = parse_aob_pattern("48 ZZ 5C");
        assert!(result.is_err());
    }

    #[test]
    fn aob_matches_exact() {
        assert!(aob_matches(&[0x48, 0x89, 0x5C], &[Some(0x48), Some(0x89), Some(0x5C)]));
    }

    #[test]
    fn aob_matches_wildcards() {
        assert!(aob_matches(&[0x48, 0xFF, 0x5C], &[Some(0x48), None, Some(0x5C)]));
    }

    #[test]
    fn aob_no_match() {
        assert!(!aob_matches(&[0x48, 0x89, 0x00], &[Some(0x48), Some(0x89), Some(0x5C)]));
    }

    #[test]
    fn aob_scan_finds_pattern_in_mock() {
        let mock = MockMemoryAccess::new(1);
        let mut data = vec![0u8; 4096];
        // Plant pattern at offset 100: 48 89 5C 24 08
        data[100] = 0x48;
        data[101] = 0x89;
        data[102] = 0x5C;
        data[103] = 0x24;
        data[104] = 0x08;
        // Plant another at offset 500
        data[500] = 0x48;
        data[501] = 0x89;
        data[502] = 0x5C;
        data[503] = 0x24;
        data[504] = 0x08;
        mock.add_region(0x14000_0000, data);
        mock.set_maps(vec![MapRegion {
            start: 0x14000_0000,
            end: 0x14000_1000,
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

        let pattern = parse_aob_pattern("48 89 5C 24 08").unwrap();
        let results = aob_scan(&mock, 1, &pattern, false).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.contains(&(0x14000_0000 + 100)));
        assert!(results.contains(&(0x14000_0000 + 500)));
    }

    #[test]
    fn aob_scan_with_wildcards() {
        let mock = MockMemoryAccess::new(1);
        let mut data = vec![0u8; 256];
        data[10] = 0x48;
        data[11] = 0xAA; // wildcard position
        data[12] = 0x5C;
        data[20] = 0x48;
        data[21] = 0xBB; // different byte at wildcard
        data[22] = 0x5C;
        mock.add_region(0x1000, data);
        mock.set_maps(vec![MapRegion {
            start: 0x1000,
            end: 0x1100,
            permissions: Permissions { read: true, write: true, execute: false, shared: false },
            offset: 0, device: "00:00".to_string(), inode: 0, pathname: String::new(),
            safety: RegionSafety::Safe,
        }]);

        let pattern = parse_aob_pattern("48 ?? 5C").unwrap();
        let results = aob_scan(&mock, 1, &pattern, false).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn aob_scan_respects_safety() {
        let mock = MockMemoryAccess::new(1);
        let mut data = vec![0u8; 256];
        data[0] = 0xAA;
        data[1] = 0xBB;
        mock.add_region(0x1000, data);
        mock.set_maps(vec![MapRegion {
            start: 0x1000,
            end: 0x1100,
            permissions: Permissions { read: true, write: true, execute: false, shared: true },
            offset: 0, device: "00:06".to_string(), inode: 1111,
            pathname: "/dev/nvidia0".to_string(),
            safety: RegionSafety::NeverTouch,
        }]);

        let pattern = parse_aob_pattern("AA BB").unwrap();
        let results = aob_scan(&mock, 1, &pattern, false).unwrap();
        assert!(results.is_empty(), "should not scan NeverTouch regions");
    }

    #[test]
    fn aob_scan_finds_pattern_spanning_chunk_boundary() {
        // Use a small chunk size (32 bytes) so the pattern at offset 30
        // straddles the boundary between chunk 0 (bytes 0..32) and chunk 1.
        let mock = MockMemoryAccess::new(1);
        let mut data = vec![0u8; 128];
        // Pattern "AA BB CC DD EE" at offset 30 -- spans bytes 30..35
        data[30] = 0xAA;
        data[31] = 0xBB;
        data[32] = 0xCC;
        data[33] = 0xDD;
        data[34] = 0xEE;
        // Also plant one entirely within a chunk at offset 10
        data[10] = 0xAA;
        data[11] = 0xBB;
        data[12] = 0xCC;
        data[13] = 0xDD;
        data[14] = 0xEE;
        mock.add_region(0x5000, data);

        let region = MapRegion {
            start: 0x5000,
            end: 0x5080,
            permissions: Permissions { read: true, write: true, execute: false, shared: false },
            offset: 0, device: "00:00".to_string(), inode: 0, pathname: String::new(),
            safety: RegionSafety::Safe,
        };

        let pattern = parse_aob_pattern("AA BB CC DD EE").unwrap();
        let anchor = pick_aob_anchor(&pattern);
        let results = aob_scan_region_chunked(&mock, 1, &region, &pattern, anchor, 32).unwrap();

        assert_eq!(results.len(), 2, "should find both the in-chunk and boundary-spanning match");
        assert!(results.contains(&(0x5000 + 10)), "should find match at offset 10");
        assert!(results.contains(&(0x5000 + 30)), "should find match at offset 30 (spans chunk boundary)");
    }

    #[test]
    fn pick_aob_anchor_avoids_zero() {
        let pattern = parse_aob_pattern("00 00 ?? 48 89").unwrap();
        let anchor = pick_aob_anchor(&pattern);
        // Should pick 0x48 or 0x89 (rarity=3), NOT 0x00 (rarity=0)
        assert!(anchor.is_some());
        let (_, byte) = anchor.unwrap();
        assert!(byte == 0x48 || byte == 0x89, "anchor should be a rare byte, got {byte:#x}");
    }

    #[test]
    fn pick_aob_anchor_avoids_ff() {
        let pattern = parse_aob_pattern("FF ?? 90").unwrap();
        let anchor = pick_aob_anchor(&pattern);
        assert_eq!(anchor, Some((2, 0x90)), "should prefer 0x90 over 0xFF");
    }

    #[test]
    fn pick_aob_anchor_all_wildcards() {
        let pattern = parse_aob_pattern("?? ??").unwrap();
        assert_eq!(pick_aob_anchor(&pattern), None);
    }

    #[test]
    fn pick_aob_anchor_all_literal() {
        let pattern = parse_aob_pattern("48 89 5C").unwrap();
        let anchor = pick_aob_anchor(&pattern);
        assert!(anchor.is_some());
        // All are rarity=3, any is valid -- just verify it's one of them
        let (idx, byte) = anchor.unwrap();
        assert!(pattern[idx] == Some(byte));
    }
}
