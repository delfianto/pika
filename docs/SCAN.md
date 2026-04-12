# scan — Memory Scanning Engine

The `scan` module implements the core scan-filter-narrow loop that locates game values
in a target process's memory. It is designed for high throughput (hundreds of MB/s) on
the large anonymous `rw-p` regions typical of Wine/Proton game heaps.

## Submodules

| Submodule | File | Purpose |
|---|---|---|
| `candidate` | `scan/candidate.rs` | Candidate addresses, type flags, value patterns |
| `engine` | `scan/engine.rs` | SIMD-parallel scanning, session management, AOB support |
| `filter` | `scan/filter.rs` | Multi-pass candidate narrowing |
| `pointer` | `scan/pointer.rs` | Pointer chain resolution via BFS |

---

## Scan workflow

A typical session follows this pattern:

```
User: "I have 847 gold"
  -> first_scan(pid, 847.0, Auto)
  -> 50,000 candidates

User: "I spent 50, now I have 797"
  -> filter_candidates(session, 797.0, Exact)
  -> 312 candidates

User: "I bought a potion, now 747"
  -> filter_candidates(session, 747.0, Exact)
  -> 3 candidates

User: "Freeze it at 999999"
  -> write_value / freeze_value on the correct address
```

### First scan

`first_scan` reads all `Safe` regions in parallel via rayon, searching for byte
patterns that match the target value in all plausible numeric types. The result is a
`ScanSession` containing potentially thousands of `Candidate` addresses.

### Filter passes

`filter_candidates` re-reads memory at every candidate address and retains only those
matching the filter criteria. After 2-4 passes, candidates typically narrow to a
handful of addresses.

---

## Candidate model (`candidate`)

### Candidate struct

```rust
pub struct Candidate {
    pub address: u64,        // Absolute virtual address in the target
    pub types: TypeFlags,    // Which type interpretations are still valid
    pub confidence: u8,      // Incremented on each confirming filter pass
    pub last_value: [u8; 8], // Raw bytes from last scan/filter (for comparison filters)
}
```

At 18 bytes per candidate (with padding), 1 million candidates consume ~18 MB.
Candidates are sorted by address for cache-friendly sequential access.

### Multi-type tracking

`TypeFlags` is a bitfield tracking which data type interpretations remain valid:

```rust
bitflags! {
    pub struct TypeFlags: u8 {
        const I32 = 0b0000_0001;
        const U32 = 0b0000_0010;
        const F32 = 0b0000_0100;
        const I64 = 0b0000_1000;
        const U64 = 0b0001_0000;
        const F64 = 0b0010_0000;
    }
}
```

On the first scan with `Auto` type, a candidate may have `I32 | U32` flags (the value
100 has the same byte pattern as both `i32` and `u32`). On subsequent `Exact` filter
passes, types whose byte pattern doesn't match the new value are eliminated. This
progressive narrowing lets the user find values without guessing the encoding.

### Value patterns

`encode_value_patterns` converts a numeric value into all plausible little-endian byte
representations. For example, the value `100.0` produces:

| Pattern | Type flags | Size | Epsilon? |
|---|---|---|---|
| `64 00 00 00` | `I32 \| U32` | 4 bytes | No |
| `00 00 c8 42` | `F32` | 4 bytes | Yes |
| `64 00 00 00 00 00 00 00` | `I64 \| U64` | 8 bytes | No |

The `f64` pattern is suppressed if it duplicates the `i64` byte representation.

---

## SIMD scan engine (`engine`)

### Architecture

```
Safe regions (from /proc/[pid]/maps)
    |
    |  rayon par_iter
    v
[Region 0]  [Region 1]  [Region 2]  ...
    |            |            |
    v            v            v
scan_region  scan_region  scan_region
    |            |            |
    |  4 MB chunked reads via process_vm_readv
    |  thread-local reusable buffer (RefCell<Vec<u8>>)
    v
scan_buffer_for_pattern  (per chunk, per pattern)
    |
    |  runtime feature detection
    v
AVX2 path      SSE2 path      Scalar path
(32 bytes/iter) (16 bytes/iter) (4 bytes/iter)
```

### SIMD implementations

**AVX2 (x86-64, 32 bytes per iteration):**
1. Broadcast target value to all 8 lanes of `__m256i`
2. Load 32 bytes from buffer (`_mm256_loadu_si256`)
3. Compare all 8 dwords simultaneously (`_mm256_cmpeq_epi32`)
4. Extract bitmask (`_mm256_movemask_epi8`)
5. Decode hit lanes from the 32-bit mask

**SSE2 (x86-64 fallback, 16 bytes per iteration):**
Same algorithm with `__m128i` (4 lanes). Always available on x86-64.

**Scalar (all platforms):**
Simple loop checking one value per iteration.

Runtime feature detection (`is_x86_feature_detected!("avx2")`) selects the fastest
available path.

### Float epsilon scanning

For `f32` values, exact byte matching misses values that have drifted due to
floating-point arithmetic (e.g., the game stores `99.999` instead of `100.0`). The
epsilon scan uses SIMD to compute `|buffer_value - target| <= 0.001`:

1. Load 8 floats from buffer (`_mm256_loadu_ps`)
2. Subtract target (`_mm256_sub_ps`)
3. Absolute value via sign-bit masking (`_mm256_andnot_ps` with `-0.0`)
4. Compare against epsilon (`_mm256_cmp_ps` with `_CMP_LE_OQ`)
5. Extract mask (`_mm256_movemask_ps`)

The epsilon value of `0.001` catches frame-delta drift without producing false
positives on unrelated float values.

### Thread-local buffers

Each rayon worker thread reuses a single 4 MB buffer stored in a `thread_local!`
`RefCell<Vec<u8>>`. This avoids per-region heap allocation. On borrow failure (should
not happen with rayon's work-stealing model), a fresh buffer is allocated as fallback.

### Session management

`SessionRegistry` stores active scan sessions in a `DashMap<String, ScanSession>`.
DashMap uses per-shard locking, so concurrent operations on different sessions never
contend. Session IDs are 12-character nanoids.

---

## Filter modes (`filter`)

| Mode | Comparison | Needs value? |
|---|---|---|
| `Exact` | Current memory equals target value | Yes |
| `NotEqual` | Current memory does not equal target value | Yes |
| `Increased` | Current memory > stored `last_value` | No |
| `Decreased` | Current memory < stored `last_value` | No |
| `Changed` | Current bytes differ from `last_value` | No |
| `Unchanged` | Current bytes same as `last_value` | No |

### Type narrowing

On `Exact` filter passes, the filter checks which specific type patterns matched and
removes type flags that didn't. For example, if a candidate has `I32 | U32 | F32`
and the `Exact` value `100` matches `I32 | U32` bytes but not `F32` bytes, the `F32`
flag is removed.

### Confidence tracking

Each successful filter pass increments the candidate's `confidence` counter (saturating
at 255). Higher confidence means the candidate has survived more filter passes and is
more likely to be the correct address. Candidates are reported to the user sorted by
confidence.

### Comparison filters

`Increased`/`Decreased`/`Changed`/`Unchanged` compare current memory against the
candidate's stored `last_value` from the previous pass. The comparison is performed
for each remaining type flag independently — if any type interpretation satisfies the
comparison, the candidate is retained (for `Increased`/`Decreased`).

---

## AOB / signature scanning (`engine`)

Array-of-bytes scanning finds a specific byte pattern in memory, optionally with
wildcards. This is used to locate code sequences (e.g., the instruction that subtracts
health) rather than data values.

### Pattern format

```
"48 89 5C 24 ?? 57"    # ?? = wildcard (matches any byte)
"48 * 5C 24 08"        # * also works as wildcard
```

### memchr-anchored search

Rather than checking the full pattern at every byte offset, the engine selects the
**rarest non-wildcard byte** in the pattern as a `memchr` anchor. `memchr` uses
SIMD internally to find the anchor byte, then the full pattern is verified only at
candidate positions. This dramatically reduces the number of full-pattern comparisons.

Byte rarity heuristic:
- `0x00`, `0xFF`: rarity 0 (extremely common in zeroed memory)
- `0x01-0x0F`, `0xF0-0xFE`: rarity 1
- `0x20-0x7E`: rarity 2 (ASCII range)
- Everything else: rarity 3 (instruction prefixes, rare opcodes)

### Sliding-window chunked reads

Memory is read in 4 MB chunks, but patterns can span chunk boundaries. The engine
carries over the last `pattern_length - 1` bytes from each chunk to the front of the
buffer for the next read, creating a sliding window that catches boundary-spanning
matches without re-reading from the kernel.

---

## Pointer chain resolution (`pointer`)

Windows heap addresses in Wine/Proton are randomized by ASLR on every game launch.
A raw address found by scanning is useless after a restart. Pointer chains provide
stable paths from module base addresses (which are stable within sessions and have
known offsets) to target values.

### Chain format

```
Game.exe+0x1234 -> [+0x48] -> [+0x10] -> target_value
```

Read: take the module base of `Game.exe`, add `0x1234`, dereference (read the
pointer), add `0x48`, dereference again, add `0x10` — you arrive at the target.

### BFS algorithm

```
Given target address T:

Queue = [(T, empty_chain)]
Visited = {T}

While queue is not empty and chains < max_results:
  Pop (target, chain_so_far)
  If chain depth >= max_depth: skip

  Scan all Safe+ReadOnly regions for pointer-sized (8-byte aligned) values
  in range [target - max_offset, target + max_offset]

  For each found pointer P at address A:
    offset = target - P
    new_chain = chain_so_far + Link(A, offset)

    If A is inside a known module:
      Record chain: module_name + (A - module_base) -> new_chain
    Else if depth < max_depth and A not visited:
      Enqueue (A, new_chain)
      Mark A visited
```

### Module identification

Modules are extracted from `/proc/[pid]/maps` by collecting unique pathnames (excluding
anonymous regions, `/dev/*`, and `NeverTouch` entries). The first mapping of each
pathname gives the module base; the last mapping gives the module end.

### Parameters

| Parameter | Default | Purpose |
|---|---|---|
| `max_offset` | 4096 | Maximum struct offset (game structs rarely exceed this) |
| `max_depth` | 5 | Maximum chain length |
| `max_results` | 100 | Maximum chains to return |

Results are sorted by chain length (shorter = more stable across game updates).

### Parallelism

Each BFS level scans all scannable regions for pointers to the current target. Region
scanning is parallelized with rayon, same as value scanning. The BFS queue itself is
processed sequentially (parallelizing across BFS levels would complicate visited-set
management without significant benefit, since the number of targets per level is small).
