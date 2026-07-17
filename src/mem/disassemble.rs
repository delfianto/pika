use crate::mem::access::MemoryAccess;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// A single disassembled instruction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Instruction {
    pub address: String,
    pub bytes: String,
    pub mnemonic: String,
    pub op_str: String,
}

/// Disassemble machine code at a given address in a target process.
///
/// On Linux: reads bytes from the target process and disassembles via capstone.
/// On other platforms: returns an error (capstone is Linux-only).
#[cfg(target_os = "linux")]
pub fn disassemble_at(
    mem: &dyn MemoryAccess,
    pid: u32,
    address: u64,
    num_instructions: usize,
) -> Result<Vec<Instruction>> {
    use capstone::prelude::*;

    // x86_64 instructions are 1-15 bytes. Read enough for the requested count.
    let read_size = num_instructions * 15;
    let mut buffer = vec![0u8; read_size];
    let bytes_read = mem.read(pid, address, &mut buffer)?;
    buffer.truncate(bytes_read);

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(false)
        .build()
        .map_err(|e| anyhow::anyhow!("capstone init failed: {e}"))?;

    let insns = cs
        .disasm_count(&buffer, address, num_instructions)
        .map_err(|e| anyhow::anyhow!("disassembly failed: {e}"))?;

    Ok(insns
        .iter()
        .map(|i| {
            let bytes_hex: String = i
                .bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            Instruction {
                address: format!("{:#x}", i.address()),
                bytes: bytes_hex,
                mnemonic: i.mnemonic().unwrap_or("???").to_string(),
                op_str: i.op_str().unwrap_or("").to_string(),
            }
        })
        .collect())
}

#[cfg(not(target_os = "linux"))]
pub fn disassemble_at(
    _mem: &dyn MemoryAccess,
    _pid: u32,
    _address: u64,
    _num_instructions: usize,
) -> Result<Vec<Instruction>> {
    anyhow::bail!("disassembly requires Linux (capstone is not available on this platform)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruction_serialization() {
        let insn = Instruction {
            address: "0x140001000".to_string(),
            bytes: "48 89 5c 24 08".to_string(),
            mnemonic: "mov".to_string(),
            op_str: "qword ptr [rsp + 8], rbx".to_string(),
        };
        let json = serde_json::to_string(&insn).unwrap();
        let parsed: Instruction = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mnemonic, "mov");
        assert_eq!(parsed.address, "0x140001000");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn disassemble_errors_on_non_linux() {
        let mock = crate::mem::access::MockMemoryAccess::new(1);
        mock.add_region(0x1000, vec![0x90; 64]); // NOP sled
        let result = disassemble_at(&mock, 1, 0x1000, 5);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("requires Linux"));
    }
}
