use std::fmt;

use fyida_core::{PeImage, PeKind, RawArch, RawImage};
use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, OpKind,
    Register,
};

const DEFAULT_MAX_BYTES: usize = 256;
pub const DEFAULT_MAX_INSTRUCTIONS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionFlow {
    Next,
    DirectCall,
    IndirectCall,
    UnconditionalBranch,
    ConditionalBranch,
    Return,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInstruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub invalid: bool,
    pub flow: InstructionFlow,
    pub near_branch_target: Option<u64>,
    pub memory_targets: Vec<u64>,
}

impl DecodedInstruction {
    pub fn bytes_text(&self) -> String {
        self.bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisassemblyError {
    UnsupportedArchitecture { machine: u16, kind: PeKind },
    EntryPointNotMapped { rva: u32 },
    EntryPointOutOfBounds { file_offset: u64, file_size: usize },
    EntryPointNotInSection { rva: u32 },
    NoBytesAvailable { file_offset: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawDisassemblyError {
    UnsupportedArchitecture { arch: RawArch },
    EntryPointOutOfBounds { entry: u64, file_size: usize },
    NoBytesAvailable { entry: u64 },
}

impl fmt::Display for RawDisassemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedArchitecture { arch } => {
                write!(
                    formatter,
                    "当前版本仅支持 x64 Raw Binary，检测到 {}",
                    arch.label()
                )
            }
            Self::EntryPointOutOfBounds { entry, file_size } => write!(
                formatter,
                "Raw 入口点 0x{entry:016X} 超出文件大小 0x{file_size:08X}"
            ),
            Self::NoBytesAvailable { entry } => {
                write!(formatter, "Raw 入口点 0x{entry:016X} 没有可解码字节")
            }
        }
    }
}

impl std::error::Error for RawDisassemblyError {}

impl fmt::Display for DisassemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedArchitecture { machine, kind } => write!(
                formatter,
                "当前版本仅支持 x64 PE 反汇编，检测到 Machine 0x{machine:04X} / {}",
                kind.label()
            ),
            Self::EntryPointNotMapped { rva } => {
                write!(formatter, "入口点 RVA 0x{rva:08X} 无法映射到文件偏移")
            }
            Self::EntryPointOutOfBounds {
                file_offset,
                file_size,
            } => write!(
                formatter,
                "入口点文件偏移 0x{file_offset:08X} 超出文件大小 0x{file_size:08X}"
            ),
            Self::EntryPointNotInSection { rva } => {
                write!(formatter, "入口点 RVA 0x{rva:08X} 不在任何 section 中")
            }
            Self::NoBytesAvailable { file_offset } => {
                write!(
                    formatter,
                    "入口点文件偏移 0x{file_offset:08X} 没有可解码字节"
                )
            }
        }
    }
}

impl std::error::Error for DisassemblyError {}

pub fn disassemble_entry_point(
    image: &PeImage,
    bytes: &[u8],
) -> Result<Vec<DecodedInstruction>, DisassemblyError> {
    disassemble_entry_point_with_limit(image, bytes, DEFAULT_MAX_INSTRUCTIONS)
}

pub fn disassemble_entry_point_with_limit(
    image: &PeImage,
    bytes: &[u8],
    max_instructions: usize,
) -> Result<Vec<DecodedInstruction>, DisassemblyError> {
    if image.nt_headers.file_header.machine != 0x8664
        || image.nt_headers.optional_header.kind != PeKind::Pe32Plus
    {
        return Err(DisassemblyError::UnsupportedArchitecture {
            machine: image.nt_headers.file_header.machine,
            kind: image.nt_headers.optional_header.kind,
        });
    }

    let entry_rva = image.entry_point_rva();
    let file_offset = image
        .rva_to_file_offset(u64::from(entry_rva))
        .ok_or(DisassemblyError::EntryPointNotMapped { rva: entry_rva })?;
    let start =
        usize::try_from(file_offset).map_err(|_| DisassemblyError::EntryPointOutOfBounds {
            file_offset,
            file_size: bytes.len(),
        })?;
    if start >= bytes.len() {
        return Err(DisassemblyError::EntryPointOutOfBounds {
            file_offset,
            file_size: bytes.len(),
        });
    }

    let section = image
        .sections
        .iter()
        .find(|section| {
            let start_rva = u64::from(section.virtual_address);
            let end_rva = start_rva.saturating_add(u64::from(section.mapped_size()));
            u64::from(entry_rva) >= start_rva && u64::from(entry_rva) < end_rva
        })
        .ok_or(DisassemblyError::EntryPointNotInSection { rva: entry_rva })?;

    let entry_delta = u64::from(entry_rva).saturating_sub(u64::from(section.virtual_address));
    let raw_remaining = u64::from(section.size_of_raw_data).saturating_sub(entry_delta);
    let available = bytes.len().saturating_sub(start);
    let decode_len = available
        .min(usize::try_from(raw_remaining).unwrap_or(usize::MAX))
        .min(DEFAULT_MAX_BYTES);
    if decode_len == 0 {
        return Err(DisassemblyError::NoBytesAvailable { file_offset });
    }

    Ok(disassemble_x64(
        image.entry_point_va(),
        &bytes[start..start + decode_len],
        max_instructions,
    ))
}

pub fn disassemble_x64(
    start_address: u64,
    bytes: &[u8],
    max_instructions: usize,
) -> Vec<DecodedInstruction> {
    let mut decoder = Decoder::with_ip(64, bytes, start_address, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut rows = Vec::new();

    while decoder.can_decode() && rows.len() < max_instructions {
        let instruction = decoder.decode();
        let start_index = usize::try_from(instruction.ip().saturating_sub(start_address))
            .unwrap_or(bytes.len())
            .min(bytes.len());
        let length = instruction.len().max(1);
        let end_index = start_index.saturating_add(length).min(bytes.len());
        let raw_bytes = bytes[start_index..end_index].to_vec();
        let invalid = instruction.code() == Code::INVALID;

        if invalid {
            let byte = raw_bytes.first().copied().unwrap_or(0);
            rows.push(DecodedInstruction {
                address: instruction.ip(),
                bytes: raw_bytes,
                mnemonic: "db".to_owned(),
                operands: format!("0x{byte:02X}"),
                invalid,
                flow: InstructionFlow::Other,
                near_branch_target: None,
                memory_targets: Vec::new(),
            });
            continue;
        }

        let mut formatted = String::new();
        formatter.format(&instruction, &mut formatted);
        let (mnemonic, operands) = split_instruction_text(&formatted);
        let flow = classify_flow(&instruction);
        let near_branch_target = direct_branch_target(&instruction, &flow);
        let memory_targets = memory_targets(&instruction);

        rows.push(DecodedInstruction {
            address: instruction.ip(),
            bytes: raw_bytes,
            mnemonic,
            operands,
            invalid,
            flow,
            near_branch_target,
            memory_targets,
        });
    }

    rows
}

pub fn disassemble_raw_entry_point(
    image: &RawImage,
    bytes: &[u8],
) -> Result<Vec<DecodedInstruction>, RawDisassemblyError> {
    disassemble_raw_entry_point_with_limit(image, bytes, DEFAULT_MAX_INSTRUCTIONS)
}

pub fn disassemble_raw_entry_point_with_limit(
    image: &RawImage,
    bytes: &[u8],
    max_instructions: usize,
) -> Result<Vec<DecodedInstruction>, RawDisassemblyError> {
    if image.arch != RawArch::X64 {
        return Err(RawDisassemblyError::UnsupportedArchitecture { arch: image.arch });
    }

    let offset = usize::try_from(image.entry_offset().ok_or(
        RawDisassemblyError::EntryPointOutOfBounds {
            entry: image.entry_address,
            file_size: bytes.len(),
        },
    )?)
    .map_err(|_| RawDisassemblyError::EntryPointOutOfBounds {
        entry: image.entry_address,
        file_size: bytes.len(),
    })?;
    if offset >= bytes.len() {
        return Err(RawDisassemblyError::EntryPointOutOfBounds {
            entry: image.entry_address,
            file_size: bytes.len(),
        });
    }

    let decode_len = bytes.len().saturating_sub(offset).min(DEFAULT_MAX_BYTES);
    if decode_len == 0 {
        return Err(RawDisassemblyError::NoBytesAvailable {
            entry: image.entry_address,
        });
    }

    Ok(disassemble_x64(
        image.entry_address,
        &bytes[offset..offset + decode_len],
        max_instructions,
    ))
}

fn classify_flow(instruction: &Instruction) -> InstructionFlow {
    match instruction.flow_control() {
        FlowControl::Next => InstructionFlow::Next,
        FlowControl::Call => InstructionFlow::DirectCall,
        FlowControl::IndirectCall => InstructionFlow::IndirectCall,
        FlowControl::UnconditionalBranch => InstructionFlow::UnconditionalBranch,
        FlowControl::ConditionalBranch => InstructionFlow::ConditionalBranch,
        FlowControl::Return => InstructionFlow::Return,
        _ => InstructionFlow::Other,
    }
}

fn direct_branch_target(instruction: &Instruction, flow: &InstructionFlow) -> Option<u64> {
    match flow {
        InstructionFlow::DirectCall
        | InstructionFlow::UnconditionalBranch
        | InstructionFlow::ConditionalBranch => Some(instruction.near_branch_target()),
        _ => None,
    }
    .filter(|target| *target != 0)
}

fn memory_targets(instruction: &Instruction) -> Vec<u64> {
    if !instruction.op_kinds().any(|kind| kind == OpKind::Memory) {
        return Vec::new();
    }

    let mut targets = Vec::new();
    if instruction.is_ip_rel_memory_operand() {
        let target = instruction.ip_rel_memory_address();
        if target != 0 {
            targets.push(target);
        }
    } else if instruction.memory_base() == Register::None
        && instruction.memory_index() == Register::None
        && instruction.memory_displ_size() > 0
    {
        let target = instruction.memory_displacement64();
        if target != 0 {
            targets.push(target);
        }
    }
    targets.sort_unstable();
    targets.dedup();
    targets
}

fn split_instruction_text(text: &str) -> (String, String) {
    let text = text.trim();
    match text.find(char::is_whitespace) {
        Some(index) => {
            let mnemonic = text[..index].to_owned();
            let operands = text[index..].trim().to_owned();
            (mnemonic, operands)
        }
        None => (text.to_owned(), String::new()),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use fyida_core::{
        CoffFileHeader, DosHeader, FileSelection, NtHeaders, PeImage, PeOptionalHeader, PeSection,
        RawImage,
    };

    use super::*;

    fn sample_image() -> PeImage {
        let selection = FileSelection::new(PathBuf::from(r"C:\samples\demo.exe"), 0x500);
        let dos_header = DosHeader {
            e_magic: 0x5A4D,
            e_lfanew: 0x80,
        };
        let nt_headers = NtHeaders {
            signature: 0x0000_4550,
            file_header: CoffFileHeader {
                machine: 0x8664,
                number_of_sections: 1,
                time_date_stamp: 0,
                pointer_to_symbol_table: 0,
                number_of_symbols: 0,
                size_of_optional_header: 0xF0,
                characteristics: 0x0022,
            },
            optional_header: PeOptionalHeader {
                magic: 0x20B,
                kind: PeKind::Pe32Plus,
                address_of_entry_point: 0x1010,
                image_base: 0x1400_00000,
                section_alignment: 0x1000,
                file_alignment: 0x200,
                size_of_image: 0x3000,
                size_of_headers: 0x200,
                subsystem: 3,
                dll_characteristics: 0x8160,
                number_of_rva_and_sizes: 16,
                data_directories: Vec::new(),
            },
        };
        let sections = vec![PeSection {
            name: ".text".to_owned(),
            virtual_size: 0x300,
            virtual_address: 0x1000,
            size_of_raw_data: 0x200,
            pointer_to_raw_data: 0x200,
            characteristics: 0x6000_0020,
        }];

        PeImage::new(selection, dos_header, nt_headers, sections)
    }

    fn sample_bytes() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x500];
        bytes[0x210..0x21B].copy_from_slice(&[
            0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0xC3,
        ]);
        bytes
    }

    fn sample_raw_image() -> RawImage {
        let selection = FileSelection::new(PathBuf::from(r"C:\samples\raw.bin"), 0x20);
        RawImage::new(selection, 0x1800_00000, 0x1800_00002, RawArch::X64)
    }

    #[test]
    fn decodes_x64_instructions_from_entry_point() {
        let image = sample_image();
        let bytes = sample_bytes();

        let rows = disassemble_entry_point_with_limit(&image, &bytes, 4).expect("decode");

        assert_eq!(rows[0].address, 0x1400_01010);
        assert_eq!(rows[0].bytes_text(), "48 89 5C 24 08");
        assert_eq!(rows[0].mnemonic, "mov");
        assert!(rows[0].operands.contains("rsp+8"));
        assert_eq!(rows[1].mnemonic, "push");
        assert_eq!(rows[2].mnemonic, "sub");
        assert_eq!(rows[3].mnemonic, "ret");
        assert_eq!(rows[3].flow, InstructionFlow::Return);
    }

    #[test]
    fn records_rip_relative_memory_targets() {
        let rows = disassemble_x64(0x1400_01000, &[0x48, 0x8B, 0x05, 0xF9, 0x0F, 0x00, 0x00], 1);

        assert_eq!(rows[0].memory_targets, vec![0x1400_02000]);
    }

    #[test]
    fn invalid_instruction_becomes_placeholder_row() {
        let rows = disassemble_x64(0x1400_01000, &[0x0F, 0x0B, 0xFF], 4);

        assert_eq!(rows[0].mnemonic, "ud2");
        assert_eq!(rows[1].mnemonic, "db");
        assert!(rows[1].invalid);
    }

    #[test]
    fn rejects_non_x64_pe_with_chinese_error_context() {
        let mut image = sample_image();
        image.nt_headers.file_header.machine = 0x014C;

        let error =
            disassemble_entry_point_with_limit(&image, &sample_bytes(), 4).expect_err("x86");

        assert!(error.to_string().contains("当前版本仅支持 x64 PE"));
    }

    #[test]
    fn decodes_raw_x64_from_entry_point() {
        let image = sample_raw_image();
        let bytes = [
            0xCC, 0xCC, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0xC4, 0x20, 0xC3,
        ];

        let rows = disassemble_raw_entry_point_with_limit(&image, &bytes, 3).expect("raw decode");

        assert_eq!(rows[0].address, 0x1800_00002);
        assert_eq!(rows[0].mnemonic, "sub");
        assert_eq!(rows[2].mnemonic, "ret");
    }
}
