use std::collections::{HashSet, VecDeque};

use fyida_core::{
    FileSelection, PeImage, PeKind, PE_DIRECTORY_BASERELOC, PE_DIRECTORY_EXPORT,
    PE_DIRECTORY_IMPORT,
};
use fyida_disasm::{disassemble_entry_point, disassemble_x64, InstructionFlow};

const MAX_FUNCTIONS: usize = 256;
const MAX_FUNCTION_BYTES: usize = 4096;
const MAX_INSTRUCTIONS_PER_FUNCTION: usize = 512;
const MAX_IMPORT_DESCRIPTORS: usize = 256;
const MAX_IMPORT_THUNKS_PER_DLL: usize = 4096;
const MAX_EXPORTS: usize = 4096;
const MAX_RELOCATIONS: usize = 16384;
const MAX_STRINGS: usize = 4096;
const MIN_STRING_CHARS: usize = 4;

#[derive(Debug, Clone)]
pub struct DisassemblyRow {
    pub address: u64,
    pub bytes: String,
    pub mnemonic: String,
    pub operands: String,
    pub comment: String,
}

#[derive(Debug, Clone)]
pub struct DisassemblyBuild {
    pub rows: Vec<DisassemblyRow>,
    pub log_lines: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StaticAnalysis {
    pub functions: Vec<FunctionSummary>,
    pub strings: Vec<ExtractedString>,
    pub imports: Vec<ImportSymbol>,
    pub exports: Vec<ExportSymbol>,
    pub relocations: Vec<RelocationEntry>,
    pub xrefs: Vec<XrefSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSummary {
    pub start_va: u64,
    pub name: String,
    pub size: u64,
    pub instruction_count: usize,
    pub call_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
}

impl StringEncoding {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ascii => "ASCII",
            Self::Utf16Le => "UTF-16LE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedString {
    pub address: u64,
    pub file_offset: u64,
    pub encoding: StringEncoding,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSymbol {
    pub dll: String,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub hint: Option<u16>,
    pub thunk_rva: u32,
    pub thunk_va: u64,
}

impl ImportSymbol {
    pub fn display_name(&self) -> String {
        match (&self.name, self.ordinal) {
            (Some(name), _) => format!("{}!{name}", self.dll),
            (None, Some(ordinal)) => format!("{}!#{ordinal}", self.dll),
            (None, None) => format!("{}!<unknown>", self.dll),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSymbol {
    pub name: String,
    pub ordinal: u32,
    pub rva: u32,
    pub va: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationEntry {
    pub page_rva: u32,
    pub rva: u32,
    pub va: u64,
    pub kind: u8,
}

impl RelocationEntry {
    pub fn kind_label(&self) -> &'static str {
        match self.kind {
            0 => "ABSOLUTE",
            3 => "HIGHLOW",
            10 => "DIR64",
            _ => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XrefKind {
    CodeCall,
    CodeJump,
}

impl XrefKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::CodeCall => "代码调用",
            Self::CodeJump => "代码跳转",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrefSummary {
    pub from_va: u64,
    pub to_va: u64,
    pub kind: XrefKind,
    pub label: String,
}

pub fn empty_workspace_disassembly() -> Vec<DisassemblyRow> {
    empty_workspace_rows()
}

pub fn analyze_pe(image: &PeImage, bytes: &[u8]) -> StaticAnalysis {
    let mut analysis = StaticAnalysis {
        strings: scan_strings(image, bytes),
        imports: parse_imports(image, bytes),
        exports: parse_exports(image, bytes),
        relocations: parse_relocations(image, bytes),
        ..StaticAnalysis::default()
    };

    let (functions, xrefs) = discover_functions_and_xrefs(image, bytes);
    analysis.functions = functions;
    analysis.xrefs = xrefs;
    analysis
}

pub fn static_analysis_log_lines(analysis: &StaticAnalysis) -> Vec<String> {
    vec![
        format!("函数发现：{} 个函数入口。", analysis.functions.len()),
        format!("字符串提取：{} 条。", analysis.strings.len()),
        format!("导入表解析：{} 个导入符号。", analysis.imports.len()),
        format!("导出表解析：{} 个导出符号。", analysis.exports.len()),
        format!("重定位解析：{} 条。", analysis.relocations.len()),
        format!("代码交叉引用：{} 条。", analysis.xrefs.len()),
    ]
}

pub fn pe_entry_disassembly(image: &PeImage, bytes: &[u8]) -> DisassemblyBuild {
    match disassemble_entry_point(image, bytes) {
        Ok(instructions) if !instructions.is_empty() => {
            let invalid_count = instructions
                .iter()
                .filter(|instruction| instruction.invalid)
                .count();
            let rows = instructions
                .into_iter()
                .map(|instruction| DisassemblyRow {
                    address: instruction.address,
                    bytes: instruction.bytes_text(),
                    mnemonic: instruction.mnemonic,
                    operands: instruction.operands,
                    comment: if instruction.invalid {
                        "无效 x64 指令占位，分析继续".to_owned()
                    } else {
                        String::new()
                    },
                })
                .collect::<Vec<_>>();

            let mut log_lines = vec![format!(
                "x64 反汇编完成：入口点附近 {} 条指令。",
                rows.len()
            )];
            if invalid_count > 0 {
                log_lines.push(format!(
                    "发现 {invalid_count} 条无效指令，已用 db 占位显示。"
                ));
            }

            DisassemblyBuild { rows, log_lines }
        }
        Ok(_) => DisassemblyBuild {
            rows: vec![disassembly_error_row(
                image,
                "入口点附近没有可显示的 x64 指令。",
            )],
            log_lines: vec!["x64 反汇编未产生指令。".to_owned()],
        },
        Err(error) => {
            let message = error.to_string();
            DisassemblyBuild {
                rows: vec![disassembly_error_row(image, &message)],
                log_lines: vec![format!("反汇编提示：{message}")],
            }
        }
    }
}

pub fn startup_log_lines() -> Vec<String> {
    vec![
        "FY_IDA GUI 已启动。".to_owned(),
        "当前版本：v0.4.0-alpha.1 开发中，基础静态分析已接入。".to_owned(),
        "可打开 Windows x64 PE 文件并显示入口点指令、函数、字符串、导入导出和重定位摘要。"
            .to_owned(),
    ]
}

pub fn pe_loaded_log_lines(image: &PeImage) -> Vec<String> {
    vec![
        format!("PE 加载完成：{}", image.file().path().display()),
        format!("文件大小：{}", image.file().formatted_size()),
        format!(
            "Machine：{} (0x{:04X})",
            image.machine_label(),
            image.nt_headers.file_header.machine
        ),
        format!("ImageBase：0x{:016X}", image.image_base()),
        format!(
            "EntryPoint：VA 0x{:016X} / RVA 0x{:08X}",
            image.entry_point_va(),
            image.entry_point_rva()
        ),
        format!("Subsystem：{}", image.subsystem_label()),
        format!("Section 数量：{}", image.sections.len()),
    ]
}

pub fn file_error_log_lines(file: &FileSelection, message: &str) -> Vec<String> {
    vec![
        format!("打开文件失败：{}", file.path().display()),
        format!("错误：{message}"),
    ]
}

fn discover_functions_and_xrefs(
    image: &PeImage,
    bytes: &[u8],
) -> (Vec<FunctionSummary>, Vec<XrefSummary>) {
    if image.nt_headers.file_header.machine != 0x8664
        || image.nt_headers.optional_header.kind != PeKind::Pe32Plus
    {
        return (Vec::new(), Vec::new());
    }

    let mut worklist = VecDeque::from([image.entry_point_va()]);
    let mut discovered = HashSet::from([image.entry_point_va()]);
    let mut processed = HashSet::new();
    let mut xref_keys = HashSet::new();
    let mut functions = Vec::new();
    let mut xrefs = Vec::new();

    while let Some(start_va) = worklist.pop_front() {
        if processed.contains(&start_va) || !image.is_executable_va(start_va) {
            continue;
        }
        processed.insert(start_va);

        let Some(function_bytes) = bytes_from_va(image, bytes, start_va, MAX_FUNCTION_BYTES) else {
            continue;
        };
        let instructions = disassemble_x64(start_va, function_bytes, MAX_INSTRUCTIONS_PER_FUNCTION);
        if instructions.is_empty() {
            continue;
        }

        let mut last_end = start_va;
        let mut call_count = 0usize;
        for instruction in &instructions {
            let instruction_end = instruction
                .address
                .saturating_add(u64::try_from(instruction.bytes.len()).unwrap_or(0));
            last_end = last_end.max(instruction_end);

            if let Some(target) = instruction.near_branch_target {
                let kind = match instruction.flow {
                    InstructionFlow::DirectCall => Some(XrefKind::CodeCall),
                    InstructionFlow::UnconditionalBranch | InstructionFlow::ConditionalBranch => {
                        Some(XrefKind::CodeJump)
                    }
                    _ => None,
                };

                if let Some(kind) = kind {
                    if xref_keys.insert((instruction.address, target, kind)) {
                        xrefs.push(XrefSummary {
                            from_va: instruction.address,
                            to_va: target,
                            kind,
                            label: format!("{} -> 0x{target:016X}", kind.label()),
                        });
                    }
                }

                if instruction.flow == InstructionFlow::DirectCall && image.is_executable_va(target)
                {
                    call_count += 1;
                    if discovered.len() < MAX_FUNCTIONS && discovered.insert(target) {
                        worklist.push_back(target);
                    }
                }
            }

            if instruction.flow == InstructionFlow::Return {
                break;
            }
        }

        let name = if start_va == image.entry_point_va() {
            "入口点".to_owned()
        } else {
            format!("sub_{start_va:016X}")
        };

        functions.push(FunctionSummary {
            start_va,
            name,
            size: last_end.saturating_sub(start_va),
            instruction_count: instructions.len(),
            call_count,
        });
    }

    functions.sort_by_key(|function| function.start_va);
    xrefs.sort_by_key(|xref| (xref.from_va, xref.to_va));
    (functions, xrefs)
}

fn parse_imports(image: &PeImage, bytes: &[u8]) -> Vec<ImportSymbol> {
    let Some(directory) = image
        .data_directory(PE_DIRECTORY_IMPORT)
        .filter(|directory| directory.is_present())
    else {
        return Vec::new();
    };

    let thunk_width = match image.nt_headers.optional_header.kind {
        PeKind::Pe32 => 4u32,
        PeKind::Pe32Plus => 8u32,
    };
    let ordinal_mask = match image.nt_headers.optional_header.kind {
        PeKind::Pe32 => 0x8000_0000u64,
        PeKind::Pe32Plus => 0x8000_0000_0000_0000u64,
    };
    let mut imports = Vec::new();

    for descriptor_index in 0..MAX_IMPORT_DESCRIPTORS {
        let descriptor_rva = directory
            .virtual_address
            .saturating_add(u32::try_from(descriptor_index * 20).unwrap_or(u32::MAX));
        let Some(original_first_thunk) = read_u32_at_rva(image, bytes, descriptor_rva) else {
            break;
        };
        let Some(_time_date_stamp) = read_u32_at_rva(image, bytes, descriptor_rva + 4) else {
            break;
        };
        let Some(_forwarder_chain) = read_u32_at_rva(image, bytes, descriptor_rva + 8) else {
            break;
        };
        let Some(name_rva) = read_u32_at_rva(image, bytes, descriptor_rva + 12) else {
            break;
        };
        let Some(first_thunk) = read_u32_at_rva(image, bytes, descriptor_rva + 16) else {
            break;
        };

        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let dll = read_c_string_at_rva(image, bytes, name_rva)
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "<unknown.dll>".to_owned());
        let thunk_table_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };

        for thunk_index in 0..MAX_IMPORT_THUNKS_PER_DLL {
            let thunk_offset = u32::try_from(thunk_index)
                .unwrap_or(u32::MAX)
                .saturating_mul(thunk_width);
            let thunk_rva = thunk_table_rva.saturating_add(thunk_offset);
            let iat_rva = first_thunk.saturating_add(thunk_offset);
            let entry = match thunk_width {
                4 => read_u32_at_rva(image, bytes, thunk_rva).map(u64::from),
                _ => read_u64_at_rva(image, bytes, thunk_rva),
            };
            let Some(entry) = entry else {
                break;
            };
            if entry == 0 {
                break;
            }

            let (name, ordinal, hint) = if entry & ordinal_mask != 0 {
                (None, Some((entry & 0xFFFF) as u16), None)
            } else {
                let hint_name_rva = entry as u32;
                let hint = read_u16_at_rva(image, bytes, hint_name_rva);
                let name = read_c_string_at_rva(image, bytes, hint_name_rva.saturating_add(2));
                (name, None, hint)
            };

            imports.push(ImportSymbol {
                dll: dll.clone(),
                name,
                ordinal,
                hint,
                thunk_rva: iat_rva,
                thunk_va: image.rva_to_va(u64::from(iat_rva)),
            });
        }
    }

    imports
}

fn parse_exports(image: &PeImage, bytes: &[u8]) -> Vec<ExportSymbol> {
    let Some(directory) = image
        .data_directory(PE_DIRECTORY_EXPORT)
        .filter(|directory| directory.is_present())
    else {
        return Vec::new();
    };

    let export_rva = directory.virtual_address;
    let Some(base) = read_u32_at_rva(image, bytes, export_rva + 16) else {
        return Vec::new();
    };
    let Some(number_of_functions) = read_u32_at_rva(image, bytes, export_rva + 20) else {
        return Vec::new();
    };
    let Some(number_of_names) = read_u32_at_rva(image, bytes, export_rva + 24) else {
        return Vec::new();
    };
    let Some(address_of_functions) = read_u32_at_rva(image, bytes, export_rva + 28) else {
        return Vec::new();
    };
    let Some(address_of_names) = read_u32_at_rva(image, bytes, export_rva + 32) else {
        return Vec::new();
    };
    let Some(address_of_name_ordinals) = read_u32_at_rva(image, bytes, export_rva + 36) else {
        return Vec::new();
    };

    let name_count = usize::try_from(number_of_names)
        .unwrap_or(usize::MAX)
        .min(MAX_EXPORTS);
    let function_count = usize::try_from(number_of_functions).unwrap_or(usize::MAX);
    let mut exports = Vec::new();

    for index in 0..name_count {
        let name_rva = read_u32_at_rva(
            image,
            bytes,
            address_of_names.saturating_add(u32::try_from(index * 4).unwrap_or(u32::MAX)),
        );
        let ordinal_index = read_u16_at_rva(
            image,
            bytes,
            address_of_name_ordinals.saturating_add(u32::try_from(index * 2).unwrap_or(u32::MAX)),
        );
        let (Some(name_rva), Some(ordinal_index)) = (name_rva, ordinal_index) else {
            continue;
        };
        let ordinal_index_usize = usize::from(ordinal_index);
        if ordinal_index_usize >= function_count {
            continue;
        }
        let function_rva = read_u32_at_rva(
            image,
            bytes,
            address_of_functions
                .saturating_add(u32::try_from(ordinal_index_usize * 4).unwrap_or(u32::MAX)),
        )
        .unwrap_or(0);
        let Some(name) = read_c_string_at_rva(image, bytes, name_rva) else {
            continue;
        };

        exports.push(ExportSymbol {
            name,
            ordinal: base.saturating_add(u32::from(ordinal_index)),
            rva: function_rva,
            va: image.rva_to_va(u64::from(function_rva)),
        });
    }

    exports
}

fn parse_relocations(image: &PeImage, bytes: &[u8]) -> Vec<RelocationEntry> {
    let Some(directory) = image
        .data_directory(PE_DIRECTORY_BASERELOC)
        .filter(|directory| directory.is_present())
    else {
        return Vec::new();
    };

    let mut relocations = Vec::new();
    let mut cursor = 0u32;
    while cursor.saturating_add(8) <= directory.size && relocations.len() < MAX_RELOCATIONS {
        let block_rva = directory.virtual_address.saturating_add(cursor);
        let Some(page_rva) = read_u32_at_rva(image, bytes, block_rva) else {
            break;
        };
        let Some(block_size) = read_u32_at_rva(image, bytes, block_rva + 4) else {
            break;
        };
        if block_size < 8 {
            break;
        }

        let entry_count = usize::try_from((block_size - 8) / 2).unwrap_or(0);
        for index in 0..entry_count {
            if relocations.len() >= MAX_RELOCATIONS {
                break;
            }
            let entry_rva = block_rva
                .saturating_add(8)
                .saturating_add(u32::try_from(index * 2).unwrap_or(u32::MAX));
            let Some(raw_entry) = read_u16_at_rva(image, bytes, entry_rva) else {
                continue;
            };
            let kind = (raw_entry >> 12) as u8;
            let offset = u32::from(raw_entry & 0x0FFF);
            if kind == 0 {
                continue;
            }
            let rva = page_rva.saturating_add(offset);
            relocations.push(RelocationEntry {
                page_rva,
                rva,
                va: image.rva_to_va(u64::from(rva)),
                kind,
            });
        }

        cursor = cursor.saturating_add(block_size);
    }

    relocations
}

fn scan_strings(image: &PeImage, bytes: &[u8]) -> Vec<ExtractedString> {
    let mut strings = Vec::new();

    for section in &image.sections {
        if section.characteristics & 0x2000_0000 != 0 {
            continue;
        }

        let Some(section_bytes) = section_raw_bytes(image, bytes, section.virtual_address) else {
            continue;
        };
        let section_file_offset = u64::from(section.pointer_to_raw_data);

        scan_ascii_strings(
            image,
            section_bytes,
            section_file_offset,
            &mut strings,
            MAX_STRINGS,
        );
        scan_utf16le_strings(
            image,
            section_bytes,
            section_file_offset,
            &mut strings,
            MAX_STRINGS,
        );

        if strings.len() >= MAX_STRINGS {
            break;
        }
    }

    strings.sort_by_key(|string| (string.address, string.encoding as u8));
    strings.truncate(MAX_STRINGS);
    strings
}

fn scan_ascii_strings(
    image: &PeImage,
    bytes: &[u8],
    section_file_offset: u64,
    strings: &mut Vec<ExtractedString>,
    max_strings: usize,
) {
    let mut index = 0usize;
    while index < bytes.len() && strings.len() < max_strings {
        if !is_ascii_string_byte(bytes[index]) {
            index += 1;
            continue;
        }

        let start = index;
        while index < bytes.len() && is_ascii_string_byte(bytes[index]) {
            index += 1;
        }

        let nul_terminated = index < bytes.len() && bytes[index] == 0;
        if index.saturating_sub(start) >= MIN_STRING_CHARS && nul_terminated {
            let file_offset = section_file_offset + u64::try_from(start).unwrap_or(0);
            let address = image.file_offset_to_va(file_offset).unwrap_or(file_offset);
            strings.push(ExtractedString {
                address,
                file_offset,
                encoding: StringEncoding::Ascii,
                value: String::from_utf8_lossy(&bytes[start..index]).to_string(),
            });
        }
    }
}

fn scan_utf16le_strings(
    image: &PeImage,
    bytes: &[u8],
    section_file_offset: u64,
    strings: &mut Vec<ExtractedString>,
    max_strings: usize,
) {
    let mut index = 0usize;
    while index + 1 < bytes.len() && strings.len() < max_strings {
        let Some(first_char) = read_utf16_printable(bytes, index) else {
            index += 1;
            continue;
        };

        let start = index;
        let mut chars = vec![first_char];
        index += 2;
        while index + 1 < bytes.len() {
            let Some(ch) = read_utf16_printable(bytes, index) else {
                break;
            };
            chars.push(ch);
            index += 2;
        }

        let nul_terminated = index + 1 < bytes.len() && bytes[index] == 0 && bytes[index + 1] == 0;
        if chars.len() >= MIN_STRING_CHARS && nul_terminated {
            let file_offset = section_file_offset + u64::try_from(start).unwrap_or(0);
            let address = image.file_offset_to_va(file_offset).unwrap_or(file_offset);
            strings.push(ExtractedString {
                address,
                file_offset,
                encoding: StringEncoding::Utf16Le,
                value: String::from_utf16_lossy(&chars),
            });
        }
    }
}

fn section_raw_bytes<'a>(image: &PeImage, bytes: &'a [u8], section_rva: u32) -> Option<&'a [u8]> {
    let section = image.section_containing_rva(u64::from(section_rva))?;
    let start = usize::try_from(section.pointer_to_raw_data).ok()?;
    if start >= bytes.len() {
        return None;
    }
    let raw_size = usize::try_from(section.size_of_raw_data).ok()?;
    let end = start.saturating_add(raw_size).min(bytes.len());
    Some(&bytes[start..end])
}

fn bytes_from_va<'a>(
    image: &PeImage,
    bytes: &'a [u8],
    va: u64,
    max_len: usize,
) -> Option<&'a [u8]> {
    let rva = image.va_to_rva(va)?;
    let section = image.section_containing_rva(rva)?;
    let file_offset = image.rva_to_file_offset(rva)?;
    let start = usize::try_from(file_offset).ok()?;
    if start >= bytes.len() {
        return None;
    }

    let delta = rva.checked_sub(u64::from(section.virtual_address))?;
    let raw_remaining = u64::from(section.size_of_raw_data).checked_sub(delta)?;
    let available = bytes.len().saturating_sub(start);
    let len = available
        .min(usize::try_from(raw_remaining).unwrap_or(usize::MAX))
        .min(max_len);
    (len > 0).then_some(&bytes[start..start + len])
}

fn read_u16_at_rva(image: &PeImage, bytes: &[u8], rva: u32) -> Option<u16> {
    let offset = usize::try_from(image.rva_to_file_offset(u64::from(rva))?).ok()?;
    let raw = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32_at_rva(image: &PeImage, bytes: &[u8], rva: u32) -> Option<u32> {
    let offset = usize::try_from(image.rva_to_file_offset(u64::from(rva))?).ok()?;
    let raw = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64_at_rva(image: &PeImage, bytes: &[u8], rva: u32) -> Option<u64> {
    let offset = usize::try_from(image.rva_to_file_offset(u64::from(rva))?).ok()?;
    let raw = bytes.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

fn read_c_string_at_rva(image: &PeImage, bytes: &[u8], rva: u32) -> Option<String> {
    let offset = usize::try_from(image.rva_to_file_offset(u64::from(rva))?).ok()?;
    let mut end = offset;
    let max_end = bytes.len().min(offset.saturating_add(4096));
    while end < max_end && bytes[end] != 0 {
        end += 1;
    }
    if end == offset || end == max_end {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[offset..end]).to_string())
}

fn is_ascii_string_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' '..=b'~')
}

fn read_utf16_printable(bytes: &[u8], index: usize) -> Option<u16> {
    let low = *bytes.get(index)?;
    let high = *bytes.get(index + 1)?;
    if high != 0 || !is_ascii_string_byte(low) {
        return None;
    }
    Some(u16::from(low))
}

fn disassembly_error_row(image: &PeImage, message: &str) -> DisassemblyRow {
    DisassemblyRow {
        address: image.entry_point_va(),
        bytes: "--".to_owned(),
        mnemonic: "提示".to_owned(),
        operands: format!("RVA 0x{:08X}", image.entry_point_rva()),
        comment: message.to_owned(),
    }
}

fn empty_workspace_rows() -> Vec<DisassemblyRow> {
    vec![
        DisassemblyRow {
            address: 0x1400_01000,
            bytes: "48 89 5C 24 08".to_owned(),
            mnemonic: "mov".to_owned(),
            operands: "[rsp+8], rbx".to_owned(),
            comment: "示例行：打开 x64 PE 后会显示入口点真实指令".to_owned(),
        },
        DisassemblyRow {
            address: 0x1400_01005,
            bytes: "57".to_owned(),
            mnemonic: "push".to_owned(),
            operands: "rdi".to_owned(),
            comment: "尚未进行真实反汇编".to_owned(),
        },
        DisassemblyRow {
            address: 0x1400_01006,
            bytes: "48 83 EC 20".to_owned(),
            mnemonic: "sub".to_owned(),
            operands: "rsp, 20h".to_owned(),
            comment: "占位反汇编视图".to_owned(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use fyida_core::{
        CoffFileHeader, DosHeader, FileSelection, NtHeaders, PeDataDirectory, PeOptionalHeader,
        PeSection,
    };

    use super::*;

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn write_c_string(bytes: &mut [u8], offset: usize, value: &str) {
        bytes[offset..offset + value.len()].copy_from_slice(value.as_bytes());
        bytes[offset + value.len()] = 0;
    }

    fn sample_image() -> PeImage {
        let selection = FileSelection::new(PathBuf::from(r"C:\samples\analysis.exe"), 0x900);
        let mut data_directories = vec![
            PeDataDirectory {
                virtual_address: 0,
                size: 0,
            };
            16
        ];
        data_directories[PE_DIRECTORY_EXPORT] = PeDataDirectory {
            virtual_address: 0x2200,
            size: 0x80,
        };
        data_directories[PE_DIRECTORY_IMPORT] = PeDataDirectory {
            virtual_address: 0x2100,
            size: 0x80,
        };
        data_directories[PE_DIRECTORY_BASERELOC] = PeDataDirectory {
            virtual_address: 0x2300,
            size: 0x0C,
        };

        PeImage::new(
            selection,
            DosHeader {
                e_magic: 0x5A4D,
                e_lfanew: 0x80,
            },
            NtHeaders {
                signature: 0x0000_4550,
                file_header: CoffFileHeader {
                    machine: 0x8664,
                    number_of_sections: 2,
                    time_date_stamp: 0,
                    pointer_to_symbol_table: 0,
                    number_of_symbols: 0,
                    size_of_optional_header: 0xF0,
                    characteristics: 0x0022,
                },
                optional_header: PeOptionalHeader {
                    magic: 0x20B,
                    kind: PeKind::Pe32Plus,
                    address_of_entry_point: 0x1000,
                    image_base: 0x1400_00000,
                    section_alignment: 0x1000,
                    file_alignment: 0x200,
                    size_of_image: 0x4000,
                    size_of_headers: 0x200,
                    subsystem: 3,
                    dll_characteristics: 0x8160,
                    number_of_rva_and_sizes: 16,
                    data_directories,
                },
            },
            vec![
                PeSection {
                    name: ".text".to_owned(),
                    virtual_size: 0x200,
                    virtual_address: 0x1000,
                    size_of_raw_data: 0x200,
                    pointer_to_raw_data: 0x200,
                    characteristics: 0x6000_0020,
                },
                PeSection {
                    name: ".rdata".to_owned(),
                    virtual_size: 0x500,
                    virtual_address: 0x2000,
                    size_of_raw_data: 0x500,
                    pointer_to_raw_data: 0x400,
                    characteristics: 0x4000_0040,
                },
            ],
        )
    }

    fn sample_bytes() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x900];

        bytes[0x200..0x206].copy_from_slice(&[0xE8, 0x0B, 0x00, 0x00, 0x00, 0xC3]);
        bytes[0x210] = 0xC3;

        write_c_string(&mut bytes, 0x400, "hello world");
        let utf16 = "wide";
        for (index, byte) in utf16.as_bytes().iter().enumerate() {
            bytes[0x420 + index * 2] = *byte;
            bytes[0x420 + index * 2 + 1] = 0;
        }

        write_u32(&mut bytes, 0x500, 0x2140);
        write_u32(&mut bytes, 0x50C, 0x2120);
        write_u32(&mut bytes, 0x510, 0x2160);
        write_c_string(&mut bytes, 0x520, "KERNEL32.dll");
        write_u16(&mut bytes, 0x530, 7);
        write_c_string(&mut bytes, 0x532, "CreateFileW");
        write_u64(&mut bytes, 0x540, 0x2130);

        write_u32(&mut bytes, 0x610, 1);
        write_u32(&mut bytes, 0x614, 1);
        write_u32(&mut bytes, 0x618, 1);
        write_u32(&mut bytes, 0x61C, 0x2240);
        write_u32(&mut bytes, 0x620, 0x2250);
        write_u32(&mut bytes, 0x624, 0x2260);
        write_u32(&mut bytes, 0x640, 0x1000);
        write_u32(&mut bytes, 0x650, 0x2270);
        write_u16(&mut bytes, 0x660, 0);
        write_c_string(&mut bytes, 0x670, "exported_func");

        write_u32(&mut bytes, 0x700, 0x1000);
        write_u32(&mut bytes, 0x704, 0x0C);
        write_u16(&mut bytes, 0x708, 0xA020);
        write_u16(&mut bytes, 0x70A, 0);

        bytes
    }

    #[test]
    fn analyzes_functions_strings_imports_exports_relocations_and_xrefs() {
        let image = sample_image();
        let bytes = sample_bytes();

        let analysis = analyze_pe(&image, &bytes);

        assert!(analysis
            .functions
            .iter()
            .any(|function| function.start_va == 0x1400_01000));
        assert!(analysis
            .functions
            .iter()
            .any(|function| function.start_va == 0x1400_01010));
        assert!(analysis
            .xrefs
            .iter()
            .any(|xref| xref.from_va == 0x1400_01000 && xref.to_va == 0x1400_01010));
        assert!(analysis.strings.iter().any(
            |string| string.value == "hello world" && string.encoding == StringEncoding::Ascii
        ));
        assert!(analysis
            .strings
            .iter()
            .any(|string| string.value == "wide" && string.encoding == StringEncoding::Utf16Le));
        assert_eq!(
            analysis.imports[0].display_name(),
            "KERNEL32.dll!CreateFileW"
        );
        assert_eq!(analysis.imports[0].hint, Some(7));
        assert_eq!(analysis.exports[0].name, "exported_func");
        assert_eq!(analysis.exports[0].va, 0x1400_01000);
        assert_eq!(analysis.relocations[0].rva, 0x1020);
        assert_eq!(analysis.relocations[0].kind_label(), "DIR64");
    }
}
