use std::fmt;
use std::path::{Path, PathBuf};

use fyida_core::{
    CoffFileHeader, DosHeader, FileSelection, NtHeaders, PeImage, PeKind, PeOptionalHeader,
    PeSection,
};

#[derive(Debug)]
pub enum LoaderError {
    Metadata {
        path: PathBuf,
        source: std::io::Error,
    },
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    NotAFile(PathBuf),
    InvalidPe {
        path: PathBuf,
        source: PeParseError,
    },
}

impl fmt::Display for LoaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Metadata { path, source } => {
                write!(
                    formatter,
                    "无法读取文件元数据：{} ({source})",
                    path.display()
                )
            }
            Self::Read { path, source } => {
                write!(formatter, "无法读取文件内容：{} ({source})", path.display())
            }
            Self::NotAFile(path) => write!(formatter, "选择的路径不是普通文件：{}", path.display()),
            Self::InvalidPe { source, .. } => write!(formatter, "不是有效的 PE 文件：{source}"),
        }
    }
}

impl std::error::Error for LoaderError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeParseError {
    TooSmall(&'static str),
    MissingDosSignature,
    InvalidNtHeaderOffset(u32),
    MissingNtSignature,
    OptionalHeaderTooSmall { expected: usize, actual: usize },
    UnsupportedOptionalHeaderMagic(u16),
    SectionTableOutOfBounds,
}

impl fmt::Display for PeParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall(context) => write!(formatter, "文件过小，无法读取 {context}"),
            Self::MissingDosSignature => write!(formatter, "缺少 DOS Header 的 MZ 签名"),
            Self::InvalidNtHeaderOffset(offset) => {
                write!(formatter, "DOS Header 中的 e_lfanew 无效：0x{offset:08X}")
            }
            Self::MissingNtSignature => write!(formatter, "缺少 NT Header 的 PE 签名"),
            Self::OptionalHeaderTooSmall { expected, actual } => write!(
                formatter,
                "Optional Header 过小：需要至少 {expected} 字节，实际 {actual} 字节"
            ),
            Self::UnsupportedOptionalHeaderMagic(magic) => {
                write!(formatter, "不支持的 Optional Header Magic：0x{magic:04X}")
            }
            Self::SectionTableOutOfBounds => write!(formatter, "Section Table 超出文件范围"),
        }
    }
}

impl std::error::Error for PeParseError {}

pub fn load_file_metadata(path: impl AsRef<Path>) -> Result<FileSelection, LoaderError> {
    let path = path.as_ref().to_path_buf();
    let metadata = std::fs::metadata(&path).map_err(|source| LoaderError::Metadata {
        path: path.clone(),
        source,
    })?;

    if !metadata.is_file() {
        return Err(LoaderError::NotAFile(path));
    }

    Ok(FileSelection::new(path, metadata.len()))
}

pub fn load_pe_from_selection(selection: FileSelection) -> Result<PeImage, LoaderError> {
    let path = selection.path().to_path_buf();
    let bytes = std::fs::read(&path).map_err(|source| LoaderError::Read {
        path: path.clone(),
        source,
    })?;

    parse_pe_bytes(selection, &bytes).map_err(|source| LoaderError::InvalidPe { path, source })
}

pub fn load_pe_file(path: impl AsRef<Path>) -> Result<PeImage, LoaderError> {
    let selection = load_file_metadata(path)?;
    load_pe_from_selection(selection)
}

pub fn parse_pe_bytes(selection: FileSelection, bytes: &[u8]) -> Result<PeImage, PeParseError> {
    let e_magic = read_u16(bytes, 0, "DOS Header")?;
    if e_magic != 0x5A4D {
        return Err(PeParseError::MissingDosSignature);
    }

    let e_lfanew = read_u32(bytes, 0x3C, "DOS Header e_lfanew")?;
    let nt_offset = usize::try_from(e_lfanew)
        .ok()
        .filter(|offset| {
            offset
                .checked_add(24)
                .map_or(false, |end| end <= bytes.len())
        })
        .ok_or(PeParseError::InvalidNtHeaderOffset(e_lfanew))?;

    let signature = read_u32(bytes, nt_offset, "NT Header signature")?;
    if signature != 0x0000_4550 {
        return Err(PeParseError::MissingNtSignature);
    }

    let file_header_offset = nt_offset + 4;
    let file_header = CoffFileHeader {
        machine: read_u16(bytes, file_header_offset, "File Header Machine")?,
        number_of_sections: read_u16(bytes, file_header_offset + 2, "File Header section count")?,
        time_date_stamp: read_u32(bytes, file_header_offset + 4, "File Header timestamp")?,
        pointer_to_symbol_table: read_u32(
            bytes,
            file_header_offset + 8,
            "File Header symbol table pointer",
        )?,
        number_of_symbols: read_u32(bytes, file_header_offset + 12, "File Header symbol count")?,
        size_of_optional_header: read_u16(
            bytes,
            file_header_offset + 16,
            "File Header optional header size",
        )?,
        characteristics: read_u16(
            bytes,
            file_header_offset + 18,
            "File Header characteristics",
        )?,
    };

    let optional_header_offset = file_header_offset + 20;
    let optional_header_size = usize::from(file_header.size_of_optional_header);
    if optional_header_size < 72 {
        return Err(PeParseError::OptionalHeaderTooSmall {
            expected: 72,
            actual: optional_header_size,
        });
    }
    if optional_header_offset
        .checked_add(optional_header_size)
        .map_or(true, |end| end > bytes.len())
    {
        return Err(PeParseError::TooSmall("Optional Header"));
    }

    let magic = read_u16(bytes, optional_header_offset, "Optional Header Magic")?;
    let kind = match magic {
        0x010B => PeKind::Pe32,
        0x020B => PeKind::Pe32Plus,
        other => return Err(PeParseError::UnsupportedOptionalHeaderMagic(other)),
    };

    let image_base = match kind {
        PeKind::Pe32 => u64::from(read_u32(
            bytes,
            optional_header_offset + 28,
            "Optional Header ImageBase",
        )?),
        PeKind::Pe32Plus => read_u64(
            bytes,
            optional_header_offset + 24,
            "Optional Header ImageBase",
        )?,
    };

    let optional_header = PeOptionalHeader {
        magic,
        kind,
        address_of_entry_point: read_u32(
            bytes,
            optional_header_offset + 16,
            "Optional Header AddressOfEntryPoint",
        )?,
        image_base,
        section_alignment: read_u32(
            bytes,
            optional_header_offset + 32,
            "Optional Header SectionAlignment",
        )?,
        file_alignment: read_u32(
            bytes,
            optional_header_offset + 36,
            "Optional Header FileAlignment",
        )?,
        size_of_image: read_u32(
            bytes,
            optional_header_offset + 56,
            "Optional Header SizeOfImage",
        )?,
        size_of_headers: read_u32(
            bytes,
            optional_header_offset + 60,
            "Optional Header SizeOfHeaders",
        )?,
        subsystem: read_u16(
            bytes,
            optional_header_offset + 68,
            "Optional Header Subsystem",
        )?,
        dll_characteristics: read_u16(
            bytes,
            optional_header_offset + 70,
            "Optional Header DllCharacteristics",
        )?,
    };

    let section_table_offset = optional_header_offset + optional_header_size;
    let section_table_size = usize::from(file_header.number_of_sections)
        .checked_mul(40)
        .ok_or(PeParseError::SectionTableOutOfBounds)?;
    if section_table_offset
        .checked_add(section_table_size)
        .map_or(true, |end| end > bytes.len())
    {
        return Err(PeParseError::SectionTableOutOfBounds);
    }

    let mut sections = Vec::with_capacity(usize::from(file_header.number_of_sections));
    for index in 0..usize::from(file_header.number_of_sections) {
        let section_offset = section_table_offset + index * 40;
        let name = parse_section_name(&bytes[section_offset..section_offset + 8]);
        sections.push(PeSection {
            name,
            virtual_size: read_u32(bytes, section_offset + 8, "Section VirtualSize")?,
            virtual_address: read_u32(bytes, section_offset + 12, "Section VirtualAddress")?,
            size_of_raw_data: read_u32(bytes, section_offset + 16, "Section SizeOfRawData")?,
            pointer_to_raw_data: read_u32(bytes, section_offset + 20, "Section PointerToRawData")?,
            characteristics: read_u32(bytes, section_offset + 36, "Section Characteristics")?,
        });
    }

    let dos_header = DosHeader { e_magic, e_lfanew };
    let nt_headers = NtHeaders {
        signature,
        file_header,
        optional_header,
    };

    Ok(PeImage::new(selection, dos_header, nt_headers, sections))
}

fn read_u16(bytes: &[u8], offset: usize, context: &'static str) -> Result<u16, PeParseError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(PeParseError::TooSmall(context))?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize, context: &'static str) -> Result<u32, PeParseError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or(PeParseError::TooSmall(context))?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(bytes: &[u8], offset: usize, context: &'static str) -> Result<u64, PeParseError> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or(PeParseError::TooSmall(context))?;
    Ok(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

fn parse_section_name(raw: &[u8]) -> String {
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).to_string()
}

#[cfg(test)]
mod tests {
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

    fn minimal_pe64_bytes() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x500];
        let nt_offset = 0x80;
        let file_header_offset = nt_offset + 4;
        let optional_header_offset = file_header_offset + 20;
        let section_offset = optional_header_offset + 0xF0;

        write_u16(&mut bytes, 0, 0x5A4D);
        write_u32(&mut bytes, 0x3C, nt_offset as u32);

        write_u32(&mut bytes, nt_offset, 0x0000_4550);
        write_u16(&mut bytes, file_header_offset, 0x8664);
        write_u16(&mut bytes, file_header_offset + 2, 1);
        write_u16(&mut bytes, file_header_offset + 16, 0xF0);
        write_u16(&mut bytes, file_header_offset + 18, 0x0022);

        write_u16(&mut bytes, optional_header_offset, 0x020B);
        write_u32(&mut bytes, optional_header_offset + 16, 0x1010);
        write_u64(&mut bytes, optional_header_offset + 24, 0x1400_00000);
        write_u32(&mut bytes, optional_header_offset + 32, 0x1000);
        write_u32(&mut bytes, optional_header_offset + 36, 0x200);
        write_u32(&mut bytes, optional_header_offset + 56, 0x3000);
        write_u32(&mut bytes, optional_header_offset + 60, 0x200);
        write_u16(&mut bytes, optional_header_offset + 68, 3);
        write_u16(&mut bytes, optional_header_offset + 70, 0x8160);

        bytes[section_offset..section_offset + 5].copy_from_slice(b".text");
        write_u32(&mut bytes, section_offset + 8, 0x300);
        write_u32(&mut bytes, section_offset + 12, 0x1000);
        write_u32(&mut bytes, section_offset + 16, 0x200);
        write_u32(&mut bytes, section_offset + 20, 0x200);
        write_u32(&mut bytes, section_offset + 36, 0x6000_0020);

        bytes
    }

    fn selection_for(bytes: &[u8]) -> FileSelection {
        FileSelection::new(PathBuf::from(r"C:\samples\demo.exe"), bytes.len() as u64)
    }

    #[test]
    fn directory_is_not_accepted_as_file() {
        let error = load_file_metadata(".").expect_err("directories should be rejected");
        assert!(matches!(error, LoaderError::NotAFile(_)));
    }

    #[test]
    fn parses_pe64_headers_and_sections() {
        let bytes = minimal_pe64_bytes();
        let image = parse_pe_bytes(selection_for(&bytes), &bytes).expect("PE should parse");

        assert_eq!(image.dos_header.e_magic, 0x5A4D);
        assert_eq!(image.dos_header.e_lfanew, 0x80);
        assert_eq!(image.nt_headers.signature, 0x0000_4550);
        assert_eq!(image.nt_headers.file_header.machine, 0x8664);
        assert_eq!(image.nt_headers.file_header.number_of_sections, 1);
        assert_eq!(image.nt_headers.file_header.characteristics, 0x0022);
        assert_eq!(image.nt_headers.optional_header.kind, PeKind::Pe32Plus);
        assert_eq!(image.image_base(), 0x1400_00000);
        assert_eq!(image.entry_point_rva(), 0x1010);
        assert_eq!(image.entry_point_va(), 0x1400_01010);
        assert_eq!(image.nt_headers.optional_header.subsystem, 3);
        assert_eq!(image.sections[0].name, ".text");
        assert_eq!(image.sections[0].virtual_address, 0x1000);
        assert_eq!(image.sections[0].pointer_to_raw_data, 0x200);
        assert_eq!(image.sections[0].permissions(), "R-X");
    }

    #[test]
    fn maps_va_rva_and_file_offsets_from_parsed_sections() {
        let bytes = minimal_pe64_bytes();
        let image = parse_pe_bytes(selection_for(&bytes), &bytes).expect("PE should parse");

        assert_eq!(image.rva_to_file_offset(0x10), Some(0x10));
        assert_eq!(image.rva_to_file_offset(0x1010), Some(0x210));
        assert_eq!(image.va_to_file_offset(0x1400_01010), Some(0x210));
        assert_eq!(image.file_offset_to_rva(0x210), Some(0x1010));
        assert_eq!(image.file_offset_to_va(0x210), Some(0x1400_01010));
        assert_eq!(image.rva_to_file_offset(0x12F0), None);
    }

    #[test]
    fn rejects_non_pe_bytes_with_clear_error() {
        let bytes = b"not a PE file";
        let error = parse_pe_bytes(selection_for(bytes), bytes).expect_err("not PE");

        assert_eq!(error, PeParseError::MissingDosSignature);
    }
}
