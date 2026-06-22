use std::path::{Path, PathBuf};

pub const APP_NAME: &str = "FY_IDA";
pub const PE_DIRECTORY_EXPORT: usize = 0;
pub const PE_DIRECTORY_IMPORT: usize = 1;
pub const PE_DIRECTORY_BASERELOC: usize = 5;
pub const PE_DIRECTORY_LIMIT: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSelection {
    path: PathBuf,
    display_name: String,
    size_bytes: u64,
}

impl FileSelection {
    pub fn new(path: PathBuf, size_bytes: u64) -> Self {
        let display_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
            .unwrap_or_else(|| path.display().to_string());

        Self {
            path,
            display_name,
            size_bytes,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub fn formatted_size(&self) -> String {
        format_file_size(self.size_bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeKind {
    Pe32,
    Pe32Plus,
}

impl PeKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pe32 => "PE32",
            Self::Pe32Plus => "PE32+",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DosHeader {
    pub e_magic: u16,
    pub e_lfanew: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoffFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

impl CoffFileHeader {
    pub fn machine_label(&self) -> &'static str {
        machine_label(self.machine)
    }

    pub fn characteristics_labels(&self) -> Vec<&'static str> {
        file_characteristics_labels(self.characteristics)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl PeDataDirectory {
    pub fn is_present(&self) -> bool {
        self.virtual_address != 0 && self.size != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeOptionalHeader {
    pub magic: u16,
    pub kind: PeKind,
    pub address_of_entry_point: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: Vec<PeDataDirectory>,
}

impl PeOptionalHeader {
    pub fn subsystem_label(&self) -> &'static str {
        subsystem_label(self.subsystem)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtHeaders {
    pub signature: u32,
    pub file_header: CoffFileHeader,
    pub optional_header: PeOptionalHeader,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeSection {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

impl PeSection {
    pub fn virtual_address_va(&self, image_base: u64) -> u64 {
        image_base + u64::from(self.virtual_address)
    }

    pub fn mapped_size(&self) -> u32 {
        self.virtual_size.max(self.size_of_raw_data)
    }

    pub fn permissions(&self) -> String {
        let read = if self.characteristics & 0x4000_0000 != 0 {
            "R"
        } else {
            "-"
        };
        let write = if self.characteristics & 0x8000_0000 != 0 {
            "W"
        } else {
            "-"
        };
        let execute = if self.characteristics & 0x2000_0000 != 0 {
            "X"
        } else {
            "-"
        };

        format!("{read}{write}{execute}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeImage {
    file: FileSelection,
    pub dos_header: DosHeader,
    pub nt_headers: NtHeaders,
    pub sections: Vec<PeSection>,
}

impl PeImage {
    pub fn new(
        file: FileSelection,
        dos_header: DosHeader,
        nt_headers: NtHeaders,
        sections: Vec<PeSection>,
    ) -> Self {
        Self {
            file,
            dos_header,
            nt_headers,
            sections,
        }
    }

    pub fn file(&self) -> &FileSelection {
        &self.file
    }

    pub fn image_base(&self) -> u64 {
        self.nt_headers.optional_header.image_base
    }

    pub fn entry_point_rva(&self) -> u32 {
        self.nt_headers.optional_header.address_of_entry_point
    }

    pub fn entry_point_va(&self) -> u64 {
        self.rva_to_va(u64::from(self.entry_point_rva()))
    }

    pub fn machine_label(&self) -> &'static str {
        self.nt_headers.file_header.machine_label()
    }

    pub fn subsystem_label(&self) -> &'static str {
        self.nt_headers.optional_header.subsystem_label()
    }

    pub fn rva_to_va(&self, rva: u64) -> u64 {
        self.image_base().saturating_add(rva)
    }

    pub fn va_to_rva(&self, va: u64) -> Option<u64> {
        va.checked_sub(self.image_base())
    }

    pub fn rva_to_file_offset(&self, rva: u64) -> Option<u64> {
        if rva < u64::from(self.nt_headers.optional_header.size_of_headers)
            && rva < self.file.size_bytes()
        {
            return Some(rva);
        }

        self.sections.iter().find_map(|section| {
            let start = u64::from(section.virtual_address);
            let mapped_size = u64::from(section.mapped_size());
            let raw_size = u64::from(section.size_of_raw_data);
            let delta = rva.checked_sub(start)?;

            if delta < mapped_size && delta < raw_size {
                Some(u64::from(section.pointer_to_raw_data) + delta)
            } else {
                None
            }
        })
    }

    pub fn file_offset_to_rva(&self, file_offset: u64) -> Option<u64> {
        if file_offset < u64::from(self.nt_headers.optional_header.size_of_headers)
            && file_offset < self.file.size_bytes()
        {
            return Some(file_offset);
        }

        self.sections.iter().find_map(|section| {
            let start = u64::from(section.pointer_to_raw_data);
            let raw_size = u64::from(section.size_of_raw_data);
            let delta = file_offset.checked_sub(start)?;

            if delta < raw_size {
                Some(u64::from(section.virtual_address) + delta)
            } else {
                None
            }
        })
    }

    pub fn va_to_file_offset(&self, va: u64) -> Option<u64> {
        self.va_to_rva(va)
            .and_then(|rva| self.rva_to_file_offset(rva))
    }

    pub fn file_offset_to_va(&self, file_offset: u64) -> Option<u64> {
        self.file_offset_to_rva(file_offset)
            .map(|rva| self.rva_to_va(rva))
    }

    pub fn data_directory(&self, index: usize) -> Option<&PeDataDirectory> {
        self.nt_headers.optional_header.data_directories.get(index)
    }

    pub fn section_containing_rva(&self, rva: u64) -> Option<&PeSection> {
        self.sections.iter().find(|section| {
            let start = u64::from(section.virtual_address);
            let end = start.saturating_add(u64::from(section.mapped_size()));
            rva >= start && rva < end
        })
    }

    pub fn section_containing_va(&self, va: u64) -> Option<&PeSection> {
        let rva = self.va_to_rva(va)?;
        self.section_containing_rva(rva)
    }

    pub fn is_executable_rva(&self, rva: u64) -> bool {
        self.section_containing_rva(rva)
            .map(|section| section.characteristics & 0x2000_0000 != 0)
            .unwrap_or(false)
    }

    pub fn is_executable_va(&self, va: u64) -> bool {
        self.va_to_rva(va)
            .map(|rva| self.is_executable_rva(rva))
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalysisState {
    NoFile,
    NotAnalyzed,
    PeLoaded,
    Error(String),
}

impl AnalysisState {
    pub fn label(&self) -> String {
        match self {
            Self::NoFile => "尚未打开文件".to_owned(),
            Self::NotAnalyzed => "已选择文件 / 暂未分析".to_owned(),
            Self::PeLoaded => "PE 已加载".to_owned(),
            Self::Error(message) => format!("错误：{message}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProjectState {
    selected_file: Option<FileSelection>,
    pe_image: Option<PeImage>,
    analysis_state: AnalysisState,
    dirty: bool,
    current_address: Option<u64>,
    current_rva: Option<u64>,
    current_file_offset: Option<u64>,
    current_function: Option<String>,
}

impl Default for ProjectState {
    fn default() -> Self {
        Self {
            selected_file: None,
            pe_image: None,
            analysis_state: AnalysisState::NoFile,
            dirty: false,
            current_address: None,
            current_rva: None,
            current_file_offset: None,
            current_function: None,
        }
    }
}

impl ProjectState {
    pub fn selected_file(&self) -> Option<&FileSelection> {
        self.selected_file.as_ref()
    }

    pub fn pe_image(&self) -> Option<&PeImage> {
        self.pe_image.as_ref()
    }

    pub fn analysis_state(&self) -> &AnalysisState {
        &self.analysis_state
    }

    pub fn dirty(&self) -> bool {
        self.dirty
    }

    pub fn current_address(&self) -> Option<u64> {
        self.current_address
    }

    pub fn current_rva(&self) -> Option<u64> {
        self.current_rva
    }

    pub fn current_file_offset(&self) -> Option<u64> {
        self.current_file_offset
    }

    pub fn current_function(&self) -> Option<&str> {
        self.current_function.as_deref()
    }

    pub fn select_file(&mut self, selection: FileSelection) {
        self.selected_file = Some(selection);
        self.pe_image = None;
        self.analysis_state = AnalysisState::NotAnalyzed;
        self.dirty = true;
        self.jump_to(0x1400_01000, Some("入口占位".to_owned()));
    }

    pub fn load_pe(&mut self, pe_image: PeImage) {
        let entry_point = pe_image.entry_point_va();
        let entry_rva = u64::from(pe_image.entry_point_rva());
        let entry_file_offset = pe_image.rva_to_file_offset(entry_rva);

        self.selected_file = Some(pe_image.file().clone());
        self.pe_image = Some(pe_image);
        self.analysis_state = AnalysisState::PeLoaded;
        self.dirty = true;
        self.current_address = Some(entry_point);
        self.current_rva = Some(entry_rva);
        self.current_file_offset = entry_file_offset;
        self.current_function = Some("入口点".to_owned());
    }

    pub fn set_file_error(&mut self, selection: FileSelection, message: impl Into<String>) {
        self.selected_file = Some(selection);
        self.pe_image = None;
        self.analysis_state = AnalysisState::Error(message.into());
        self.dirty = false;
        self.current_address = None;
        self.current_rva = None;
        self.current_file_offset = None;
        self.current_function = None;
    }

    pub fn set_error(&mut self, message: impl Into<String>) {
        self.pe_image = None;
        self.analysis_state = AnalysisState::Error(message.into());
    }

    pub fn jump_to(&mut self, address: u64, function: Option<String>) {
        self.current_address = Some(address);

        if let Some(pe_image) = &self.pe_image {
            self.current_rva = pe_image.va_to_rva(address);
            self.current_file_offset = self
                .current_rva
                .and_then(|rva| pe_image.rva_to_file_offset(rva));
        } else {
            self.current_rva = address.checked_sub(0x1400_00000);
            self.current_file_offset = self.current_rva.map(|rva| rva.saturating_add(0x400));
        }

        self.current_function = function;
    }

    pub fn project_status_label(&self) -> &'static str {
        if self.dirty {
            "未保存"
        } else {
            "已保存"
        }
    }
}

pub fn format_address(value: Option<u64>, prefix: &str) -> String {
    match value {
        Some(value) => format!("{prefix} {value:08X}"),
        None => format!("{prefix} --------"),
    }
}

pub fn format_hex_u16(value: u16) -> String {
    format!("0x{value:04X}")
}

pub fn format_hex_u32(value: u32) -> String {
    format!("0x{value:08X}")
}

pub fn format_hex_u64(value: u64) -> String {
    format!("0x{value:016X}")
}

fn format_file_size(size_bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let bytes = size_bytes as f64;
    if bytes >= GB {
        format!("{:.2} GB", bytes / GB)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes / MB)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes / KB)
    } else {
        format!("{size_bytes} B")
    }
}

fn machine_label(machine: u16) -> &'static str {
    match machine {
        0x014C => "x86 (I386)",
        0x0200 => "Intel Itanium",
        0x8664 => "x64 (AMD64)",
        0xAA64 => "ARM64",
        0x01C0 => "ARM",
        0x01C4 => "ARM Thumb-2",
        _ => "未知 Machine",
    }
}

fn subsystem_label(subsystem: u16) -> &'static str {
    match subsystem {
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows Console",
        7 => "POSIX Console",
        9 => "Windows CE GUI",
        10 => "EFI Application",
        11 => "EFI Boot Service Driver",
        12 => "EFI Runtime Driver",
        13 => "EFI ROM",
        14 => "Xbox",
        16 => "Windows Boot Application",
        _ => "未知 Subsystem",
    }
}

fn file_characteristics_labels(characteristics: u16) -> Vec<&'static str> {
    let flags = [
        (0x0001, "RELOCS_STRIPPED"),
        (0x0002, "EXECUTABLE_IMAGE"),
        (0x0004, "LINE_NUMS_STRIPPED"),
        (0x0008, "LOCAL_SYMS_STRIPPED"),
        (0x0020, "LARGE_ADDRESS_AWARE"),
        (0x0100, "32BIT_MACHINE"),
        (0x0200, "DEBUG_STRIPPED"),
        (0x1000, "SYSTEM"),
        (0x2000, "DLL"),
        (0x4000, "UP_SYSTEM_ONLY"),
    ];

    flags
        .into_iter()
        .filter_map(|(bit, label)| (characteristics & bit != 0).then_some(label))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pe_image() -> PeImage {
        let selection = FileSelection::new(PathBuf::from(r"C:\samples\demo.exe"), 4096);
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
                size_of_image: 0x2000,
                size_of_headers: 0x200,
                subsystem: 3,
                dll_characteristics: 0x8160,
                number_of_rva_and_sizes: 16,
                data_directories: vec![
                    PeDataDirectory {
                        virtual_address: 0,
                        size: 0,
                    };
                    16
                ],
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

    #[test]
    fn file_selection_uses_file_name() {
        let selection = FileSelection::new(PathBuf::from(r"C:\samples\demo.exe"), 42);
        assert_eq!(selection.display_name(), "demo.exe");
        assert_eq!(selection.formatted_size(), "42 B");
    }

    #[test]
    fn project_select_file_sets_not_analyzed_state() {
        let mut project = ProjectState::default();
        project.select_file(FileSelection::new(PathBuf::from("demo.bin"), 4096));
        assert_eq!(project.analysis_state(), &AnalysisState::NotAnalyzed);
        assert_eq!(project.project_status_label(), "未保存");
    }

    #[test]
    fn maps_rva_va_and_file_offsets() {
        let image = sample_pe_image();
        let entry_va = 0x1400_01010;

        assert_eq!(image.rva_to_va(0x1010), entry_va);
        assert_eq!(image.va_to_rva(entry_va), Some(0x1010));
        assert_eq!(image.rva_to_file_offset(0x1010), Some(0x210));
        assert_eq!(image.va_to_file_offset(entry_va), Some(0x210));
        assert_eq!(image.file_offset_to_rva(0x210), Some(0x1010));
        assert_eq!(image.file_offset_to_va(0x210), Some(entry_va));
        assert_eq!(image.rva_to_file_offset(0x40), Some(0x40));
        assert_eq!(image.rva_to_file_offset(0x12F0), None);
    }

    #[test]
    fn project_load_pe_sets_entry_point_context() {
        let image = sample_pe_image();
        let mut project = ProjectState::default();

        project.load_pe(image);

        assert_eq!(project.analysis_state(), &AnalysisState::PeLoaded);
        assert_eq!(project.current_address(), Some(0x1400_01010));
        assert_eq!(project.current_rva(), Some(0x1010));
        assert_eq!(project.current_file_offset(), Some(0x210));
        assert_eq!(project.current_function(), Some("入口点"));
    }
}
