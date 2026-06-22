use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const APP_NAME: &str = "FY_IDA";
pub const PROJECT_SCHEMA_VERSION: u32 = 3;
const MAX_NAVIGATION_HISTORY: usize = 128;
pub const PE_DIRECTORY_EXPORT: usize = 0;
pub const PE_DIRECTORY_IMPORT: usize = 1;
pub const PE_DIRECTORY_BASERELOC: usize = 5;
pub const PE_DIRECTORY_DEBUG: usize = 6;
pub const PE_DIRECTORY_LIMIT: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RawArch {
    X64,
}

#[derive(Debug)]
pub enum ProjectIoError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    Encode {
        source: serde_json::Error,
    },
}

impl fmt::Display for ProjectIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(formatter, "无法读取项目文件：{} ({source})", path.display())
            }
            Self::Write { path, source } => {
                write!(formatter, "无法写入项目文件：{} ({source})", path.display())
            }
            Self::Parse { path, source } => {
                write!(formatter, "项目文件格式无效：{} ({source})", path.display())
            }
            Self::Encode { source } => write!(formatter, "项目文件编码失败：{source}"),
        }
    }
}

impl std::error::Error for ProjectIoError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProjectInputKind {
    Pe,
    Raw {
        base_address: u64,
        entry_address: u64,
        arch: RawArch,
    },
}

impl ProjectInputKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pe => "PE",
            Self::Raw { .. } => "Raw Binary",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectInput {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub kind: ProjectInputKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectFunction {
    pub start_va: u64,
    pub name: String,
    pub size: u64,
    pub instruction_count: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectDebugInfo {
    pub pe_pdb_path: Option<String>,
    pub pe_pdb_guid: Option<String>,
    pub pe_pdb_age: Option<u32>,
    pub loaded_pdb_path: Option<String>,
    pub loaded_pdb_guid: Option<String>,
    pub loaded_pdb_age: Option<u32>,
    pub matched: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectSymbol {
    pub address: Option<u64>,
    pub rva: Option<u32>,
    pub name: String,
    pub original_name: String,
    pub kind: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectType {
    pub name: String,
    pub kind: String,
    pub source: String,
    #[serde(default)]
    pub definition: Option<TypeDefinition>,
}

impl ProjectType {
    pub fn simple(
        name: impl Into<String>,
        kind: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            kind: kind.into(),
            source: source.into(),
            definition: None,
        }
    }

    pub fn with_definition(
        name: impl Into<String>,
        source: impl Into<String>,
        definition: TypeDefinition,
    ) -> Self {
        let kind = definition.label().to_owned();
        Self {
            name: name.into(),
            kind,
            source: source.into(),
            definition: Some(definition),
        }
    }

    pub fn display_signature(&self) -> String {
        match &self.definition {
            Some(definition) => definition.signature(&self.name),
            None => format!("{} {}", self.kind, self.name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "definition_kind", rename_all = "snake_case")]
pub enum TypeDefinition {
    Integer {
        signed: bool,
        bits: u16,
    },
    Pointer {
        to: String,
    },
    Array {
        element: String,
        count: u64,
    },
    Struct {
        fields: Vec<TypeField>,
    },
    Union {
        fields: Vec<TypeField>,
    },
    Enum {
        variants: Vec<EnumVariant>,
    },
    Typedef {
        target: String,
    },
    Function {
        return_type: String,
        calling_convention: String,
        parameters: Vec<TypeParameter>,
    },
    Opaque,
}

impl TypeDefinition {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Integer { .. } => "integer",
            Self::Pointer { .. } => "pointer",
            Self::Array { .. } => "array",
            Self::Struct { .. } => "struct",
            Self::Union { .. } => "union",
            Self::Enum { .. } => "enum",
            Self::Typedef { .. } => "typedef",
            Self::Function { .. } => "function",
            Self::Opaque => "opaque",
        }
    }

    pub fn signature(&self, name: &str) -> String {
        match self {
            Self::Integer { signed, bits } => {
                let prefix = if *signed { "int" } else { "uint" };
                format!("{prefix}{bits}_t {name}")
            }
            Self::Pointer { to } => format!("{to} *{name}"),
            Self::Array { element, count } => format!("{element} {name}[{count}]"),
            Self::Struct { fields } => format!("struct {name} ({} fields)", fields.len()),
            Self::Union { fields } => format!("union {name} ({} fields)", fields.len()),
            Self::Enum { variants } => format!("enum {name} ({} variants)", variants.len()),
            Self::Typedef { target } => format!("typedef {target} {name}"),
            Self::Function {
                return_type,
                calling_convention,
                parameters,
            } => {
                let params = if parameters.is_empty() {
                    "void".to_owned()
                } else {
                    parameters
                        .iter()
                        .map(|parameter| format!("{} {}", parameter.type_name, parameter.name))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                if calling_convention.is_empty() {
                    format!("{return_type} {name}({params})")
                } else {
                    format!("{return_type} {calling_convention} {name}({params})")
                }
            }
            Self::Opaque => format!("opaque {name}"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeField {
    pub name: String,
    pub type_name: String,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumVariant {
    pub name: String,
    pub value: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeParameter {
    pub name: String,
    pub type_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProjectTypeTarget {
    Address(u64),
    Function(u64),
}

impl ProjectTypeTarget {
    pub fn address(self) -> u64 {
        match self {
            Self::Address(address) | Self::Function(address) => address,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Address(_) => "address",
            Self::Function(_) => "function",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectTypeApplication {
    pub target: ProjectTypeTarget,
    pub type_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectSourceFile {
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserName {
    pub address: u64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserComment {
    pub address: u64,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionComment {
    pub function_start: u64,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bookmark {
    pub address: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManualDefinitionKind {
    Code,
    Data,
}

impl ManualDefinitionKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Code => "代码",
            Self::Data => "数据",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualDefinition {
    pub address: u64,
    pub kind: ManualDefinitionKind,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserAnnotations {
    pub names: Vec<UserName>,
    pub comments: Vec<UserComment>,
    pub function_comments: Vec<FunctionComment>,
    pub bookmarks: Vec<Bookmark>,
    pub manual_definitions: Vec<ManualDefinition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectDocument {
    pub schema_version: u32,
    pub app_version: String,
    pub input: ProjectInput,
    pub functions: Vec<ProjectFunction>,
    #[serde(default)]
    pub debug_info: Option<ProjectDebugInfo>,
    #[serde(default)]
    pub symbols: Vec<ProjectSymbol>,
    #[serde(default)]
    pub types: Vec<ProjectType>,
    #[serde(default)]
    pub type_applications: Vec<ProjectTypeApplication>,
    #[serde(default)]
    pub source_files: Vec<ProjectSourceFile>,
    pub annotations: UserAnnotations,
}

impl ProjectDocument {
    pub fn new(
        app_version: impl Into<String>,
        input: ProjectInput,
        functions: Vec<ProjectFunction>,
        debug_info: Option<ProjectDebugInfo>,
        symbols: Vec<ProjectSymbol>,
        types: Vec<ProjectType>,
        type_applications: Vec<ProjectTypeApplication>,
        source_files: Vec<ProjectSourceFile>,
        annotations: UserAnnotations,
    ) -> Self {
        Self {
            schema_version: PROJECT_SCHEMA_VERSION,
            app_version: app_version.into(),
            input,
            functions,
            debug_info,
            symbols,
            types,
            type_applications,
            source_files,
            annotations,
        }
    }

    pub fn save_to_path(&self, path: impl AsRef<Path>) -> Result<(), ProjectIoError> {
        let path = path.as_ref().to_path_buf();
        let encoded = serde_json::to_string_pretty(self)
            .map_err(|source| ProjectIoError::Encode { source })?;
        std::fs::write(&path, encoded).map_err(|source| ProjectIoError::Write { path, source })
    }

    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, ProjectIoError> {
        let path = path.as_ref().to_path_buf();
        let bytes = std::fs::read(&path).map_err(|source| ProjectIoError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_slice(&bytes).map_err(|source| ProjectIoError::Parse { path, source })
    }
}

impl RawArch {
    pub fn label(self) -> &'static str {
        match self {
            Self::X64 => "x64",
        }
    }
}

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
pub struct RawImage {
    file: FileSelection,
    pub base_address: u64,
    pub entry_address: u64,
    pub arch: RawArch,
}

impl RawImage {
    pub fn new(file: FileSelection, base_address: u64, entry_address: u64, arch: RawArch) -> Self {
        Self {
            file,
            base_address,
            entry_address,
            arch,
        }
    }

    pub fn file(&self) -> &FileSelection {
        &self.file
    }

    pub fn size_bytes(&self) -> u64 {
        self.file.size_bytes()
    }

    pub fn end_address(&self) -> u64 {
        self.base_address.saturating_add(self.size_bytes())
    }

    pub fn va_to_file_offset(&self, va: u64) -> Option<u64> {
        let offset = va.checked_sub(self.base_address)?;
        (offset < self.size_bytes()).then_some(offset)
    }

    pub fn file_offset_to_va(&self, file_offset: u64) -> Option<u64> {
        (file_offset < self.size_bytes()).then_some(self.base_address.saturating_add(file_offset))
    }

    pub fn va_to_rva(&self, va: u64) -> Option<u64> {
        self.va_to_file_offset(va)
    }

    pub fn rva_to_va(&self, rva: u64) -> Option<u64> {
        self.file_offset_to_va(rva)
    }

    pub fn entry_offset(&self) -> Option<u64> {
        self.va_to_file_offset(self.entry_address)
    }

    pub fn contains_va(&self, va: u64) -> bool {
        self.va_to_file_offset(va).is_some()
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
enum AnnotationCommand {
    Rename {
        address: u64,
        before: Option<String>,
        after: Option<String>,
    },
    AddressComment {
        address: u64,
        before: Option<String>,
        after: Option<String>,
    },
    FunctionComment {
        function_start: u64,
        before: Option<String>,
        after: Option<String>,
    },
    Bookmark {
        address: u64,
        before: bool,
        after: bool,
    },
    ManualDefinition {
        address: u64,
        before: Option<ManualDefinitionKind>,
        after: Option<ManualDefinitionKind>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NavigationPoint {
    address: u64,
    function: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalysisState {
    NoFile,
    NotAnalyzed,
    PeLoaded,
    RawLoaded,
    Error(String),
}

impl AnalysisState {
    pub fn label(&self) -> String {
        match self {
            Self::NoFile => "尚未打开文件".to_owned(),
            Self::NotAnalyzed => "已选择文件 / 暂未分析".to_owned(),
            Self::PeLoaded => "PE 已加载".to_owned(),
            Self::RawLoaded => "Raw Binary 已加载".to_owned(),
            Self::Error(message) => format!("错误：{message}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProjectState {
    selected_file: Option<FileSelection>,
    pe_image: Option<PeImage>,
    raw_image: Option<RawImage>,
    analysis_state: AnalysisState,
    dirty: bool,
    user_names: BTreeMap<u64, String>,
    address_comments: BTreeMap<u64, String>,
    function_comments: BTreeMap<u64, String>,
    bookmarks: BTreeSet<u64>,
    manual_definitions: BTreeMap<u64, ManualDefinitionKind>,
    type_definitions: BTreeMap<String, ProjectType>,
    type_applications: BTreeMap<ProjectTypeTarget, String>,
    undo_stack: Vec<AnnotationCommand>,
    redo_stack: Vec<AnnotationCommand>,
    back_stack: Vec<NavigationPoint>,
    forward_stack: Vec<NavigationPoint>,
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
            raw_image: None,
            analysis_state: AnalysisState::NoFile,
            dirty: false,
            user_names: BTreeMap::new(),
            address_comments: BTreeMap::new(),
            function_comments: BTreeMap::new(),
            bookmarks: BTreeSet::new(),
            manual_definitions: BTreeMap::new(),
            type_definitions: builtin_type_library()
                .into_iter()
                .map(|item| (item.name.clone(), item))
                .collect(),
            type_applications: BTreeMap::new(),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            back_stack: Vec::new(),
            forward_stack: Vec::new(),
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

    pub fn raw_image(&self) -> Option<&RawImage> {
        self.raw_image.as_ref()
    }

    pub fn analysis_state(&self) -> &AnalysisState {
        &self.analysis_state
    }

    pub fn dirty(&self) -> bool {
        self.dirty
    }

    pub fn mark_saved(&mut self) {
        self.dirty = false;
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

    pub fn name_for(&self, address: u64) -> Option<&str> {
        self.user_names.get(&address).map(String::as_str)
    }

    pub fn address_comment(&self, address: u64) -> Option<&str> {
        self.address_comments.get(&address).map(String::as_str)
    }

    pub fn function_comment(&self, function_start: u64) -> Option<&str> {
        self.function_comments
            .get(&function_start)
            .map(String::as_str)
    }

    pub fn is_bookmarked(&self, address: u64) -> bool {
        self.bookmarks.contains(&address)
    }

    pub fn manual_definition(&self, address: u64) -> Option<ManualDefinitionKind> {
        self.manual_definitions.get(&address).copied()
    }

    pub fn project_types(&self) -> Vec<ProjectType> {
        self.type_definitions.values().cloned().collect()
    }

    pub fn project_type(&self, name: &str) -> Option<&ProjectType> {
        self.type_definitions.get(name)
    }

    pub fn type_applications(&self) -> Vec<ProjectTypeApplication> {
        self.type_applications
            .iter()
            .map(|(target, type_name)| ProjectTypeApplication {
                target: *target,
                type_name: type_name.clone(),
            })
            .collect()
    }

    pub fn applied_type(&self, target: ProjectTypeTarget) -> Option<&str> {
        self.type_applications.get(&target).map(String::as_str)
    }

    pub fn applied_address_type(&self, address: u64) -> Option<&str> {
        self.applied_type(ProjectTypeTarget::Address(address))
    }

    pub fn applied_function_type(&self, function_start: u64) -> Option<&str> {
        self.applied_type(ProjectTypeTarget::Function(function_start))
    }

    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    pub fn can_go_back(&self) -> bool {
        !self.back_stack.is_empty()
    }

    pub fn can_go_forward(&self) -> bool {
        !self.forward_stack.is_empty()
    }

    pub fn user_names(&self) -> Vec<UserName> {
        self.user_names
            .iter()
            .map(|(address, name)| UserName {
                address: *address,
                name: name.clone(),
            })
            .collect()
    }

    pub fn address_comments(&self) -> Vec<UserComment> {
        self.address_comments
            .iter()
            .map(|(address, text)| UserComment {
                address: *address,
                text: text.clone(),
            })
            .collect()
    }

    pub fn function_comments(&self) -> Vec<FunctionComment> {
        self.function_comments
            .iter()
            .map(|(function_start, text)| FunctionComment {
                function_start: *function_start,
                text: text.clone(),
            })
            .collect()
    }

    pub fn manual_definitions(&self) -> Vec<ManualDefinition> {
        self.manual_definitions
            .iter()
            .map(|(address, kind)| ManualDefinition {
                address: *address,
                kind: *kind,
            })
            .collect()
    }

    pub fn bookmarks(&self) -> Vec<Bookmark> {
        self.bookmarks
            .iter()
            .map(|address| Bookmark { address: *address })
            .collect()
    }

    pub fn select_file(&mut self, selection: FileSelection) {
        self.selected_file = Some(selection);
        self.pe_image = None;
        self.raw_image = None;
        self.clear_user_state();
        self.clear_navigation_history();
        self.analysis_state = AnalysisState::NotAnalyzed;
        self.dirty = true;
        self.set_current_location(0x1400_01000, Some("入口占位".to_owned()));
    }

    pub fn load_pe(&mut self, pe_image: PeImage) {
        let entry_point = pe_image.entry_point_va();
        let entry_rva = u64::from(pe_image.entry_point_rva());
        let entry_file_offset = pe_image.rva_to_file_offset(entry_rva);

        self.selected_file = Some(pe_image.file().clone());
        self.pe_image = Some(pe_image);
        self.raw_image = None;
        self.clear_user_state();
        self.clear_navigation_history();
        self.analysis_state = AnalysisState::PeLoaded;
        self.dirty = true;
        self.current_address = Some(entry_point);
        self.current_rva = Some(entry_rva);
        self.current_file_offset = entry_file_offset;
        self.current_function = Some("入口点".to_owned());
    }

    pub fn load_raw(&mut self, raw_image: RawImage) {
        let entry_point = raw_image.entry_address;
        let entry_rva = raw_image.entry_offset();

        self.selected_file = Some(raw_image.file().clone());
        self.pe_image = None;
        self.raw_image = Some(raw_image);
        self.clear_user_state();
        self.clear_navigation_history();
        self.analysis_state = AnalysisState::RawLoaded;
        self.dirty = true;
        self.current_address = Some(entry_point);
        self.current_rva = entry_rva;
        self.current_file_offset = entry_rva;
        self.current_function = Some("raw_entry".to_owned());
    }

    pub fn set_file_error(&mut self, selection: FileSelection, message: impl Into<String>) {
        self.selected_file = Some(selection);
        self.pe_image = None;
        self.raw_image = None;
        self.clear_user_state();
        self.clear_navigation_history();
        self.analysis_state = AnalysisState::Error(message.into());
        self.dirty = false;
        self.current_address = None;
        self.current_rva = None;
        self.current_file_offset = None;
        self.current_function = None;
    }

    pub fn set_error(&mut self, message: impl Into<String>) {
        self.pe_image = None;
        self.raw_image = None;
        self.clear_user_state();
        self.clear_navigation_history();
        self.analysis_state = AnalysisState::Error(message.into());
    }

    pub fn jump_to(&mut self, address: u64, function: Option<String>) {
        if self.current_address != Some(address) {
            if let Some(point) = self.current_navigation_point() {
                self.back_stack.push(point);
                if self.back_stack.len() > MAX_NAVIGATION_HISTORY {
                    self.back_stack.remove(0);
                }
            }
            self.forward_stack.clear();
        }

        self.set_current_location(address, function);
    }

    pub fn go_back(&mut self) -> bool {
        let Some(previous) = self.back_stack.pop() else {
            return false;
        };
        if let Some(current) = self.current_navigation_point() {
            self.forward_stack.push(current);
        }
        self.set_current_location(previous.address, previous.function);
        true
    }

    pub fn go_forward(&mut self) -> bool {
        let Some(next) = self.forward_stack.pop() else {
            return false;
        };
        if let Some(current) = self.current_navigation_point() {
            self.back_stack.push(current);
        }
        self.set_current_location(next.address, next.function);
        true
    }

    fn set_current_location(&mut self, address: u64, function: Option<String>) {
        self.current_address = Some(address);

        if let Some(pe_image) = &self.pe_image {
            self.current_rva = pe_image.va_to_rva(address);
            self.current_file_offset = self
                .current_rva
                .and_then(|rva| pe_image.rva_to_file_offset(rva));
        } else if let Some(raw_image) = &self.raw_image {
            self.current_rva = raw_image.va_to_rva(address);
            self.current_file_offset = raw_image.va_to_file_offset(address);
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

    pub fn rename_address(&mut self, address: u64, name: impl Into<String>) {
        let after = normalize_user_text(name.into());
        let before = self.user_names.get(&address).cloned();
        if before == after {
            return;
        }
        let command = AnnotationCommand::Rename {
            address,
            before,
            after,
        };
        self.apply_command(&command, true);
        self.undo_stack.push(command);
        self.redo_stack.clear();
    }

    pub fn set_address_comment(&mut self, address: u64, text: impl Into<String>) {
        let after = normalize_user_text(text.into());
        let before = self.address_comments.get(&address).cloned();
        if before == after {
            return;
        }
        let command = AnnotationCommand::AddressComment {
            address,
            before,
            after,
        };
        self.apply_command(&command, true);
        self.undo_stack.push(command);
        self.redo_stack.clear();
    }

    pub fn set_function_comment(&mut self, function_start: u64, text: impl Into<String>) {
        let after = normalize_user_text(text.into());
        let before = self.function_comments.get(&function_start).cloned();
        if before == after {
            return;
        }
        let command = AnnotationCommand::FunctionComment {
            function_start,
            before,
            after,
        };
        self.apply_command(&command, true);
        self.undo_stack.push(command);
        self.redo_stack.clear();
    }

    pub fn toggle_bookmark(&mut self, address: u64) {
        let before = self.bookmarks.contains(&address);
        let command = AnnotationCommand::Bookmark {
            address,
            before,
            after: !before,
        };
        self.apply_command(&command, true);
        self.undo_stack.push(command);
        self.redo_stack.clear();
    }

    pub fn set_manual_definition(&mut self, address: u64, kind: ManualDefinitionKind) {
        let before = self.manual_definitions.get(&address).copied();
        let after = Some(kind);
        if before == after {
            return;
        }
        let command = AnnotationCommand::ManualDefinition {
            address,
            before,
            after,
        };
        self.apply_command(&command, true);
        self.undo_stack.push(command);
        self.redo_stack.clear();
    }

    pub fn upsert_project_type(&mut self, type_item: ProjectType) {
        if type_item.name.trim().is_empty() {
            return;
        }
        self.type_definitions
            .insert(type_item.name.trim().to_owned(), type_item);
        self.dirty = true;
    }

    pub fn upsert_project_types(&mut self, types: impl IntoIterator<Item = ProjectType>) -> usize {
        let mut count = 0;
        for type_item in types {
            if type_item.name.trim().is_empty() {
                continue;
            }
            self.type_definitions
                .insert(type_item.name.trim().to_owned(), type_item);
            count += 1;
        }
        if count > 0 {
            self.dirty = true;
        }
        count
    }

    pub fn replace_project_types(&mut self, types: Vec<ProjectType>) {
        self.type_definitions = builtin_type_library()
            .into_iter()
            .map(|item| (item.name.clone(), item))
            .collect();
        for type_item in types {
            if type_item.name.trim().is_empty() {
                continue;
            }
            self.type_definitions
                .insert(type_item.name.trim().to_owned(), type_item);
        }
        self.dirty = false;
    }

    pub fn apply_type_to_target(
        &mut self,
        target: ProjectTypeTarget,
        type_name: impl Into<String>,
    ) {
        let type_name = type_name.into().trim().to_owned();
        if type_name.is_empty() {
            self.type_applications.remove(&target);
        } else {
            self.type_applications.insert(target, type_name);
        }
        self.dirty = true;
    }

    pub fn replace_type_applications(&mut self, applications: Vec<ProjectTypeApplication>) {
        self.type_applications = applications
            .into_iter()
            .filter_map(|application| {
                let type_name = application.type_name.trim().to_owned();
                (!type_name.is_empty()).then_some((application.target, type_name))
            })
            .collect();
        self.dirty = false;
    }

    pub fn undo(&mut self) -> bool {
        let Some(command) = self.undo_stack.pop() else {
            return false;
        };
        self.apply_command(&command, false);
        self.redo_stack.push(command);
        true
    }

    pub fn redo(&mut self) -> bool {
        let Some(command) = self.redo_stack.pop() else {
            return false;
        };
        self.apply_command(&command, true);
        self.undo_stack.push(command);
        true
    }

    pub fn annotations(&self) -> UserAnnotations {
        UserAnnotations {
            names: self
                .user_names
                .iter()
                .map(|(address, name)| UserName {
                    address: *address,
                    name: name.clone(),
                })
                .collect(),
            comments: self
                .address_comments
                .iter()
                .map(|(address, text)| UserComment {
                    address: *address,
                    text: text.clone(),
                })
                .collect(),
            function_comments: self
                .function_comments
                .iter()
                .map(|(function_start, text)| FunctionComment {
                    function_start: *function_start,
                    text: text.clone(),
                })
                .collect(),
            bookmarks: self.bookmarks(),
            manual_definitions: self
                .manual_definitions
                .iter()
                .map(|(address, kind)| ManualDefinition {
                    address: *address,
                    kind: *kind,
                })
                .collect(),
        }
    }

    pub fn apply_annotations(&mut self, annotations: UserAnnotations) {
        self.user_names = annotations
            .names
            .into_iter()
            .filter_map(|item| normalize_user_text(item.name).map(|name| (item.address, name)))
            .collect();
        self.address_comments = annotations
            .comments
            .into_iter()
            .filter_map(|item| normalize_user_text(item.text).map(|text| (item.address, text)))
            .collect();
        self.function_comments = annotations
            .function_comments
            .into_iter()
            .filter_map(|item| {
                normalize_user_text(item.text).map(|text| (item.function_start, text))
            })
            .collect();
        self.bookmarks = annotations
            .bookmarks
            .into_iter()
            .map(|bookmark| bookmark.address)
            .collect();
        self.manual_definitions = annotations
            .manual_definitions
            .into_iter()
            .map(|definition| (definition.address, definition.kind))
            .collect();
        self.undo_stack.clear();
        self.redo_stack.clear();
        self.dirty = false;
    }

    fn clear_user_state(&mut self) {
        self.user_names.clear();
        self.address_comments.clear();
        self.function_comments.clear();
        self.bookmarks.clear();
        self.manual_definitions.clear();
        self.type_definitions = builtin_type_library()
            .into_iter()
            .map(|item| (item.name.clone(), item))
            .collect();
        self.type_applications.clear();
        self.undo_stack.clear();
        self.redo_stack.clear();
    }

    fn clear_navigation_history(&mut self) {
        self.back_stack.clear();
        self.forward_stack.clear();
    }

    fn current_navigation_point(&self) -> Option<NavigationPoint> {
        self.current_address.map(|address| NavigationPoint {
            address,
            function: self.current_function.clone(),
        })
    }

    fn apply_command(&mut self, command: &AnnotationCommand, forward: bool) {
        match command {
            AnnotationCommand::Rename {
                address,
                before,
                after,
            } => set_optional_string(
                &mut self.user_names,
                *address,
                choose(before, after, forward),
            ),
            AnnotationCommand::AddressComment {
                address,
                before,
                after,
            } => set_optional_string(
                &mut self.address_comments,
                *address,
                choose(before, after, forward),
            ),
            AnnotationCommand::FunctionComment {
                function_start,
                before,
                after,
            } => set_optional_string(
                &mut self.function_comments,
                *function_start,
                choose(before, after, forward),
            ),
            AnnotationCommand::Bookmark {
                address,
                before,
                after,
            } => {
                let value = if forward { *after } else { *before };
                if value {
                    self.bookmarks.insert(*address);
                } else {
                    self.bookmarks.remove(address);
                }
            }
            AnnotationCommand::ManualDefinition {
                address,
                before,
                after,
            } => match if forward { after } else { before } {
                Some(kind) => {
                    self.manual_definitions.insert(*address, *kind);
                }
                None => {
                    self.manual_definitions.remove(address);
                }
            },
        }
        self.dirty = true;
    }
}

pub fn builtin_type_library() -> Vec<ProjectType> {
    let mut types = Vec::new();
    for (name, signed, bits) in [
        ("int8_t", true, 8),
        ("uint8_t", false, 8),
        ("int16_t", true, 16),
        ("uint16_t", false, 16),
        ("int32_t", true, 32),
        ("uint32_t", false, 32),
        ("int64_t", true, 64),
        ("uint64_t", false, 64),
    ] {
        types.push(ProjectType::with_definition(
            name,
            "builtin:crt",
            TypeDefinition::Integer { signed, bits },
        ));
    }

    for (name, target, source) in [
        ("void", "void", "builtin:c"),
        ("char", "char", "builtin:c"),
        ("wchar_t", "wchar_t", "builtin:c"),
        ("bool", "bool", "builtin:c"),
        ("BYTE", "uint8_t", "builtin:windows"),
        ("WORD", "uint16_t", "builtin:windows"),
        ("DWORD", "uint32_t", "builtin:windows"),
        ("QWORD", "uint64_t", "builtin:windows"),
        ("BOOL", "int32_t", "builtin:windows"),
        ("HRESULT", "int32_t", "builtin:windows"),
        ("CHAR", "char", "builtin:windows"),
        ("WCHAR", "wchar_t", "builtin:windows"),
        ("size_t", "uint64_t", "builtin:crt"),
        ("intptr_t", "int64_t", "builtin:crt"),
        ("uintptr_t", "uint64_t", "builtin:crt"),
        ("errno_t", "int32_t", "builtin:crt"),
    ] {
        types.push(ProjectType::with_definition(
            name,
            source,
            TypeDefinition::Typedef {
                target: target.to_owned(),
            },
        ));
    }

    for (name, to, source) in [
        ("PVOID", "void", "builtin:windows"),
        ("LPVOID", "void", "builtin:windows"),
        ("LPCVOID", "const void", "builtin:windows"),
        ("LPSTR", "CHAR", "builtin:windows"),
        ("LPCSTR", "const CHAR", "builtin:windows"),
        ("LPWSTR", "WCHAR", "builtin:windows"),
        ("LPCWSTR", "const WCHAR", "builtin:windows"),
        ("HANDLE", "void", "builtin:windows"),
        ("HMODULE", "void", "builtin:windows"),
        ("HWND", "void", "builtin:windows"),
        ("FILE", "void", "builtin:crt"),
        ("va_list", "char", "builtin:crt"),
    ] {
        types.push(ProjectType::with_definition(
            name,
            source,
            TypeDefinition::Pointer { to: to.to_owned() },
        ));
    }

    types.extend([
        ProjectType::with_definition(
            "memcpy",
            "builtin:crt",
            TypeDefinition::Function {
                return_type: "void *".to_owned(),
                calling_convention: "__cdecl".to_owned(),
                parameters: vec![
                    TypeParameter {
                        name: "dest".to_owned(),
                        type_name: "void *".to_owned(),
                    },
                    TypeParameter {
                        name: "src".to_owned(),
                        type_name: "const void *".to_owned(),
                    },
                    TypeParameter {
                        name: "count".to_owned(),
                        type_name: "size_t".to_owned(),
                    },
                ],
            },
        ),
        ProjectType::with_definition(
            "memset",
            "builtin:crt",
            TypeDefinition::Function {
                return_type: "void *".to_owned(),
                calling_convention: "__cdecl".to_owned(),
                parameters: vec![
                    TypeParameter {
                        name: "dest".to_owned(),
                        type_name: "void *".to_owned(),
                    },
                    TypeParameter {
                        name: "value".to_owned(),
                        type_name: "int".to_owned(),
                    },
                    TypeParameter {
                        name: "count".to_owned(),
                        type_name: "size_t".to_owned(),
                    },
                ],
            },
        ),
        ProjectType::with_definition(
            "memcmp",
            "builtin:crt",
            TypeDefinition::Function {
                return_type: "int".to_owned(),
                calling_convention: "__cdecl".to_owned(),
                parameters: vec![
                    TypeParameter {
                        name: "left".to_owned(),
                        type_name: "const void *".to_owned(),
                    },
                    TypeParameter {
                        name: "right".to_owned(),
                        type_name: "const void *".to_owned(),
                    },
                    TypeParameter {
                        name: "count".to_owned(),
                        type_name: "size_t".to_owned(),
                    },
                ],
            },
        ),
    ]);

    types
}

pub fn import_c_header_types(source_name: impl Into<String>, text: &str) -> Vec<ProjectType> {
    let source_name = source_name.into();
    split_c_declarations(&strip_c_comments(text))
        .into_iter()
        .filter_map(|declaration| parse_c_declaration(&source_name, &declaration))
        .collect()
}

pub fn export_c_header_types(types: &[ProjectType]) -> String {
    let mut output = String::new();
    output.push_str("/* Generated by FY_IDA type system. */\n#pragma once\n\n");
    for type_item in types {
        if let Some(declaration) = type_to_c_declaration(type_item) {
            output.push_str(&declaration);
            if !declaration.ends_with('\n') {
                output.push('\n');
            }
            output.push('\n');
        }
    }
    output
}

fn strip_c_comments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '/' {
            match chars.peek().copied() {
                Some('/') => {
                    chars.next();
                    for next in chars.by_ref() {
                        if next == '\n' {
                            output.push('\n');
                            break;
                        }
                    }
                }
                Some('*') => {
                    chars.next();
                    let mut previous = '\0';
                    for next in chars.by_ref() {
                        if previous == '*' && next == '/' {
                            break;
                        }
                        previous = next;
                    }
                }
                _ => output.push(character),
            }
        } else {
            output.push(character);
        }
    }
    output
}

fn split_c_declarations(text: &str) -> Vec<String> {
    let mut declarations = Vec::new();
    let mut current = String::new();
    let mut brace_depth = 0usize;

    for character in text.chars() {
        current.push(character);
        match character {
            '{' => brace_depth = brace_depth.saturating_add(1),
            '}' => brace_depth = brace_depth.saturating_sub(1),
            ';' if brace_depth == 0 => {
                let declaration = current.trim();
                if !declaration.is_empty() {
                    declarations.push(declaration.to_owned());
                }
                current.clear();
            }
            _ => {}
        }
    }

    let trailing = current.trim();
    if !trailing.is_empty() {
        declarations.push(trailing.to_owned());
    }
    declarations
}

fn parse_c_declaration(source_name: &str, declaration: &str) -> Option<ProjectType> {
    let declaration = declaration.trim().trim_end_matches(';').trim();
    if declaration.is_empty() || declaration.starts_with('#') {
        return None;
    }

    if declaration.contains('{') && declaration.contains('}') {
        if declaration.contains("struct") {
            return parse_c_aggregate(source_name, declaration, "struct");
        }
        if declaration.contains("union") {
            return parse_c_aggregate(source_name, declaration, "union");
        }
        if declaration.contains("enum") {
            return parse_c_enum(source_name, declaration);
        }
    }

    if declaration.starts_with("typedef ") {
        return parse_c_typedef(source_name, declaration);
    }

    parse_c_function_prototype(source_name, declaration)
}

fn parse_c_aggregate(source_name: &str, declaration: &str, keyword: &str) -> Option<ProjectType> {
    let body_start = declaration.find('{')?;
    let body_end = declaration.rfind('}')?;
    let head = declaration[..body_start].trim();
    let body = &declaration[body_start + 1..body_end];
    let tail = declaration[body_end + 1..].trim();

    let name = aggregate_name(head, tail, keyword)?;
    let fields = split_c_declarations(body)
        .into_iter()
        .filter_map(|field| parse_c_field(&field))
        .collect::<Vec<_>>();
    let definition = if keyword == "union" {
        TypeDefinition::Union { fields }
    } else {
        TypeDefinition::Struct { fields }
    };
    Some(ProjectType::with_definition(
        name,
        format!("header:{source_name}"),
        definition,
    ))
}

fn parse_c_enum(source_name: &str, declaration: &str) -> Option<ProjectType> {
    let body_start = declaration.find('{')?;
    let body_end = declaration.rfind('}')?;
    let head = declaration[..body_start].trim();
    let body = &declaration[body_start + 1..body_end];
    let tail = declaration[body_end + 1..].trim();
    let name = aggregate_name(head, tail, "enum")?;
    let variants = parse_c_enum_variants(body);
    Some(ProjectType::with_definition(
        name,
        format!("header:{source_name}"),
        TypeDefinition::Enum { variants },
    ))
}

fn parse_c_typedef(source_name: &str, declaration: &str) -> Option<ProjectType> {
    let body = declaration.strip_prefix("typedef")?.trim();
    if body.contains('(') && body.contains(')') {
        return parse_c_function_prototype(source_name, body);
    }

    let (target, name, array_count) = parse_c_named_type(body)?;
    let definition = if let Some(count) = array_count {
        TypeDefinition::Array {
            element: target,
            count,
        }
    } else if target.ends_with('*') {
        TypeDefinition::Pointer {
            to: target.trim_end_matches('*').trim().to_owned(),
        }
    } else {
        TypeDefinition::Typedef { target }
    };
    Some(ProjectType::with_definition(
        name,
        format!("header:{source_name}"),
        definition,
    ))
}

fn parse_c_function_prototype(source_name: &str, declaration: &str) -> Option<ProjectType> {
    let open = declaration.find('(')?;
    let close = declaration.rfind(')')?;
    if close < open {
        return None;
    }
    let before = declaration[..open].trim();
    if before.contains("if ") || before.contains("while ") || before.contains("for ") {
        return None;
    }
    let (return_type, name, _) = parse_c_named_type(before)?;
    let params_text = declaration[open + 1..close].trim();
    let parameters = parse_c_parameters(params_text);
    Some(ProjectType::with_definition(
        name,
        format!("header:{source_name}"),
        TypeDefinition::Function {
            return_type,
            calling_convention: String::new(),
            parameters,
        },
    ))
}

fn aggregate_name(head: &str, tail: &str, keyword: &str) -> Option<String> {
    let tail_name = tail
        .split_whitespace()
        .next()
        .map(clean_c_identifier)
        .filter(|name| !name.is_empty());
    if tail_name.is_some() {
        return tail_name;
    }

    head.split_whitespace()
        .skip_while(|token| *token != keyword)
        .nth(1)
        .map(clean_c_identifier)
        .filter(|name| !name.is_empty())
}

fn parse_c_field(field: &str) -> Option<TypeField> {
    let field = field.trim().trim_end_matches(';').trim();
    if field.is_empty() || field.starts_with('#') {
        return None;
    }
    let field = field.split(':').next().unwrap_or(field).trim();
    let (type_name, name, array_count) = parse_c_named_type(field)?;
    let type_name = if let Some(count) = array_count {
        format!("{type_name}[{count}]")
    } else {
        type_name
    };
    Some(TypeField {
        name,
        type_name,
        offset: None,
        size: None,
    })
}

fn parse_c_enum_variants(body: &str) -> Vec<EnumVariant> {
    let mut variants = Vec::new();
    let mut next_value = 0i64;
    for raw in body.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let (name, value) = match raw.split_once('=') {
            Some((name, value)) => {
                let parsed = parse_signed_number(value.trim()).unwrap_or(next_value);
                (name.trim(), parsed)
            }
            None => (raw, next_value),
        };
        let name = clean_c_identifier(name);
        if name.is_empty() {
            continue;
        }
        variants.push(EnumVariant { name, value });
        next_value = value.saturating_add(1);
    }
    variants
}

fn parse_c_parameters(text: &str) -> Vec<TypeParameter> {
    if text.is_empty() || text == "void" {
        return Vec::new();
    }

    text.split(',')
        .enumerate()
        .filter_map(|(index, parameter)| {
            let parameter = parameter.trim();
            if parameter == "..." {
                return Some(TypeParameter {
                    name: "varargs".to_owned(),
                    type_name: "...".to_owned(),
                });
            }
            let (type_name, name, _) = parse_c_named_type(parameter).unwrap_or_else(|| {
                (
                    normalize_c_type(parameter),
                    format!("arg{}", index.saturating_add(1)),
                    None,
                )
            });
            Some(TypeParameter { name, type_name })
        })
        .collect()
}

fn parse_c_named_type(text: &str) -> Option<(String, String, Option<u64>)> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }

    let (without_array, array_count) = if let Some(open) = text.rfind('[') {
        let close = text.rfind(']')?;
        if close > open {
            let count = text[open + 1..close].trim().parse::<u64>().ok();
            (text[..open].trim(), count)
        } else {
            (text, None)
        }
    } else {
        (text, None)
    };

    let mut parts = without_array.split_whitespace().collect::<Vec<_>>();
    let mut name = parts.pop()?.trim().to_owned();
    let mut leading_pointer = 0usize;
    while name.starts_with('*') {
        leading_pointer += 1;
        name.remove(0);
    }
    name = clean_c_identifier(&name);
    if name.is_empty() {
        return None;
    }

    let mut type_name = normalize_c_type(&parts.join(" "));
    if leading_pointer > 0 {
        if !type_name.is_empty() {
            type_name.push(' ');
        }
        type_name.push_str(&"*".repeat(leading_pointer));
    }
    type_name = normalize_c_type(&type_name);
    if type_name.is_empty() {
        return None;
    }

    Some((type_name, name, array_count))
}

fn normalize_c_type(text: &str) -> String {
    text.replace('\t', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn clean_c_identifier(text: &str) -> String {
    text.trim()
        .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .to_owned()
}

fn parse_signed_number(text: &str) -> Option<i64> {
    let text = text.trim();
    let negative = text.starts_with('-');
    let digits = text.trim_start_matches('-').trim_start_matches('+');
    let parsed = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        digits.parse::<i64>().ok()?
    };
    Some(if negative { -parsed } else { parsed })
}

fn type_to_c_declaration(type_item: &ProjectType) -> Option<String> {
    let definition = type_item.definition.as_ref()?;
    let name = &type_item.name;
    match definition {
        TypeDefinition::Integer { signed, bits } => {
            let keyword = match (*signed, *bits) {
                (true, 8) => "signed char",
                (false, 8) => "unsigned char",
                (true, 16) => "short",
                (false, 16) => "unsigned short",
                (true, 32) => "int",
                (false, 32) => "unsigned int",
                (true, 64) => "__int64",
                (false, 64) => "unsigned __int64",
                _ => return Some(format!("/* unsupported integer width: {name} */")),
            };
            Some(format!("typedef {keyword} {name};"))
        }
        TypeDefinition::Pointer { to } => Some(format!("typedef {to} *{name};")),
        TypeDefinition::Array { element, count } => {
            Some(format!("typedef {element} {name}[{count}];"))
        }
        TypeDefinition::Struct { fields } => Some(format_c_aggregate("struct", name, fields)),
        TypeDefinition::Union { fields } => Some(format_c_aggregate("union", name, fields)),
        TypeDefinition::Enum { variants } => Some(format_c_enum(name, variants)),
        TypeDefinition::Typedef { target } => Some(format!("typedef {target} {name};")),
        TypeDefinition::Function {
            return_type,
            calling_convention,
            parameters,
        } => {
            let params = if parameters.is_empty() {
                "void".to_owned()
            } else {
                parameters
                    .iter()
                    .map(|parameter| format!("{} {}", parameter.type_name, parameter.name))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let convention = if calling_convention.is_empty() {
                String::new()
            } else {
                format!("{calling_convention} ")
            };
            Some(format!("{return_type} {convention}{name}({params});"))
        }
        TypeDefinition::Opaque => Some(format!("typedef struct {name} {name};")),
    }
}

fn format_c_aggregate(keyword: &str, name: &str, fields: &[TypeField]) -> String {
    let mut output = format!("typedef {keyword} {name} {{\n");
    if fields.is_empty() {
        output.push_str("    unsigned char _opaque;\n");
    } else {
        for field in fields {
            output.push_str(&format!("    {} {};\n", field.type_name, field.name));
        }
    }
    output.push_str(&format!("}} {name};"));
    output
}

fn format_c_enum(name: &str, variants: &[EnumVariant]) -> String {
    let mut output = format!("typedef enum {name} {{\n");
    for variant in variants {
        output.push_str(&format!("    {} = {},\n", variant.name, variant.value));
    }
    output.push_str(&format!("}} {name};"));
    output
}

pub fn format_address(value: Option<u64>, prefix: &str) -> String {
    match value {
        Some(value) => format!("{prefix} {value:08X}"),
        None => format!("{prefix} --------"),
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn normalize_user_text(text: String) -> Option<String> {
    let text = text.trim().to_owned();
    (!text.is_empty()).then_some(text)
}

fn choose<'a>(
    before: &'a Option<String>,
    after: &'a Option<String>,
    forward: bool,
) -> &'a Option<String> {
    if forward {
        after
    } else {
        before
    }
}

fn set_optional_string(map: &mut BTreeMap<u64, String>, address: u64, value: &Option<String>) {
    match value {
        Some(value) => {
            map.insert(address, value.clone());
        }
        None => {
            map.remove(&address);
        }
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

    #[test]
    fn project_load_raw_sets_entry_point_context() {
        let selection = FileSelection::new(PathBuf::from(r"C:\samples\raw.bin"), 0x80);
        let image = RawImage::new(selection, 0x1800_00000, 0x1800_00020, RawArch::X64);
        let mut project = ProjectState::default();

        project.load_raw(image);

        assert_eq!(project.analysis_state(), &AnalysisState::RawLoaded);
        assert_eq!(project.current_address(), Some(0x1800_00020));
        assert_eq!(project.current_rva(), Some(0x20));
        assert_eq!(project.current_file_offset(), Some(0x20));
        assert_eq!(project.current_function(), Some("raw_entry"));
    }

    #[test]
    fn navigation_history_supports_back_and_forward() {
        let image = sample_pe_image();
        let mut project = ProjectState::default();

        project.load_pe(image);
        assert!(!project.can_go_back());
        assert!(!project.can_go_forward());

        project.jump_to(0x1400_01020, Some("first".to_owned()));
        project.jump_to(0x1400_01040, Some("second".to_owned()));

        assert!(project.can_go_back());
        assert!(!project.can_go_forward());
        assert!(project.go_back());
        assert_eq!(project.current_address(), Some(0x1400_01020));
        assert_eq!(project.current_function(), Some("first"));
        assert!(project.can_go_forward());

        assert!(project.go_back());
        assert_eq!(project.current_address(), Some(0x1400_01010));
        assert_eq!(project.current_function(), Some("入口点"));

        assert!(project.go_forward());
        assert_eq!(project.current_address(), Some(0x1400_01020));
        assert_eq!(project.current_file_offset(), Some(0x220));
    }

    #[test]
    fn annotation_commands_support_undo_and_redo() {
        let mut project = ProjectState::default();
        let address = 0x1400_01000;

        project.rename_address(address, "decrypt_config");
        project.set_address_comment(address, "reads encrypted blob");
        project.toggle_bookmark(address);
        project.set_manual_definition(address, ManualDefinitionKind::Code);

        assert_eq!(project.name_for(address), Some("decrypt_config"));
        assert_eq!(
            project.address_comment(address),
            Some("reads encrypted blob")
        );
        assert!(project.is_bookmarked(address));
        assert_eq!(
            project.manual_definition(address),
            Some(ManualDefinitionKind::Code)
        );

        assert!(project.undo());
        assert_eq!(project.manual_definition(address), None);
        assert!(project.undo());
        assert!(!project.is_bookmarked(address));
        assert!(project.redo());
        assert!(project.is_bookmarked(address));
    }

    #[test]
    fn project_document_round_trips_user_annotations() {
        let input = ProjectInput {
            path: r"C:\samples\demo.exe".to_owned(),
            size_bytes: 42,
            sha256: sha256_hex(b"demo"),
            kind: ProjectInputKind::Pe,
        };
        let annotations = UserAnnotations {
            names: vec![UserName {
                address: 0x1400_01000,
                name: "main".to_owned(),
            }],
            comments: vec![UserComment {
                address: 0x1400_01005,
                text: "interesting branch".to_owned(),
            }],
            function_comments: vec![FunctionComment {
                function_start: 0x1400_01000,
                text: "entry function".to_owned(),
            }],
            bookmarks: vec![Bookmark {
                address: 0x1400_01010,
            }],
            manual_definitions: vec![ManualDefinition {
                address: 0x1400_01020,
                kind: ManualDefinitionKind::Data,
            }],
        };
        let document = ProjectDocument::new(
            "test",
            input,
            vec![ProjectFunction {
                start_va: 0x1400_01000,
                name: "入口点".to_owned(),
                size: 0x20,
                instruction_count: 4,
            }],
            Some(ProjectDebugInfo {
                pe_pdb_path: Some(r"C:\symbols\demo.pdb".to_owned()),
                pe_pdb_guid: Some("00112233-4455-6677-8899-aabbccddeeff".to_owned()),
                pe_pdb_age: Some(2),
                loaded_pdb_path: Some(r"C:\symbols\demo.pdb".to_owned()),
                loaded_pdb_guid: Some("00112233-4455-6677-8899-aabbccddeeff".to_owned()),
                loaded_pdb_age: Some(2),
                matched: Some(true),
            }),
            vec![ProjectSymbol {
                address: Some(0x1400_01000),
                rva: Some(0x1000),
                name: "main".to_owned(),
                original_name: "?main@@YAHXZ".to_owned(),
                kind: "PDB 函数".to_owned(),
                source: "public".to_owned(),
            }],
            vec![ProjectType {
                name: "CONFIG".to_owned(),
                kind: "struct".to_owned(),
                source: "user".to_owned(),
                definition: Some(TypeDefinition::Struct {
                    fields: vec![TypeField {
                        name: "flags".to_owned(),
                        type_name: "DWORD".to_owned(),
                        offset: Some(0),
                        size: Some(4),
                    }],
                }),
            }],
            vec![ProjectTypeApplication {
                target: ProjectTypeTarget::Address(0x1400_02000),
                type_name: "CONFIG".to_owned(),
            }],
            vec![ProjectSourceFile {
                path: r"C:\src\demo.cpp".to_owned(),
            }],
            annotations,
        );
        let path = std::env::temp_dir().join(format!(
            "fyida_project_roundtrip_{}.fyida.json",
            std::process::id()
        ));

        document.save_to_path(&path).expect("save project");
        let loaded = ProjectDocument::load_from_path(&path).expect("load project");
        let _ = std::fs::remove_file(&path);

        assert_eq!(loaded.schema_version, PROJECT_SCHEMA_VERSION);
        assert_eq!(loaded.input.sha256, sha256_hex(b"demo"));
        assert_eq!(loaded.functions[0].start_va, 0x1400_01000);
        assert_eq!(loaded.debug_info.as_ref().unwrap().pe_pdb_age, Some(2));
        assert_eq!(loaded.symbols[0].original_name, "?main@@YAHXZ");
        assert_eq!(loaded.types[0].name, "CONFIG");
        assert_eq!(
            loaded.type_applications[0].target,
            ProjectTypeTarget::Address(0x1400_02000)
        );
        assert_eq!(loaded.source_files[0].path, r"C:\src\demo.cpp");
        assert_eq!(loaded.annotations.names[0].name, "main");
        assert_eq!(
            loaded.annotations.manual_definitions[0].kind,
            ManualDefinitionKind::Data
        );
    }

    #[test]
    fn type_library_tracks_applications() {
        let mut project = ProjectState::default();
        assert!(project.project_type("DWORD").is_some());

        project.upsert_project_type(ProjectType::with_definition(
            "CONFIG",
            "user",
            TypeDefinition::Struct {
                fields: vec![TypeField {
                    name: "size".to_owned(),
                    type_name: "DWORD".to_owned(),
                    offset: None,
                    size: None,
                }],
            },
        ));
        project.apply_type_to_target(ProjectTypeTarget::Function(0x1400_01000), "CONFIG *");

        assert_eq!(
            project.applied_function_type(0x1400_01000),
            Some("CONFIG *")
        );
        assert!(project
            .project_type("CONFIG")
            .unwrap()
            .display_signature()
            .contains("struct CONFIG"));
    }

    #[test]
    fn imports_and_exports_c_header_types() {
        let header = r#"
            typedef unsigned long DWORD;
            typedef struct CONFIG {
                DWORD flags;
                const char *name;
                unsigned char key[16];
            } CONFIG;
            typedef enum MODE { MODE_A = 1, MODE_B } MODE;
            int parse_config(CONFIG *config, const char *path);
        "#;

        let types = import_c_header_types("config.h", header);
        assert!(types.iter().any(|type_item| type_item.name == "DWORD"));
        let config = types
            .iter()
            .find(|type_item| type_item.name == "CONFIG")
            .expect("CONFIG struct");
        match config.definition.as_ref().expect("definition") {
            TypeDefinition::Struct { fields } => {
                assert_eq!(fields.len(), 3);
                assert_eq!(fields[2].type_name, "unsigned char[16]");
            }
            other => panic!("unexpected definition: {other:?}"),
        }
        let exported = export_c_header_types(&types);
        assert!(exported.contains("typedef struct CONFIG"));
        assert!(exported.contains("int parse_config"));
        assert!(exported.contains("MODE_B = 2"));
    }
}
