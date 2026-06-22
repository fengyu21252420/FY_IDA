use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use fyida_core::{
    FileSelection, PeImage, PeKind, RawImage, PE_DIRECTORY_BASERELOC, PE_DIRECTORY_DEBUG,
    PE_DIRECTORY_EXPORT, PE_DIRECTORY_IMPORT,
};
use fyida_disasm::{
    disassemble_entry_point, disassemble_raw_entry_point, disassemble_x64, DecodedInstruction,
    InstructionFlow,
};
use pdb::FallibleIterator;
use serde::{Deserialize, Serialize};

const MAX_FUNCTIONS: usize = 256;
const MAX_FUNCTION_BYTES: usize = 4096;
const MAX_INSTRUCTIONS_PER_FUNCTION: usize = 512;
const MAX_IMPORT_DESCRIPTORS: usize = 256;
const MAX_IMPORT_THUNKS_PER_DLL: usize = 4096;
const MAX_EXPORTS: usize = 4096;
const MAX_RELOCATIONS: usize = 16384;
const MAX_STRINGS: usize = 4096;
const MAX_PDB_SYMBOLS: usize = 8192;
const MAX_PDB_TYPES: usize = 2048;
const MAX_PDB_SOURCES: usize = 1024;
const MAX_DEBUG_DIRECTORY_ENTRIES: usize = 128;
const MAX_RUNTIME_SIGNATURES: usize = 2048;
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
    pub function_cfgs: Vec<FunctionCfg>,
    pub call_graph: CallGraph,
    pub pseudocode_functions: Vec<PseudocodeFunction>,
    pub runtime_signatures: Vec<RuntimeSignature>,
    pub pe_pdb_records: Vec<PePdbRecord>,
    pub loaded_pdb: Option<LoadedPdbInfo>,
    pub pdb_symbols: Vec<PdbSymbol>,
    pub pdb_types: Vec<PdbTypeSummary>,
    pub pdb_sources: Vec<PdbSourceFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSummary {
    pub start_va: u64,
    pub name: String,
    pub size: u64,
    pub instruction_count: usize,
    pub call_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionCfg {
    pub function_start: u64,
    pub blocks: Vec<BasicBlock>,
    pub edges: Vec<CfgEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlock {
    pub start_va: u64,
    pub end_va: u64,
    pub instruction_count: usize,
    pub call_count: usize,
    pub instructions: Vec<BlockInstruction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockInstruction {
    pub address: u64,
    pub bytes: String,
    pub mnemonic: String,
    pub operands: String,
    pub flow: InstructionFlow,
    pub branch_target: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CfgEdgeKind {
    ConditionalTrue,
    ConditionalFalse,
    Unconditional,
    Fallthrough,
}

impl CfgEdgeKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::ConditionalTrue => "条件真分支",
            Self::ConditionalFalse => "条件假分支",
            Self::Unconditional => "无条件跳转",
            Self::Fallthrough => "顺序流",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgEdge {
    pub from_va: u64,
    pub to_va: u64,
    pub kind: CfgEdgeKind,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallGraph {
    pub nodes: Vec<CallGraphNode>,
    pub edges: Vec<CallGraphEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallGraphNode {
    pub start_va: u64,
    pub name: String,
    pub is_external: bool,
    pub call_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallGraphEdge {
    pub caller_va: u64,
    pub callee_va: u64,
    pub callsite_va: u64,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PseudocodeFunction {
    pub function_start: u64,
    pub name: String,
    pub lines: Vec<PseudocodeLine>,
    pub ir: Vec<IrInstruction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PseudocodeLine {
    pub address: Option<u64>,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrInstruction {
    pub address: u64,
    pub op: String,
    pub args: Vec<String>,
    pub comment: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuntimeSignatureKind {
    CrtStartup,
    SecurityCookie,
    ExceptionHandling,
    MemoryRoutine,
    RuntimeImport,
    Pattern,
    UserSignature,
}

impl RuntimeSignatureKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::CrtStartup => "CRT startup",
            Self::SecurityCookie => "security cookie",
            Self::ExceptionHandling => "exception handling",
            Self::MemoryRoutine => "memory routine",
            Self::RuntimeImport => "runtime import",
            Self::Pattern => "runtime pattern",
            Self::UserSignature => "user signature",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuntimeSignatureTarget {
    Function,
    Import,
    Pattern,
}

impl RuntimeSignatureTarget {
    pub fn label(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Import => "import",
            Self::Pattern => "pattern",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSignature {
    pub address: u64,
    pub name: String,
    pub kind: RuntimeSignatureKind,
    pub target: RuntimeSignatureTarget,
    pub library: String,
    pub evidence: String,
    pub confidence: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureLibrary {
    pub name: String,
    pub version: Option<String>,
    #[serde(default, alias = "signatures")]
    pub rules: Vec<SignatureRule>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureRule {
    pub id: Option<String>,
    pub name: String,
    pub kind: Option<String>,
    pub library: Option<String>,
    pub target: Option<String>,
    pub evidence: Option<String>,
    pub confidence: Option<u8>,
    #[serde(default)]
    pub import_name_contains: Vec<String>,
    #[serde(default)]
    pub import_dll_contains: Vec<String>,
    #[serde(default)]
    pub function_name_contains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PePdbFormat {
    Rsds,
    Nb10,
    Unknown(String),
}

impl PePdbFormat {
    pub fn label(&self) -> &str {
        match self {
            Self::Rsds => "RSDS",
            Self::Nb10 => "NB10",
            Self::Unknown(value) => value.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PePdbRecord {
    pub format: PePdbFormat,
    pub path: String,
    pub guid: Option<String>,
    pub age: Option<u32>,
    pub signature: Option<u32>,
    pub debug_rva: u32,
    pub debug_file_offset: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedPdbInfo {
    pub path: String,
    pub guid: Option<String>,
    pub age: u32,
    pub signature: u32,
    pub matched_pe: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PdbSymbolKind {
    Function,
    PublicCode,
    Data,
    PublicData,
    UserDefinedType,
    ProcedureReference,
    DataReference,
}

impl PdbSymbolKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Function => "PDB 函数",
            Self::PublicCode => "PDB Public Code",
            Self::Data => "PDB 数据",
            Self::PublicData => "PDB Public Data",
            Self::UserDefinedType => "PDB UDT",
            Self::ProcedureReference => "PDB 过程引用",
            Self::DataReference => "PDB 数据引用",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbSymbol {
    pub address: Option<u64>,
    pub rva: Option<u32>,
    pub name: String,
    pub demangled_name: Option<String>,
    pub kind: PdbSymbolKind,
    pub source: String,
}

impl PdbSymbol {
    pub fn display_name(&self) -> &str {
        self.demangled_name.as_deref().unwrap_or(&self.name)
    }

    pub fn is_function_like(&self) -> bool {
        matches!(
            self.kind,
            PdbSymbolKind::Function | PdbSymbolKind::PublicCode | PdbSymbolKind::ProcedureReference
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbTypeSummary {
    pub name: String,
    pub kind: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbSourceFile {
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbLoadSummary {
    pub loaded: LoadedPdbInfo,
    pub symbol_count: usize,
    pub type_count: usize,
    pub source_count: usize,
}

struct DecodedFunctionAnalysis {
    function: FunctionSummary,
    cfg: FunctionCfg,
    xrefs: Vec<XrefSummary>,
    calls: Vec<CallGraphEdge>,
    discovered_call_targets: Vec<u64>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
        pe_pdb_records: parse_pe_pdb_records(image, bytes),
        ..StaticAnalysis::default()
    };

    let discovery = discover_functions_and_xrefs(image, bytes);
    analysis.functions = discovery.functions;
    analysis.xrefs = discovery.xrefs;
    analysis.function_cfgs = discovery.function_cfgs;
    analysis.call_graph = discovery.call_graph;
    analysis.pseudocode_functions = build_pseudocode_functions(
        &analysis.functions,
        &analysis.function_cfgs,
        &analysis.call_graph,
    );
    analysis.runtime_signatures = build_runtime_signatures(&analysis);
    analysis
}

pub fn analyze_raw(image: &RawImage, bytes: &[u8]) -> StaticAnalysis {
    let discovery = discover_raw_functions_and_xrefs(image, bytes);
    let mut analysis = StaticAnalysis {
        functions: discovery.functions,
        strings: scan_raw_strings(image, bytes),
        imports: Vec::new(),
        exports: Vec::new(),
        relocations: Vec::new(),
        xrefs: discovery.xrefs,
        function_cfgs: discovery.function_cfgs,
        call_graph: discovery.call_graph,
        ..StaticAnalysis::default()
    };
    analysis.pseudocode_functions = build_pseudocode_functions(
        &analysis.functions,
        &analysis.function_cfgs,
        &analysis.call_graph,
    );
    analysis.runtime_signatures = build_runtime_signatures(&analysis);
    analysis
}

pub fn static_analysis_log_lines(analysis: &StaticAnalysis) -> Vec<String> {
    let mut lines = vec![
        format!("函数发现：{} 个函数入口。", analysis.functions.len()),
        format!("字符串提取：{} 条。", analysis.strings.len()),
        format!("导入表解析：{} 个导入符号。", analysis.imports.len()),
        format!("导出表解析：{} 个导出符号。", analysis.exports.len()),
        format!("重定位解析：{} 条。", analysis.relocations.len()),
        format!("代码交叉引用：{} 条。", analysis.xrefs.len()),
        format!("CFG 生成：{} 个函数图。", analysis.function_cfgs.len()),
        format!(
            "伪 C/IR 生成：{} 个函数。",
            analysis.pseudocode_functions.len()
        ),
        format!(
            "Runtime signatures: {} matches",
            analysis.runtime_signatures.len()
        ),
        format!(
            "调用图：{} 个节点 / {} 条边。",
            analysis.call_graph.nodes.len(),
            analysis.call_graph.edges.len()
        ),
    ];

    lines.push(format!(
        "PDB 线索：{} 条 CodeView / {} 个符号 / {} 个类型。",
        analysis.pe_pdb_records.len(),
        analysis.pdb_symbols.len(),
        analysis.pdb_types.len()
    ));
    if let Some(record) = analysis.pe_pdb_records.first() {
        lines.push(format!(
            "PE Debug Directory PDB：{} age {} {}",
            record.path,
            record.age.unwrap_or(0),
            record.guid.as_deref().unwrap_or(record.format.label())
        ));
    }
    if let Some(loaded) = &analysis.loaded_pdb {
        lines.push(format!(
            "外部 PDB 已加载：{} / GUID {} / age {} / 匹配 {}",
            loaded.path,
            loaded.guid.as_deref().unwrap_or("-"),
            loaded.age,
            match loaded.matched_pe {
                Some(true) => "是",
                Some(false) => "否",
                None => "未知",
            }
        ));
    }

    lines
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

pub fn raw_entry_disassembly(image: &RawImage, bytes: &[u8]) -> DisassemblyBuild {
    match disassemble_raw_entry_point(image, bytes) {
        Ok(instructions) if !instructions.is_empty() => instructions_to_disassembly_build(
            instructions,
            "x64 Raw 反汇编完成",
            "无效 x64 指令占位，分析继续",
        ),
        Ok(_) => DisassemblyBuild {
            rows: vec![DisassemblyRow {
                address: image.entry_address,
                bytes: "--".to_owned(),
                mnemonic: "提示".to_owned(),
                operands: format!("FO 0x{:08X}", image.entry_offset().unwrap_or(0)),
                comment: "Raw 入口点附近没有可显示的 x64 指令。".to_owned(),
            }],
            log_lines: vec!["x64 Raw 反汇编未产生指令。".to_owned()],
        },
        Err(error) => {
            let message = error.to_string();
            DisassemblyBuild {
                rows: vec![DisassemblyRow {
                    address: image.entry_address,
                    bytes: "--".to_owned(),
                    mnemonic: "提示".to_owned(),
                    operands: format!("FO 0x{:08X}", image.entry_offset().unwrap_or(0)),
                    comment: message.clone(),
                }],
                log_lines: vec![format!("Raw 反汇编提示：{message}")],
            }
        }
    }
}

pub fn startup_log_lines() -> Vec<String> {
    vec![
        "FY_IDA GUI 已启动。".to_owned(),
        "当前版本：v0.22.0-alpha.1，Python 标注动作写入、headless 项目保存、Python 报告辅助 API 示例、递归插件扫描、结构化 Python 自动化报告、headless 搜索报告、伪代码/IR headless 导出、伪代码/IR 搜索、正式 headless analyze 入口、本地签名库、Runtime 识别、运行库过滤和基础 x64 伪 C/IR 已接入。".to_owned(),
        "可打开 Windows x64 PE 或 Raw Binary，并显示入口点指令、函数、字符串、基础引用和图数据。"
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

pub fn raw_loaded_log_lines(image: &RawImage) -> Vec<String> {
    vec![
        format!("Raw Binary 加载完成：{}", image.file().path().display()),
        format!("文件大小：{}", image.file().formatted_size()),
        format!("Arch：{}", image.arch.label()),
        format!("Base：0x{:016X}", image.base_address),
        format!(
            "Entry：VA 0x{:016X} / FO 0x{:08X}",
            image.entry_address,
            image.entry_offset().unwrap_or(0)
        ),
        format!("End：0x{:016X}", image.end_address()),
    ]
}

pub fn file_error_log_lines(file: &FileSelection, message: &str) -> Vec<String> {
    vec![
        format!("打开文件失败：{}", file.path().display()),
        format!("错误：{message}"),
    ]
}

pub fn pdb_candidate_paths(image: &PeImage, analysis: &StaticAnalysis) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for record in &analysis.pe_pdb_records {
        if record.path.trim().is_empty() {
            continue;
        }

        let raw_path = PathBuf::from(&record.path);
        paths.push(raw_path.clone());
        if let Some(file_name) = raw_path.file_name() {
            if let Some(parent) = image.file().path().parent() {
                paths.push(parent.join(file_name));
            }
        }
    }

    let mut seen = BTreeSet::new();
    paths
        .into_iter()
        .filter(|path| seen.insert(path.display().to_string().to_lowercase()))
        .collect()
}

pub fn apply_pdb_file(
    image: &PeImage,
    analysis: &mut StaticAnalysis,
    path: impl AsRef<Path>,
) -> Result<PdbLoadSummary, String> {
    let path = path.as_ref();
    let file = std::fs::File::open(path)
        .map_err(|source| format!("无法打开 PDB 文件 {}：{source}", path.display()))?;
    let mut pdb =
        pdb::PDB::open(file).map_err(|source| format!("PDB 格式无效或不受支持：{source}"))?;
    let pdb_info = pdb
        .pdb_information()
        .map_err(|source| format!("读取 PDB 信息流失败：{source}"))?;
    let loaded = LoadedPdbInfo {
        path: path.display().to_string(),
        guid: Some(pdb_info.guid.to_string()),
        age: pdb_info.age,
        signature: pdb_info.signature,
        matched_pe: match analysis.pe_pdb_records.first() {
            Some(record) => Some(pdb_matches_pe(
                record,
                &pdb_info.guid.to_string(),
                pdb_info.age,
            )),
            None => None,
        },
    };

    let address_map = pdb
        .address_map()
        .map_err(|source| format!("建立 PDB 地址映射失败：{source}"))?;
    let mut symbols = collect_global_pdb_symbols(&mut pdb, image, &address_map)?;
    let (mut module_symbols, module_sources) =
        collect_module_pdb_symbols(&mut pdb, image, &address_map);
    symbols.append(&mut module_symbols);
    dedup_pdb_symbols(&mut symbols);
    let types = collect_pdb_type_summaries(&symbols);
    let sources = module_sources;

    analysis.loaded_pdb = Some(loaded.clone());
    analysis.pdb_symbols = symbols;
    analysis.pdb_types = types;
    analysis.pdb_sources = sources;
    overlay_pdb_function_names(image, analysis);
    refresh_pseudocode(analysis);
    refresh_runtime_signatures(analysis);

    Ok(PdbLoadSummary {
        loaded,
        symbol_count: analysis.pdb_symbols.len(),
        type_count: analysis.pdb_types.len(),
        source_count: analysis.pdb_sources.len(),
    })
}

pub fn apply_pdb_snapshot(
    analysis: &mut StaticAnalysis,
    loaded: Option<LoadedPdbInfo>,
    symbols: Vec<PdbSymbol>,
    types: Vec<PdbTypeSummary>,
    sources: Vec<PdbSourceFile>,
) {
    analysis.loaded_pdb = loaded;
    analysis.pdb_symbols = symbols;
    analysis.pdb_types = types;
    analysis.pdb_sources = sources;
    overlay_pdb_names_only(analysis);
    refresh_pseudocode(analysis);
    refresh_runtime_signatures(analysis);
}

pub fn load_signature_library_file(path: impl AsRef<Path>) -> Result<SignatureLibrary, String> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path)
        .map_err(|source| format!("无法读取签名库 {}：{source}", path.display()))?;
    let library: SignatureLibrary = serde_json::from_str(&text)
        .map_err(|source| format!("签名库 JSON 格式无效 {}：{source}", path.display()))?;
    validate_signature_library(&library)?;
    Ok(library)
}

pub fn apply_signature_library(analysis: &mut StaticAnalysis, library: &SignatureLibrary) -> usize {
    let mut matches = build_signature_library_matches(analysis, library);
    let count = matches.len();
    analysis.runtime_signatures.append(&mut matches);
    sort_and_dedup_runtime_signatures(&mut analysis.runtime_signatures);
    count
}

#[derive(Debug, Clone, Default)]
struct DiscoveryResult {
    functions: Vec<FunctionSummary>,
    xrefs: Vec<XrefSummary>,
    function_cfgs: Vec<FunctionCfg>,
    call_graph: CallGraph,
}

fn discover_functions_and_xrefs(image: &PeImage, bytes: &[u8]) -> DiscoveryResult {
    if image.nt_headers.file_header.machine != 0x8664
        || image.nt_headers.optional_header.kind != PeKind::Pe32Plus
    {
        return DiscoveryResult::default();
    }

    let mut worklist = VecDeque::from([image.entry_point_va()]);
    let mut discovered = HashSet::from([image.entry_point_va()]);
    let mut processed = HashSet::new();
    let mut functions = Vec::new();
    let mut xrefs = Vec::new();
    let mut function_cfgs = Vec::new();
    let mut call_edges = Vec::new();

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

        let name = if start_va == image.entry_point_va() {
            "入口点".to_owned()
        } else {
            format!("sub_{start_va:016X}")
        };

        let decoded = analyze_decoded_function(start_va, name, &instructions, |target| {
            image.is_executable_va(target)
        });
        for target in &decoded.discovered_call_targets {
            if discovered.len() < MAX_FUNCTIONS && discovered.insert(*target) {
                worklist.push_back(*target);
            }
        }

        functions.push(decoded.function);
        function_cfgs.push(decoded.cfg);
        xrefs.extend(decoded.xrefs);
        call_edges.extend(decoded.calls);
    }

    functions.sort_by_key(|function| function.start_va);
    function_cfgs.sort_by_key(|cfg| cfg.function_start);
    dedup_xrefs(&mut xrefs);
    let call_graph = build_call_graph(&functions, call_edges);

    DiscoveryResult {
        functions,
        xrefs,
        function_cfgs,
        call_graph,
    }
}

fn discover_raw_functions_and_xrefs(image: &RawImage, bytes: &[u8]) -> DiscoveryResult {
    let mut worklist = VecDeque::from([image.entry_address]);
    let mut discovered = HashSet::from([image.entry_address]);
    let mut processed = HashSet::new();
    let mut functions = Vec::new();
    let mut xrefs = Vec::new();
    let mut function_cfgs = Vec::new();
    let mut call_edges = Vec::new();

    while let Some(start_va) = worklist.pop_front() {
        if processed.contains(&start_va) || !image.contains_va(start_va) {
            continue;
        }
        processed.insert(start_va);

        let Some(function_bytes) = bytes_from_raw_va(image, bytes, start_va, MAX_FUNCTION_BYTES)
        else {
            continue;
        };
        let instructions = disassemble_x64(start_va, function_bytes, MAX_INSTRUCTIONS_PER_FUNCTION);
        if instructions.is_empty() {
            continue;
        }

        let name = if start_va == image.entry_address {
            "raw_entry".to_owned()
        } else {
            format!("sub_{start_va:016X}")
        };
        let decoded = analyze_decoded_function(start_va, name, &instructions, |target| {
            image.contains_va(target)
        });
        for target in &decoded.discovered_call_targets {
            if discovered.len() < MAX_FUNCTIONS && discovered.insert(*target) {
                worklist.push_back(*target);
            }
        }

        functions.push(decoded.function);
        function_cfgs.push(decoded.cfg);
        xrefs.extend(decoded.xrefs);
        call_edges.extend(decoded.calls);
    }

    functions.sort_by_key(|function| function.start_va);
    function_cfgs.sort_by_key(|cfg| cfg.function_start);
    dedup_xrefs(&mut xrefs);
    let call_graph = build_call_graph(&functions, call_edges);

    DiscoveryResult {
        functions,
        xrefs,
        function_cfgs,
        call_graph,
    }
}

fn analyze_decoded_function(
    start_va: u64,
    name: String,
    instructions: &[DecodedInstruction],
    target_allowed: impl Fn(u64) -> bool,
) -> DecodedFunctionAnalysis {
    let mut truncated = Vec::new();
    for instruction in instructions {
        truncated.push(instruction.clone());
        if instruction.flow == InstructionFlow::Return {
            break;
        }
    }

    let mut last_end = start_va;
    let mut call_count = 0usize;
    let mut xrefs = Vec::new();
    let mut calls = Vec::new();
    let mut discovered_call_targets = Vec::new();

    for instruction in &truncated {
        last_end = last_end.max(instruction_end(instruction));

        if let Some(target) = instruction.near_branch_target {
            let kind = match instruction.flow {
                InstructionFlow::DirectCall => Some(XrefKind::CodeCall),
                InstructionFlow::UnconditionalBranch | InstructionFlow::ConditionalBranch => {
                    Some(XrefKind::CodeJump)
                }
                _ => None,
            };

            if let Some(kind) = kind {
                xrefs.push(XrefSummary {
                    from_va: instruction.address,
                    to_va: target,
                    kind,
                    label: format!("{} -> 0x{target:016X}", kind.label()),
                });
            }

            if instruction.flow == InstructionFlow::DirectCall && target_allowed(target) {
                call_count += 1;
                discovered_call_targets.push(target);
                calls.push(CallGraphEdge {
                    caller_va: start_va,
                    callee_va: target,
                    callsite_va: instruction.address,
                    label: "direct call".to_owned(),
                });
            }
        }
    }

    let cfg = build_function_cfg(start_va, &truncated);
    let function = FunctionSummary {
        start_va,
        name,
        size: last_end.saturating_sub(start_va),
        instruction_count: truncated.len(),
        call_count,
    };

    DecodedFunctionAnalysis {
        function,
        cfg,
        xrefs,
        calls,
        discovered_call_targets,
    }
}

fn build_function_cfg(function_start: u64, instructions: &[DecodedInstruction]) -> FunctionCfg {
    if instructions.is_empty() {
        return FunctionCfg {
            function_start,
            blocks: Vec::new(),
            edges: Vec::new(),
        };
    }

    let instruction_addresses = instructions
        .iter()
        .map(|instruction| instruction.address)
        .collect::<BTreeSet<_>>();
    let function_end = instructions
        .iter()
        .map(instruction_end)
        .max()
        .unwrap_or(function_start);
    let mut leaders = BTreeSet::from([function_start]);

    for instruction in instructions {
        let next = instruction_end(instruction);
        if let Some(target) = instruction.near_branch_target {
            if target >= function_start
                && target < function_end
                && instruction_addresses.contains(&target)
            {
                leaders.insert(target);
            }
        }

        if matches!(
            instruction.flow,
            InstructionFlow::ConditionalBranch | InstructionFlow::UnconditionalBranch
        ) && instruction_addresses.contains(&next)
        {
            leaders.insert(next);
        }
    }

    let mut blocks = Vec::new();
    let mut current: Vec<DecodedInstruction> = Vec::new();
    for instruction in instructions {
        if leaders.contains(&instruction.address) && !current.is_empty() {
            blocks.push(decoded_block(&current));
            current.clear();
        }
        current.push(instruction.clone());
    }
    if !current.is_empty() {
        blocks.push(decoded_block(&current));
    }

    let block_starts = blocks
        .iter()
        .map(|block| block.start_va)
        .collect::<BTreeSet<_>>();
    let mut edges = Vec::new();
    let mut edge_keys = HashSet::new();
    for (index, block) in blocks.iter().enumerate() {
        let Some(last) = block.instructions.last() else {
            continue;
        };
        let next_block = blocks.get(index + 1).map(|next| next.start_va);

        match last.flow {
            InstructionFlow::ConditionalBranch => {
                if let Some(target) = last
                    .branch_target
                    .filter(|target| block_starts.contains(target))
                {
                    push_cfg_edge(
                        &mut edges,
                        &mut edge_keys,
                        block.start_va,
                        target,
                        CfgEdgeKind::ConditionalTrue,
                    );
                }
                if let Some(target) = next_block {
                    push_cfg_edge(
                        &mut edges,
                        &mut edge_keys,
                        block.start_va,
                        target,
                        CfgEdgeKind::ConditionalFalse,
                    );
                }
            }
            InstructionFlow::UnconditionalBranch => {
                if let Some(target) = last
                    .branch_target
                    .filter(|target| block_starts.contains(target))
                {
                    push_cfg_edge(
                        &mut edges,
                        &mut edge_keys,
                        block.start_va,
                        target,
                        CfgEdgeKind::Unconditional,
                    );
                }
            }
            InstructionFlow::Return => {}
            _ => {
                if let Some(target) = next_block {
                    push_cfg_edge(
                        &mut edges,
                        &mut edge_keys,
                        block.start_va,
                        target,
                        CfgEdgeKind::Fallthrough,
                    );
                }
            }
        }
    }

    FunctionCfg {
        function_start,
        blocks,
        edges,
    }
}

fn decoded_block(instructions: &[DecodedInstruction]) -> BasicBlock {
    let start_va = instructions
        .first()
        .map(|instruction| instruction.address)
        .unwrap_or(0);
    let end_va = instructions.last().map(instruction_end).unwrap_or(start_va);
    let call_count = instructions
        .iter()
        .filter(|instruction| instruction.flow == InstructionFlow::DirectCall)
        .count();
    let block_instructions = instructions
        .iter()
        .map(|instruction| BlockInstruction {
            address: instruction.address,
            bytes: instruction.bytes_text(),
            mnemonic: instruction.mnemonic.clone(),
            operands: instruction.operands.clone(),
            flow: instruction.flow,
            branch_target: instruction.near_branch_target,
        })
        .collect::<Vec<_>>();

    BasicBlock {
        start_va,
        end_va,
        instruction_count: instructions.len(),
        call_count,
        instructions: block_instructions,
    }
}

fn push_cfg_edge(
    edges: &mut Vec<CfgEdge>,
    edge_keys: &mut HashSet<(u64, u64, CfgEdgeKind)>,
    from_va: u64,
    to_va: u64,
    kind: CfgEdgeKind,
) {
    if edge_keys.insert((from_va, to_va, kind)) {
        edges.push(CfgEdge {
            from_va,
            to_va,
            kind,
        });
    }
}

fn build_call_graph(functions: &[FunctionSummary], mut edges: Vec<CallGraphEdge>) -> CallGraph {
    let mut nodes = BTreeMap::new();
    for function in functions {
        nodes.insert(
            function.start_va,
            CallGraphNode {
                start_va: function.start_va,
                name: function.name.clone(),
                is_external: false,
                call_count: function.call_count,
            },
        );
    }

    edges.sort_by_key(|edge| (edge.caller_va, edge.callee_va, edge.callsite_va));
    edges.dedup_by_key(|edge| (edge.caller_va, edge.callee_va, edge.callsite_va));
    for edge in &edges {
        nodes
            .entry(edge.callee_va)
            .or_insert_with(|| CallGraphNode {
                start_va: edge.callee_va,
                name: format!("sub_{:016X}", edge.callee_va),
                is_external: true,
                call_count: 0,
            });
    }

    CallGraph {
        nodes: nodes.into_values().collect(),
        edges,
    }
}

fn refresh_pseudocode(analysis: &mut StaticAnalysis) {
    analysis.pseudocode_functions = build_pseudocode_functions(
        &analysis.functions,
        &analysis.function_cfgs,
        &analysis.call_graph,
    );
}

fn refresh_runtime_signatures(analysis: &mut StaticAnalysis) {
    analysis.runtime_signatures = build_runtime_signatures(analysis);
}

fn validate_signature_library(library: &SignatureLibrary) -> Result<(), String> {
    if library.name.trim().is_empty() {
        return Err("签名库 name 不能为空。".to_owned());
    }
    if library.rules.is_empty() {
        return Err("签名库 rules 不能为空。".to_owned());
    }
    for rule in &library.rules {
        if rule.name.trim().is_empty() {
            return Err("签名规则 name 不能为空。".to_owned());
        }
        if rule.import_name_contains.is_empty()
            && rule.import_dll_contains.is_empty()
            && rule.function_name_contains.is_empty()
        {
            return Err(format!(
                "签名规则 `{}` 至少需要一个 import_name_contains、import_dll_contains 或 function_name_contains 条件。",
                rule.name
            ));
        }
    }
    Ok(())
}

fn build_signature_library_matches(
    analysis: &StaticAnalysis,
    library: &SignatureLibrary,
) -> Vec<RuntimeSignature> {
    let mut signatures = Vec::new();
    for rule in &library.rules {
        if rule_targets_import(rule) {
            for import in &analysis.imports {
                if rule_matches_import(rule, import) {
                    push_runtime_signature(
                        &mut signatures,
                        RuntimeSignature {
                            address: import.thunk_va,
                            name: format!("{} ({})", rule.name, import.display_name()),
                            kind: signature_rule_kind(rule),
                            target: RuntimeSignatureTarget::Import,
                            library: signature_rule_library(library, rule),
                            evidence: signature_rule_evidence(library, rule, import.display_name()),
                            confidence: signature_rule_confidence(rule),
                        },
                    );
                }
            }
        }

        if rule_targets_function(rule) {
            for function in &analysis.functions {
                if rule_matches_function(rule, function) {
                    push_runtime_signature(
                        &mut signatures,
                        RuntimeSignature {
                            address: function.start_va,
                            name: format!("{} ({})", rule.name, function.name),
                            kind: signature_rule_kind(rule),
                            target: RuntimeSignatureTarget::Function,
                            library: signature_rule_library(library, rule),
                            evidence: signature_rule_evidence(library, rule, function.name.clone()),
                            confidence: signature_rule_confidence(rule),
                        },
                    );
                }
            }
        }
    }
    sort_and_dedup_runtime_signatures(&mut signatures);
    signatures
}

fn rule_targets_import(rule: &SignatureRule) -> bool {
    rule.target
        .as_deref()
        .map(|target| target.eq_ignore_ascii_case("import"))
        .unwrap_or(true)
        && (!rule.import_name_contains.is_empty() || !rule.import_dll_contains.is_empty())
}

fn rule_targets_function(rule: &SignatureRule) -> bool {
    rule.target
        .as_deref()
        .map(|target| target.eq_ignore_ascii_case("function"))
        .unwrap_or(true)
        && !rule.function_name_contains.is_empty()
}

fn rule_matches_import(rule: &SignatureRule, import: &ImportSymbol) -> bool {
    all_needles_match(&rule.import_name_contains, &import.display_name())
        && all_needles_match(&rule.import_dll_contains, &import.dll)
}

fn rule_matches_function(rule: &SignatureRule, function: &FunctionSummary) -> bool {
    all_needles_match(&rule.function_name_contains, &function.name)
}

fn all_needles_match(needles: &[String], haystack: &str) -> bool {
    let haystack = haystack.to_ascii_lowercase();
    needles
        .iter()
        .all(|needle| haystack.contains(&needle.to_ascii_lowercase()))
}

fn signature_rule_kind(rule: &SignatureRule) -> RuntimeSignatureKind {
    match rule
        .kind
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "crt" | "crt_startup" | "crt-startup" | "startup" => RuntimeSignatureKind::CrtStartup,
        "security" | "security_cookie" | "security-cookie" => RuntimeSignatureKind::SecurityCookie,
        "exception" | "exception_handling" | "exception-handling" => {
            RuntimeSignatureKind::ExceptionHandling
        }
        "memory" | "memory_routine" | "memory-routine" => RuntimeSignatureKind::MemoryRoutine,
        "runtime" | "runtime_import" | "runtime-import" => RuntimeSignatureKind::RuntimeImport,
        "pattern" => RuntimeSignatureKind::Pattern,
        _ => RuntimeSignatureKind::UserSignature,
    }
}

fn signature_rule_library(library: &SignatureLibrary, rule: &SignatureRule) -> String {
    rule.library
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(&library.name)
        .to_owned()
}

fn signature_rule_evidence(
    library: &SignatureLibrary,
    rule: &SignatureRule,
    matched_name: String,
) -> String {
    let rule_id = rule.id.as_deref().unwrap_or(&rule.name);
    match &rule.evidence {
        Some(evidence) if !evidence.trim().is_empty() => {
            format!(
                "{evidence}; library `{}` rule `{rule_id}` matched `{matched_name}`",
                library.name
            )
        }
        _ => format!(
            "signature library `{}` rule `{rule_id}` matched `{matched_name}`",
            library.name
        ),
    }
}

fn signature_rule_confidence(rule: &SignatureRule) -> u8 {
    rule.confidence.unwrap_or(75).clamp(1, 100)
}

fn build_runtime_signatures(analysis: &StaticAnalysis) -> Vec<RuntimeSignature> {
    let mut signatures = Vec::new();

    for import in &analysis.imports {
        let display_name = import.display_name();
        let import_name = import.name.as_deref().unwrap_or(&display_name);
        if let Some((kind, library, confidence)) = classify_runtime_name(import_name) {
            push_runtime_signature(
                &mut signatures,
                RuntimeSignature {
                    address: import.thunk_va,
                    name: display_name.clone(),
                    kind,
                    target: RuntimeSignatureTarget::Import,
                    library: runtime_library_label(&import.dll)
                        .unwrap_or(library)
                        .to_owned(),
                    evidence: format!("import name matched `{import_name}`"),
                    confidence,
                },
            );
        } else if let Some(library) = runtime_library_label(&import.dll) {
            push_runtime_signature(
                &mut signatures,
                RuntimeSignature {
                    address: import.thunk_va,
                    name: display_name,
                    kind: RuntimeSignatureKind::RuntimeImport,
                    target: RuntimeSignatureTarget::Import,
                    library: library.to_owned(),
                    evidence: format!("runtime DLL `{}`", import.dll),
                    confidence: 70,
                },
            );
        }
    }

    for function in &analysis.functions {
        if let Some((kind, library, confidence)) = classify_runtime_name(&function.name) {
            push_runtime_signature(
                &mut signatures,
                RuntimeSignature {
                    address: function.start_va,
                    name: function.name.clone(),
                    kind,
                    target: RuntimeSignatureTarget::Function,
                    library: library.to_owned(),
                    evidence: format!("function name matched `{}`", function.name),
                    confidence,
                },
            );
        }
    }

    if let Some(entry) = detect_crt_startup_function(analysis, &signatures) {
        push_runtime_signature(
            &mut signatures,
            RuntimeSignature {
                address: entry.start_va,
                name: entry.name.clone(),
                kind: RuntimeSignatureKind::CrtStartup,
                target: RuntimeSignatureTarget::Function,
                library: "MSVC CRT".to_owned(),
                evidence: "entry function has multiple CRT startup imports".to_owned(),
                confidence: 78,
            },
        );
    }

    for cfg in &analysis.function_cfgs {
        if has_memory_routine_pattern(cfg) {
            let name = analysis
                .functions
                .iter()
                .find(|function| function.start_va == cfg.function_start)
                .map(|function| function.name.clone())
                .unwrap_or_else(|| format!("sub_{:016X}", cfg.function_start));
            push_runtime_signature(
                &mut signatures,
                RuntimeSignature {
                    address: cfg.function_start,
                    name,
                    kind: RuntimeSignatureKind::MemoryRoutine,
                    target: RuntimeSignatureTarget::Pattern,
                    library: "CRT".to_owned(),
                    evidence: "function contains repeated movs/stos memory instruction pattern"
                        .to_owned(),
                    confidence: 62,
                },
            );
        }
    }

    sort_and_dedup_runtime_signatures(&mut signatures);
    signatures
}

fn sort_and_dedup_runtime_signatures(signatures: &mut Vec<RuntimeSignature>) {
    signatures.sort_by_key(|signature| {
        (
            signature.address,
            signature.target,
            signature.kind,
            std::cmp::Reverse(signature.confidence),
        )
    });
    let mut seen = BTreeSet::new();
    signatures.retain(|signature| {
        seen.insert((
            signature.address,
            signature.target,
            signature.kind,
            signature.name.clone(),
        ))
    });
    signatures.truncate(MAX_RUNTIME_SIGNATURES);
}

fn push_runtime_signature(signatures: &mut Vec<RuntimeSignature>, signature: RuntimeSignature) {
    if signatures.len() < MAX_RUNTIME_SIGNATURES {
        signatures.push(signature);
    }
}

fn classify_runtime_name(name: &str) -> Option<(RuntimeSignatureKind, &'static str, u8)> {
    let normalized = normalize_runtime_name(name);
    let stripped = normalized
        .trim_start_matches('_')
        .trim_start_matches('@')
        .to_owned();

    if normalized.contains("security_check_cookie")
        || normalized.contains("security_cookie")
        || normalized.contains("gsfailure")
    {
        return Some((RuntimeSignatureKind::SecurityCookie, "MSVC Runtime", 96));
    }

    if contains_any(
        &normalized,
        &[
            "__c_specific_handler",
            "c_specific_handler",
            "rtlvirtualunwind",
            "rtlcapturecontext",
            "rtllookupfunctionentry",
            "unhandledexceptionfilter",
            "setunhandledexceptionfilter",
            "__current_exception",
            "__current_exception_context",
            "_seh_filter_exe",
            "seh_filter_exe",
            "cxxframehandler",
            "cxxthrowexception",
        ],
    ) {
        return Some((RuntimeSignatureKind::ExceptionHandling, "MSVC Runtime", 92));
    }

    if matches!(
        stripped.as_str(),
        "memcpy"
            | "memmove"
            | "memset"
            | "memcmp"
            | "memchr"
            | "memcpy_s"
            | "memmove_s"
            | "memset_s"
    ) || contains_any(&normalized, &["__movsb", "__stosb", "__movsd", "__stosd"])
    {
        return Some((RuntimeSignatureKind::MemoryRoutine, "CRT", 90));
    }

    if is_crt_startup_name(&normalized, &stripped) {
        return Some((RuntimeSignatureKind::CrtStartup, "MSVC CRT", 88));
    }

    None
}

fn normalize_runtime_name(name: &str) -> String {
    let without_module = name.rsplit('!').next().unwrap_or(name);
    without_module
        .trim()
        .trim_matches('`')
        .trim_matches('"')
        .to_ascii_lowercase()
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn is_crt_startup_name(normalized: &str, stripped: &str) -> bool {
    const CRT_SUBSTRINGS: &[&str] = &[
        "_configure_narrow_argv",
        "_get_narrow_winmain_command_line",
        "_initialize_narrow_environment",
        "_initialize_onexit_table",
        "_register_onexit_function",
        "_register_thread_local_exe_atexit_callback",
        "_initterm",
        "_initterm_e",
        "_set_app_type",
        "_set_new_mode",
        "_set_fmode",
        "_c_exit",
        "_cexit",
        "maincrtstartup",
        "winmaincrtstartup",
        "__scrt_",
        "__vcrt_",
        "__acrt_",
    ];
    contains_any(normalized, CRT_SUBSTRINGS)
        || matches!(
            stripped,
            "exit" | "terminate" | "abort" | "atexit" | "getmainargs" | "wgetmainargs"
        )
}

fn runtime_library_label(dll: &str) -> Option<&'static str> {
    let lower = dll.to_ascii_lowercase();
    if lower.contains("api-ms-win-crt") || lower.contains("ucrt") {
        Some("Universal CRT")
    } else if lower.contains("vcruntime") {
        Some("MSVC Runtime")
    } else if lower.contains("msvcp") {
        Some("MSVC C++ Runtime")
    } else if lower == "msvcrt.dll" || lower.contains("msvcrt") {
        Some("MSVCRT")
    } else if lower.contains("concrt") {
        Some("Concurrency Runtime")
    } else {
        None
    }
}

fn detect_crt_startup_function<'a>(
    analysis: &'a StaticAnalysis,
    signatures: &[RuntimeSignature],
) -> Option<&'a FunctionSummary> {
    let crt_imports = signatures
        .iter()
        .filter(|signature| {
            signature.target == RuntimeSignatureTarget::Import
                && matches!(
                    signature.kind,
                    RuntimeSignatureKind::CrtStartup | RuntimeSignatureKind::RuntimeImport
                )
        })
        .count();
    if crt_imports < 3 {
        return None;
    }

    analysis
        .functions
        .iter()
        .find(|function| {
            let name = function.name.to_ascii_lowercase();
            name.contains("entry") || name.contains("crtstartup")
        })
        .or_else(|| analysis.functions.first())
}

fn has_memory_routine_pattern(cfg: &FunctionCfg) -> bool {
    cfg.blocks.iter().any(|block| {
        block.instructions.iter().any(|instruction| {
            let mnemonic = instruction.mnemonic.to_ascii_lowercase();
            mnemonic.contains("movs")
                || mnemonic.contains("stos")
                || mnemonic.contains("rep movs")
                || mnemonic.contains("rep stos")
        })
    })
}

fn build_pseudocode_functions(
    functions: &[FunctionSummary],
    cfgs: &[FunctionCfg],
    call_graph: &CallGraph,
) -> Vec<PseudocodeFunction> {
    let names = functions
        .iter()
        .map(|function| (function.start_va, function.name.clone()))
        .collect::<BTreeMap<_, _>>();
    let call_targets = call_graph
        .edges
        .iter()
        .map(|edge| (edge.callsite_va, edge.callee_va))
        .collect::<BTreeMap<_, _>>();

    functions
        .iter()
        .filter_map(|function| {
            let cfg = cfgs
                .iter()
                .find(|cfg| cfg.function_start == function.start_va)?;
            let mut lines = vec![
                PseudocodeLine {
                    address: Some(function.start_va),
                    text: format!("void {}(void)", sanitize_identifier(&function.name)),
                },
                PseudocodeLine {
                    address: None,
                    text: "{".to_owned(),
                },
            ];
            let mut ir = Vec::new();

            for block in &cfg.blocks {
                if cfg.blocks.len() > 1 {
                    lines.push(PseudocodeLine {
                        address: Some(block.start_va),
                        text: format!("loc_{:X}:", block.start_va),
                    });
                }

                for instruction in &block.instructions {
                    let pseudo = pseudo_for_instruction(instruction, &names, &call_targets);
                    lines.push(PseudocodeLine {
                        address: Some(instruction.address),
                        text: format!("    {pseudo}"),
                    });
                    ir.push(ir_for_instruction(instruction, &names, &call_targets));
                }
            }

            lines.push(PseudocodeLine {
                address: None,
                text: "}".to_owned(),
            });
            Some(PseudocodeFunction {
                function_start: function.start_va,
                name: function.name.clone(),
                lines,
                ir,
            })
        })
        .collect()
}

fn pseudo_for_instruction(
    instruction: &BlockInstruction,
    names: &BTreeMap<u64, String>,
    call_targets: &BTreeMap<u64, u64>,
) -> String {
    match instruction.flow {
        InstructionFlow::DirectCall | InstructionFlow::IndirectCall => {
            let target = call_targets
                .get(&instruction.address)
                .copied()
                .or(instruction.branch_target);
            let callee = target
                .and_then(|address| names.get(&address).cloned())
                .unwrap_or_else(|| {
                    target
                        .map(|address| format!("sub_{address:016X}"))
                        .unwrap_or_else(|| "indirect_call".to_owned())
                });
            format!("{}();", sanitize_identifier(&callee))
        }
        InstructionFlow::ConditionalBranch => {
            let target = instruction
                .branch_target
                .map(|address| format!("loc_{address:X}"))
                .unwrap_or_else(|| "unknown".to_owned());
            format!(
                "if (/* {} {} */) goto {};",
                instruction.mnemonic, instruction.operands, target
            )
        }
        InstructionFlow::UnconditionalBranch => {
            let target = instruction
                .branch_target
                .map(|address| format!("loc_{address:X}"))
                .unwrap_or_else(|| "unknown".to_owned());
            format!("goto {target};")
        }
        InstructionFlow::Return => "return;".to_owned(),
        _ => pseudo_for_linear_instruction(instruction),
    }
}

fn pseudo_for_linear_instruction(instruction: &BlockInstruction) -> String {
    let mnemonic = instruction.mnemonic.to_ascii_lowercase();
    let operands = instruction.operands.trim();
    if mnemonic == "mov" || mnemonic == "lea" {
        if let Some((left, right)) = operands.split_once(',') {
            let operator = if mnemonic == "lea" { "&" } else { "" };
            return format!("{} = {}{};", left.trim(), operator, right.trim());
        }
    }
    if mnemonic == "xor" {
        if let Some((left, right)) = operands.split_once(',') {
            if left.trim().eq_ignore_ascii_case(right.trim()) {
                return format!("{} = 0;", left.trim());
            }
        }
    }
    if mnemonic == "cmp" || mnemonic == "test" {
        return format!("/* condition: {} {} */", instruction.mnemonic, operands);
    }
    if operands.is_empty() {
        format!("/* {} */", instruction.mnemonic)
    } else {
        format!("/* {} {} */", instruction.mnemonic, operands)
    }
}

fn ir_for_instruction(
    instruction: &BlockInstruction,
    names: &BTreeMap<u64, String>,
    call_targets: &BTreeMap<u64, u64>,
) -> IrInstruction {
    let op = match instruction.flow {
        InstructionFlow::DirectCall | InstructionFlow::IndirectCall => "call",
        InstructionFlow::ConditionalBranch => "branch_if",
        InstructionFlow::UnconditionalBranch => "jump",
        InstructionFlow::Return => "return",
        _ => instruction.mnemonic.as_str(),
    }
    .to_owned();
    let mut args = Vec::new();
    if !instruction.operands.trim().is_empty() {
        args.push(instruction.operands.clone());
    }
    if let Some(target) = call_targets
        .get(&instruction.address)
        .copied()
        .or(instruction.branch_target)
    {
        args.push(format!("0x{target:016X}"));
        if let Some(name) = names.get(&target) {
            args.push(name.clone());
        }
    }
    IrInstruction {
        address: instruction.address,
        op,
        args,
        comment: format!("{} {}", instruction.mnemonic, instruction.operands)
            .trim()
            .to_owned(),
    }
}

fn sanitize_identifier(name: &str) -> String {
    let mut output = String::with_capacity(name.len());
    for (index, character) in name.chars().enumerate() {
        let valid = character.is_ascii_alphanumeric() || character == '_';
        if index == 0 && character.is_ascii_digit() {
            output.push('_');
        }
        output.push(if valid { character } else { '_' });
    }
    if output.is_empty() {
        "sub_unknown".to_owned()
    } else {
        output
    }
}

fn parse_pe_pdb_records(image: &PeImage, bytes: &[u8]) -> Vec<PePdbRecord> {
    let Some(directory) = image
        .data_directory(PE_DIRECTORY_DEBUG)
        .filter(|dir| dir.is_present())
    else {
        return Vec::new();
    };

    let mut records = Vec::new();
    let entry_count = (directory.size / 28).min(MAX_DEBUG_DIRECTORY_ENTRIES as u32);
    for index in 0..entry_count {
        let debug_rva = directory.virtual_address.saturating_add(index * 28);
        let Some(kind) = read_u32_at_rva(image, bytes, debug_rva + 12) else {
            break;
        };
        if kind != 2 {
            continue;
        }

        let Some(size_of_data) = read_u32_at_rva(image, bytes, debug_rva + 16) else {
            continue;
        };
        let Some(address_of_raw_data) = read_u32_at_rva(image, bytes, debug_rva + 20) else {
            continue;
        };
        let Some(pointer_to_raw_data) = read_u32_at_rva(image, bytes, debug_rva + 24) else {
            continue;
        };
        let debug_file_offset = if usize::try_from(pointer_to_raw_data)
            .ok()
            .map_or(false, |offset| offset < bytes.len())
        {
            Some(pointer_to_raw_data)
        } else {
            image
                .rva_to_file_offset(u64::from(address_of_raw_data))
                .and_then(|value| u32::try_from(value).ok())
        };

        let Some(file_offset) = debug_file_offset else {
            continue;
        };
        let Some(record_bytes) = read_bytes_at_file_offset(bytes, file_offset, size_of_data) else {
            continue;
        };
        if let Some(record) =
            parse_codeview_pdb_record(record_bytes, address_of_raw_data, file_offset)
        {
            records.push(record);
        }
    }

    records
}

fn parse_codeview_pdb_record(
    bytes: &[u8],
    debug_rva: u32,
    debug_file_offset: u32,
) -> Option<PePdbRecord> {
    let signature = bytes.get(0..4)?;
    match signature {
        b"RSDS" => {
            if bytes.len() < 24 {
                return None;
            }
            let guid = format_rsds_guid(bytes.get(4..20)?);
            let age = u32::from_le_bytes(bytes.get(20..24)?.try_into().ok()?);
            let path = read_null_terminated_utf8(bytes.get(24..).unwrap_or_default());
            Some(PePdbRecord {
                format: PePdbFormat::Rsds,
                path,
                guid: Some(guid),
                age: Some(age),
                signature: None,
                debug_rva,
                debug_file_offset,
            })
        }
        b"NB10" => {
            if bytes.len() < 16 {
                return None;
            }
            let signature = u32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?);
            let age = u32::from_le_bytes(bytes.get(12..16)?.try_into().ok()?);
            let path = read_null_terminated_utf8(bytes.get(16..).unwrap_or_default());
            Some(PePdbRecord {
                format: PePdbFormat::Nb10,
                path,
                guid: None,
                age: Some(age),
                signature: Some(signature),
                debug_rva,
                debug_file_offset,
            })
        }
        other => {
            let format = String::from_utf8_lossy(other).to_string();
            Some(PePdbRecord {
                format: PePdbFormat::Unknown(format),
                path: String::new(),
                guid: None,
                age: None,
                signature: None,
                debug_rva,
                debug_file_offset,
            })
        }
    }
}

fn collect_global_pdb_symbols(
    pdb: &mut pdb::PDB<'_, std::fs::File>,
    image: &PeImage,
    address_map: &pdb::AddressMap<'_>,
) -> Result<Vec<PdbSymbol>, String> {
    let mut symbols = Vec::new();
    let symbol_table = pdb
        .global_symbols()
        .map_err(|source| format!("读取 PDB 全局符号表失败：{source}"))?;
    let mut iter = symbol_table.iter();

    while let Some(symbol) = iter
        .next()
        .map_err(|source| format!("遍历 PDB 全局符号失败：{source}"))?
    {
        if symbols.len() >= MAX_PDB_SYMBOLS {
            break;
        }
        let Ok(data) = symbol.parse() else {
            continue;
        };

        match data {
            pdb::SymbolData::Public(public) => {
                let (rva, address) = offset_to_rva_va(public.offset, image, address_map);
                let kind = if public.function {
                    PdbSymbolKind::Function
                } else if public.code {
                    PdbSymbolKind::PublicCode
                } else {
                    PdbSymbolKind::PublicData
                };
                let name = public.name.to_string().into_owned();
                symbols.push(make_pdb_symbol(address, rva, name, kind, "public"));
            }
            pdb::SymbolData::Data(data) => {
                let (rva, address) = offset_to_rva_va(data.offset, image, address_map);
                let name = data.name.to_string().into_owned();
                symbols.push(make_pdb_symbol(
                    address,
                    rva,
                    name,
                    PdbSymbolKind::Data,
                    "data",
                ));
            }
            pdb::SymbolData::UserDefinedType(udt) => {
                let name = udt.name.to_string().into_owned();
                symbols.push(make_pdb_symbol(
                    None,
                    None,
                    name,
                    PdbSymbolKind::UserDefinedType,
                    "udt",
                ));
            }
            pdb::SymbolData::ProcedureReference(reference) => {
                if let Some(name) = reference.name {
                    let name = name.to_string().into_owned();
                    symbols.push(make_pdb_symbol(
                        None,
                        None,
                        name,
                        PdbSymbolKind::ProcedureReference,
                        "proc-ref",
                    ));
                }
            }
            pdb::SymbolData::DataReference(reference) => {
                if let Some(name) = reference.name {
                    let name = name.to_string().into_owned();
                    symbols.push(make_pdb_symbol(
                        None,
                        None,
                        name,
                        PdbSymbolKind::DataReference,
                        "data-ref",
                    ));
                }
            }
            _ => {}
        }
    }

    Ok(symbols)
}

fn collect_module_pdb_symbols(
    pdb: &mut pdb::PDB<'_, std::fs::File>,
    image: &PeImage,
    address_map: &pdb::AddressMap<'_>,
) -> (Vec<PdbSymbol>, Vec<PdbSourceFile>) {
    let Ok(debug_info) = pdb.debug_information() else {
        return (Vec::new(), Vec::new());
    };
    let Ok(mut modules) = debug_info.modules() else {
        return (Vec::new(), Vec::new());
    };

    let mut symbols = Vec::new();
    let mut sources = BTreeSet::new();
    while let Ok(Some(module)) = modules.next() {
        if sources.len() < MAX_PDB_SOURCES {
            let module_name = module.module_name().to_string();
            if !module_name.is_empty() {
                sources.insert(module_name);
            }
            let object_name = module.object_file_name().to_string();
            if !object_name.is_empty() {
                sources.insert(object_name);
            }
        }

        if symbols.len() >= MAX_PDB_SYMBOLS {
            continue;
        }
        let Ok(Some(info)) = pdb.module_info(&module) else {
            continue;
        };
        let Ok(mut module_symbols) = info.symbols() else {
            continue;
        };
        while let Ok(Some(symbol)) = module_symbols.next() {
            if symbols.len() >= MAX_PDB_SYMBOLS {
                break;
            }
            let Ok(data) = symbol.parse() else {
                continue;
            };
            match data {
                pdb::SymbolData::Procedure(proc_symbol) => {
                    let (rva, address) = offset_to_rva_va(proc_symbol.offset, image, address_map);
                    let name = proc_symbol.name.to_string().into_owned();
                    symbols.push(make_pdb_symbol(
                        address,
                        rva,
                        name,
                        PdbSymbolKind::Function,
                        "procedure",
                    ));
                }
                pdb::SymbolData::Data(data) => {
                    let (rva, address) = offset_to_rva_va(data.offset, image, address_map);
                    let name = data.name.to_string().into_owned();
                    symbols.push(make_pdb_symbol(
                        address,
                        rva,
                        name,
                        PdbSymbolKind::Data,
                        "data",
                    ));
                }
                pdb::SymbolData::UserDefinedType(udt) => {
                    let name = udt.name.to_string().into_owned();
                    symbols.push(make_pdb_symbol(
                        None,
                        None,
                        name,
                        PdbSymbolKind::UserDefinedType,
                        "udt",
                    ));
                }
                _ => {}
            }
        }
    }

    let source_files = sources
        .into_iter()
        .take(MAX_PDB_SOURCES)
        .map(|path| PdbSourceFile { path })
        .collect();
    (symbols, source_files)
}

fn collect_pdb_type_summaries(symbols: &[PdbSymbol]) -> Vec<PdbTypeSummary> {
    let mut seen = BTreeSet::new();
    symbols
        .iter()
        .filter(|symbol| symbol.kind == PdbSymbolKind::UserDefinedType)
        .filter_map(|symbol| {
            let name = symbol.display_name().to_owned();
            if seen.insert(name.clone()) {
                Some(PdbTypeSummary {
                    name,
                    kind: "UDT".to_owned(),
                    source: symbol.source.clone(),
                })
            } else {
                None
            }
        })
        .take(MAX_PDB_TYPES)
        .collect()
}

fn overlay_pdb_function_names(image: &PeImage, analysis: &mut StaticAnalysis) {
    let mut known_functions = analysis
        .functions
        .iter()
        .map(|function| function.start_va)
        .collect::<BTreeSet<_>>();
    for symbol in &analysis.pdb_symbols {
        let Some(address) = symbol.address else {
            continue;
        };
        if !symbol.is_function_like() || !image.is_executable_va(address) {
            continue;
        }
        if known_functions.insert(address) {
            analysis.functions.push(FunctionSummary {
                start_va: address,
                name: symbol.display_name().to_owned(),
                size: 0,
                instruction_count: 0,
                call_count: 0,
            });
        }
    }
    analysis.functions.sort_by_key(|function| function.start_va);
    overlay_pdb_names_only(analysis);
}

fn overlay_pdb_names_only(analysis: &mut StaticAnalysis) {
    let names = analysis
        .pdb_symbols
        .iter()
        .filter(|symbol| symbol.is_function_like())
        .filter_map(|symbol| Some((symbol.address?, symbol.display_name().to_owned())))
        .collect::<BTreeMap<_, _>>();

    for function in &mut analysis.functions {
        if let Some(name) = names.get(&function.start_va) {
            function.name = name.clone();
        }
    }
    for node in &mut analysis.call_graph.nodes {
        if let Some(name) = names.get(&node.start_va) {
            node.name = name.clone();
        }
    }
}

fn make_pdb_symbol(
    address: Option<u64>,
    rva: Option<u32>,
    name: String,
    kind: PdbSymbolKind,
    source: &str,
) -> PdbSymbol {
    let demangled_name = demangle_symbol(&name);
    PdbSymbol {
        address,
        rva,
        name,
        demangled_name,
        kind,
        source: source.to_owned(),
    }
}

fn demangle_symbol(name: &str) -> Option<String> {
    if let Ok(value) = msvc_demangler::demangle(name, msvc_demangler::DemangleFlags::llvm()) {
        let value = value.to_string();
        if value != name {
            return Some(value);
        }
    }

    if name.starts_with("_R") || name.starts_with("ZN") || name.starts_with("_ZN") {
        let value = rustc_demangle::demangle(name).to_string();
        if value != name {
            return Some(value);
        }
    }
    None
}

fn offset_to_rva_va(
    offset: pdb::PdbInternalSectionOffset,
    image: &PeImage,
    address_map: &pdb::AddressMap<'_>,
) -> (Option<u32>, Option<u64>) {
    let rva = offset.to_rva(address_map).map(|rva| rva.0);
    let address = rva.map(|rva| image.rva_to_va(u64::from(rva)));
    (rva, address)
}

fn dedup_pdb_symbols(symbols: &mut Vec<PdbSymbol>) {
    symbols.sort_by(|left, right| {
        left.address
            .cmp(&right.address)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.display_name().cmp(right.display_name()))
    });
    symbols.dedup_by(|left, right| {
        left.address == right.address
            && left.kind == right.kind
            && left.display_name() == right.display_name()
    });
    if symbols.len() > MAX_PDB_SYMBOLS {
        symbols.truncate(MAX_PDB_SYMBOLS);
    }
}

fn pdb_matches_pe(record: &PePdbRecord, pdb_guid: &str, pdb_age: u32) -> bool {
    let guid_matches = record
        .guid
        .as_deref()
        .map(|guid| guid.eq_ignore_ascii_case(pdb_guid))
        .unwrap_or(true);
    let age_matches = record.age.map(|age| pdb_age >= age).unwrap_or(true);
    guid_matches && age_matches
}

fn format_rsds_guid(bytes: &[u8]) -> String {
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

fn read_null_terminated_utf8(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

fn read_bytes_at_file_offset(bytes: &[u8], file_offset: u32, size: u32) -> Option<&[u8]> {
    let start = usize::try_from(file_offset).ok()?;
    let size = usize::try_from(size).ok()?;
    let end = start.checked_add(size)?;
    bytes.get(start..end)
}

fn dedup_xrefs(xrefs: &mut Vec<XrefSummary>) {
    xrefs.sort_by_key(|xref| (xref.from_va, xref.to_va, xref.kind));
    xrefs.dedup_by_key(|xref| (xref.from_va, xref.to_va, xref.kind));
}

fn instruction_end(instruction: &DecodedInstruction) -> u64 {
    instruction
        .address
        .saturating_add(u64::try_from(instruction.bytes.len()).unwrap_or(0))
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

fn scan_raw_strings(image: &RawImage, bytes: &[u8]) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    scan_ascii_strings_raw(image, bytes, &mut strings, MAX_STRINGS);
    scan_utf16le_strings_raw(image, bytes, &mut strings, MAX_STRINGS);
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

fn scan_ascii_strings_raw(
    image: &RawImage,
    bytes: &[u8],
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
            let file_offset = u64::try_from(start).unwrap_or(0);
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

fn scan_utf16le_strings_raw(
    image: &RawImage,
    bytes: &[u8],
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
            let file_offset = u64::try_from(start).unwrap_or(0);
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

fn bytes_from_raw_va<'a>(
    image: &RawImage,
    bytes: &'a [u8],
    va: u64,
    max_len: usize,
) -> Option<&'a [u8]> {
    let start = usize::try_from(image.va_to_file_offset(va)?).ok()?;
    if start >= bytes.len() {
        return None;
    }
    let len = bytes.len().saturating_sub(start).min(max_len);
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

fn instructions_to_disassembly_build(
    instructions: Vec<DecodedInstruction>,
    complete_label: &str,
    invalid_comment: &str,
) -> DisassemblyBuild {
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
                invalid_comment.to_owned()
            } else {
                String::new()
            },
        })
        .collect::<Vec<_>>();
    let mut log_lines = vec![format!(
        "{complete_label}：入口点附近 {} 条指令。",
        rows.len()
    )];
    if invalid_count > 0 {
        log_lines.push(format!(
            "发现 {invalid_count} 条无效指令，已用 db 占位显示。"
        ));
    }
    DisassemblyBuild { rows, log_lines }
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
        PeSection, RawArch, RawImage, PE_DIRECTORY_DEBUG,
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
        data_directories[PE_DIRECTORY_DEBUG] = PeDataDirectory {
            virtual_address: 0x2400,
            size: 0x1C,
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

        let pdb_path = b"C:\\symbols\\analysis.pdb";
        write_u32(&mut bytes, 0x800 + 12, 2);
        write_u32(&mut bytes, 0x800 + 16, (24 + pdb_path.len() + 1) as u32);
        write_u32(&mut bytes, 0x800 + 20, 0x2420);
        write_u32(&mut bytes, 0x800 + 24, 0x820);
        bytes[0x820..0x824].copy_from_slice(b"RSDS");
        bytes[0x824..0x834].copy_from_slice(&[
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ]);
        write_u32(&mut bytes, 0x834, 2);
        bytes[0x838..0x838 + pdb_path.len()].copy_from_slice(pdb_path);

        bytes
    }

    fn sample_raw_image() -> RawImage {
        let selection = FileSelection::new(PathBuf::from(r"C:\samples\raw.bin"), 0x80);
        RawImage::new(selection, 0x1800_00000, 0x1800_00000, RawArch::X64)
    }

    fn sample_raw_bytes() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x80];
        bytes[0x00..0x06].copy_from_slice(&[0xE8, 0x0B, 0x00, 0x00, 0x00, 0xC3]);
        bytes[0x10] = 0xC3;
        write_c_string(&mut bytes, 0x20, "raw string");
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
        assert_eq!(analysis.pe_pdb_records[0].path, r"C:\symbols\analysis.pdb");
        assert_eq!(
            analysis.pe_pdb_records[0].guid.as_deref(),
            Some("00112233-4455-6677-8899-aabbccddeeff")
        );
        assert_eq!(analysis.pe_pdb_records[0].age, Some(2));
        assert!(analysis
            .function_cfgs
            .iter()
            .any(|cfg| cfg.function_start == 0x1400_01000 && !cfg.blocks.is_empty()));
        assert!(analysis
            .call_graph
            .edges
            .iter()
            .any(|edge| { edge.caller_va == 0x1400_01000 && edge.callee_va == 0x1400_01010 }));
        assert!(analysis.pseudocode_functions.iter().any(|function| {
            function.function_start == 0x1400_01000
                && function.lines.iter().any(|line| line.text.contains("sub_"))
                && !function.ir.is_empty()
        }));
    }

    #[test]
    fn analyzes_raw_functions_strings_and_xrefs() {
        let image = sample_raw_image();
        let bytes = sample_raw_bytes();

        let analysis = analyze_raw(&image, &bytes);

        assert!(analysis
            .functions
            .iter()
            .any(|function| function.name == "raw_entry" && function.start_va == 0x1800_00000));
        assert!(analysis
            .functions
            .iter()
            .any(|function| function.start_va == 0x1800_00010));
        assert!(analysis
            .strings
            .iter()
            .any(|string| string.value == "raw string" && string.address == 0x1800_00020));
        assert!(analysis
            .xrefs
            .iter()
            .any(|xref| xref.from_va == 0x1800_00000 && xref.to_va == 0x1800_00010));
        assert!(analysis.imports.is_empty());
        assert!(analysis.exports.is_empty());
        assert!(analysis.relocations.is_empty());
        assert!(analysis
            .function_cfgs
            .iter()
            .any(|cfg| cfg.function_start == 0x1800_00000 && !cfg.blocks.is_empty()));
        assert!(analysis
            .call_graph
            .edges
            .iter()
            .any(|edge| { edge.caller_va == 0x1800_00000 && edge.callee_va == 0x1800_00010 }));
        assert!(analysis.pseudocode_functions.iter().any(|function| {
            function.function_start == 0x1800_00000
                && function.lines.iter().any(|line| line.text.contains("raw_"))
                && !function.ir.is_empty()
        }));
    }

    #[test]
    fn builds_cfg_edges_for_conditional_branch() {
        let instructions = disassemble_x64(0x1800_00000, &[0x75, 0x01, 0x90, 0xC3], 8);

        let cfg = build_function_cfg(0x1800_00000, &instructions);

        assert_eq!(cfg.blocks.len(), 3);
        assert!(cfg.edges.iter().any(|edge| {
            edge.from_va == 0x1800_00000
                && edge.to_va == 0x1800_00003
                && edge.kind == CfgEdgeKind::ConditionalTrue
        }));
        assert!(cfg.edges.iter().any(|edge| {
            edge.from_va == 0x1800_00000
                && edge.to_va == 0x1800_00002
                && edge.kind == CfgEdgeKind::ConditionalFalse
        }));
        assert!(cfg.edges.iter().any(|edge| {
            edge.from_va == 0x1800_00002
                && edge.to_va == 0x1800_00003
                && edge.kind == CfgEdgeKind::Fallthrough
        }));
    }

    #[test]
    fn classifies_common_msvc_runtime_names() {
        assert_eq!(
            classify_runtime_name("__security_check_cookie").map(|(kind, _, _)| kind),
            Some(RuntimeSignatureKind::SecurityCookie)
        );
        assert_eq!(
            classify_runtime_name("__C_specific_handler").map(|(kind, _, _)| kind),
            Some(RuntimeSignatureKind::ExceptionHandling)
        );
        assert_eq!(
            classify_runtime_name("memcpy").map(|(kind, _, _)| kind),
            Some(RuntimeSignatureKind::MemoryRoutine)
        );
        assert_eq!(
            classify_runtime_name("_initialize_onexit_table").map(|(kind, _, _)| kind),
            Some(RuntimeSignatureKind::CrtStartup)
        );
    }

    #[test]
    fn applies_local_signature_library_rules() {
        let image = sample_image();
        let bytes = sample_bytes();
        let mut analysis = analyze_pe(&image, &bytes);
        let library = SignatureLibrary {
            name: "local triage".to_owned(),
            version: Some("0.1".to_owned()),
            rules: vec![SignatureRule {
                id: Some("create-file".to_owned()),
                name: "Create File Import".to_owned(),
                kind: Some("user".to_owned()),
                library: Some("Windows API".to_owned()),
                target: Some("import".to_owned()),
                evidence: Some("test rule".to_owned()),
                confidence: Some(81),
                import_name_contains: vec!["CreateFileW".to_owned()],
                import_dll_contains: Vec::new(),
                function_name_contains: Vec::new(),
            }],
        };

        let count = apply_signature_library(&mut analysis, &library);

        assert_eq!(count, 1);
        assert!(analysis.runtime_signatures.iter().any(|signature| {
            signature.kind == RuntimeSignatureKind::UserSignature
                && signature.name.contains("Create File Import")
                && signature.evidence.contains("create-file")
                && signature.confidence == 81
        }));
    }

    #[test]
    fn demangles_msvc_symbol_names() {
        let demangled = demangle_symbol("??_0klass@@QEAAHH@Z").expect("msvc demangle");

        assert!(demangled.contains("klass"));
        assert_ne!(demangled, "??_0klass@@QEAAHH@Z");
    }
}
