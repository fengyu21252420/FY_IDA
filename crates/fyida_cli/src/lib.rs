use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use fyida_analysis::StaticAnalysis;
use fyida_core::{sha256_hex, RawArch};
use fyida_loader::RawLoadOptions;
use serde::{Deserialize, Serialize};

const HEADLESS_ANALYZE_COMMAND: &str = "analyze";

#[derive(Debug, Parser)]
#[command(
    name = "fy_ida",
    version,
    about = "FY_IDA 中文逆向分析工作台",
    long_about = "FY_IDA 是面向 Windows x64 PE / Raw Binary 的轻量逆向分析工具。当前 v0.19.0-alpha.1 已提供 headless 搜索报告、伪代码/IR headless 选择性导出、伪代码/IR 搜索、`--headless analyze <FILE>`、本地 JSON 签名库导入、运行库签名识别、GUI 运行库函数过滤、基础 x64 伪 C/IR 输出、Python 脚本 API、headless JSON/CSV 导出和基础静态分析。"
)]
pub struct Cli {
    #[arg(long, help = "以命令行占位模式运行，不启动 GUI")]
    pub headless: bool,

    #[arg(long, help = "按 Raw Binary 加载输入文件")]
    pub raw: bool,

    #[arg(long, default_value = "0x140000000", help = "Raw Binary 基址")]
    pub base: String,

    #[arg(long, default_value = "0x140000000", help = "Raw Binary 入口地址")]
    pub entry: String,

    #[arg(long, default_value = "x64", help = "Raw Binary 架构；当前仅支持 x64")]
    pub arch: String,

    #[arg(long, value_name = "PDB", help = "为 PE 手动加载外部 PDB 符号文件")]
    pub pdb: Option<PathBuf>,
    #[arg(
        long,
        value_name = "JSON",
        help = "导入本地 FY_IDA JSON 签名库；可重复指定"
    )]
    pub signature_library: Vec<PathBuf>,

    #[arg(long, value_name = "HEADER", help = "导入 C Header 类型定义")]
    pub type_header: Option<PathBuf>,

    #[arg(long, value_name = "HEADER", help = "导出内置/导入的类型库为 C Header")]
    pub export_types: Option<PathBuf>,

    #[arg(
        long,
        value_enum,
        default_value_t = ExportFormat::Text,
        help = "headless 输出格式"
    )]
    pub export_format: ExportFormat,

    #[arg(
        long,
        value_enum,
        default_value_t = ExportKind::All,
        help = "CSV/text 输出的数据范围"
    )]
    pub export: ExportKind,

    #[arg(
        long,
        value_name = "QUERY",
        help = "在 headless 报告中搜索函数、字符串、导入导出、xref、伪代码、IR、类型和字节序列"
    )]
    pub search: Option<String>,

    #[arg(long, value_name = "OUTPUT", help = "将 headless 报告写入文件")]
    pub output: Option<PathBuf>,

    #[arg(long, value_name = "DIR", help = "批量分析目录中的文件")]
    pub batch_dir: Option<PathBuf>,

    #[arg(long, help = "批量分析时递归子目录")]
    pub recursive: bool,

    #[arg(long, default_value_t = 0, help = "单文件分析超时毫秒；0 表示不限制")]
    pub timeout_ms: u64,

    #[arg(
        long,
        value_name = "REPORT",
        help = "将 headless 错误报告写入 JSON 文件"
    )]
    pub error_report: Option<PathBuf>,

    #[arg(
        long,
        value_name = "PY",
        help = "分析后运行 Python 脚本，脚本通过 FYIDA_REPORT_JSON 读取报告"
    )]
    pub python_script: Option<PathBuf>,

    #[arg(long, value_name = "DIR", help = "扫描 FY_IDA 插件 manifest 目录")]
    pub plugins_dir: Option<PathBuf>,

    #[arg(long = "plugin", value_name = "ID", help = "运行指定插件 ID；可重复")]
    pub plugins: Vec<String>,

    #[arg(
        value_name = "COMMAND_OR_FILE",
        num_args = 0..=2,
        help = "GUI 预选文件；headless 可使用 analyze <FILE> 或直接 <FILE>"
    )]
    pub positionals: Vec<PathBuf>,
}

impl Cli {
    pub fn gui_file(&self) -> Option<PathBuf> {
        if self.uses_analyze_command() {
            self.positionals.get(1).cloned()
        } else {
            self.positionals.first().cloned()
        }
    }

    pub fn headless_input_file(&self) -> Result<Option<&Path>, String> {
        if self.uses_analyze_command() {
            return Ok(self.positionals.get(1).map(PathBuf::as_path));
        }
        if self.positionals.len() > 1 {
            return Err(format!(
                "未知 headless 命令 `{}`；请使用 `analyze <FILE>` 或直接提供 `<FILE>`。",
                self.positionals[0].display()
            ));
        }
        Ok(self.positionals.first().map(PathBuf::as_path))
    }

    fn uses_analyze_command(&self) -> bool {
        self.positionals
            .first()
            .and_then(|value| value.to_str())
            .map(|value| value.eq_ignore_ascii_case(HEADLESS_ANALYZE_COMMAND))
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    Text,
    Json,
    Csv,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportKind {
    All,
    Summary,
    Functions,
    Strings,
    Imports,
    Exports,
    Xrefs,
    RuntimeSignatures,
    Pseudocode,
    Ir,
    Search,
    Types,
}

#[derive(Debug, Serialize)]
struct HeadlessReport {
    version: String,
    input: InputReport,
    analysis: AnalysisReport,
    type_library: TypeLibraryReport,
    search: Option<SearchReport>,
    messages: Vec<String>,
    elapsed_ms: u128,
}

#[derive(Debug, Serialize)]
struct InputReport {
    path: String,
    kind: String,
    size_bytes: u64,
    sha256: String,
    arch: Option<String>,
    base_address: Option<u64>,
    entry_va: Option<u64>,
    entry_rva_or_offset: Option<u64>,
    image_base: Option<u64>,
    machine: Option<String>,
    subsystem: Option<String>,
    sections: Vec<SectionReport>,
}

#[derive(Debug, Serialize)]
struct SectionReport {
    name: String,
    rva: u32,
    va: u64,
    file_offset: u32,
    virtual_size: u32,
    raw_size: u32,
    permissions: String,
}

#[derive(Debug, Serialize)]
struct AnalysisReport {
    functions: Vec<FunctionRecord>,
    strings: Vec<StringRecord>,
    imports: Vec<ImportRecord>,
    exports: Vec<ExportRecord>,
    relocations: Vec<RelocationRecord>,
    xrefs: Vec<XrefRecord>,
    cfg_count: usize,
    call_graph_nodes: usize,
    call_graph_edges: usize,
    pseudocode_functions: Vec<PseudocodeRecord>,
    runtime_signatures: Vec<RuntimeSignatureRecord>,
    pdb_records: Vec<PdbRecord>,
    pdb_symbols: Vec<PdbSymbolRecord>,
    pdb_types: Vec<PdbTypeRecord>,
}

#[derive(Debug, Serialize)]
struct FunctionRecord {
    start_va: u64,
    name: String,
    size: u64,
    instruction_count: usize,
    call_count: usize,
}

#[derive(Debug, Serialize)]
struct StringRecord {
    address: u64,
    file_offset: u64,
    encoding: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct ImportRecord {
    thunk_va: u64,
    thunk_rva: u32,
    dll: String,
    name: Option<String>,
    ordinal: Option<u16>,
    hint: Option<u16>,
    display_name: String,
}

#[derive(Debug, Serialize)]
struct ExportRecord {
    va: u64,
    rva: u32,
    ordinal: u32,
    name: String,
}

#[derive(Debug, Serialize)]
struct RelocationRecord {
    va: u64,
    rva: u32,
    page_rva: u32,
    kind: String,
}

#[derive(Debug, Serialize)]
struct XrefRecord {
    from_va: u64,
    to_va: u64,
    kind: String,
    label: String,
}

#[derive(Debug, Serialize)]
struct PseudocodeRecord {
    function_start: u64,
    name: String,
    lines: Vec<String>,
    line_addresses: Vec<Option<u64>>,
    ir: Vec<IrRecord>,
}

#[derive(Debug, Serialize)]
struct IrRecord {
    address: u64,
    op: String,
    args: Vec<String>,
    comment: String,
}

#[derive(Debug, Serialize)]
struct RuntimeSignatureRecord {
    address: u64,
    name: String,
    kind: String,
    target: String,
    library: String,
    evidence: String,
    confidence: u8,
}

#[derive(Debug, Serialize)]
struct PdbRecord {
    format: String,
    path: String,
    guid: Option<String>,
    age: Option<u32>,
    signature: Option<u32>,
    debug_rva: u32,
    debug_file_offset: u32,
}

#[derive(Debug, Serialize)]
struct PdbSymbolRecord {
    address: Option<u64>,
    rva: Option<u32>,
    kind: String,
    name: String,
    original_name: String,
    source: String,
}

#[derive(Debug, Serialize)]
struct PdbTypeRecord {
    name: String,
    kind: String,
    source: String,
}

#[derive(Debug, Serialize)]
struct TypeLibraryReport {
    count: usize,
    types: Vec<TypeRecord>,
}

#[derive(Debug, Serialize)]
struct SearchReport {
    query: String,
    result_count: usize,
    results: Vec<SearchRecord>,
}

#[derive(Debug, Serialize)]
struct SearchRecord {
    category: String,
    address: Option<u64>,
    label: String,
    snippet: String,
}

#[derive(Debug, Serialize)]
struct TypeRecord {
    name: String,
    kind: String,
    source: String,
    signature: String,
}

#[derive(Debug, Serialize)]
struct BatchReport {
    version: String,
    root: String,
    recursive: bool,
    files: Vec<BatchFileReport>,
    errors: Vec<BatchError>,
    elapsed_ms: u128,
}

#[derive(Debug, Serialize)]
struct BatchFileReport {
    path: String,
    status: String,
    elapsed_ms: u128,
    functions: usize,
    strings: usize,
    imports: usize,
    exports: usize,
    xrefs: usize,
    search_results: usize,
    pdb_symbols: usize,
    pdb_types: usize,
    error: Option<String>,
    report: Option<HeadlessReport>,
}

#[derive(Debug, Clone, Serialize)]
struct BatchError {
    path: String,
    message: String,
}

struct CliTypeLoad {
    types: Vec<fyida_core::ProjectType>,
    messages: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PluginManifest {
    id: String,
    name: String,
    version: Option<String>,
    description: Option<String>,
    script: PathBuf,
    menu: Option<String>,
}

pub fn run_headless(cli: &Cli) -> i32 {
    let input_file = match cli.headless_input_file() {
        Ok(file) => file,
        Err(message) => {
            let _ = write_errors(
                cli,
                &[BatchError {
                    path: "-".to_owned(),
                    message: message.clone(),
                }],
            );
            eprintln!("{message}");
            return 2;
        }
    };

    let type_load = match load_cli_types(cli) {
        Ok(types) => types,
        Err(message) => {
            let _ = write_errors(
                cli,
                &[BatchError {
                    path: "-".to_owned(),
                    message: message.clone(),
                }],
            );
            eprintln!("类型参数错误：{message}");
            return 2;
        }
    };

    if let Some(batch_dir) = &cli.batch_dir {
        return run_batch(cli, batch_dir, &type_load);
    }

    let Some(file) = input_file else {
        let message = "FY_IDA headless 模式需要提供输入文件，或使用 --batch-dir。".to_owned();
        let _ = write_errors(
            cli,
            &[BatchError {
                path: "-".to_owned(),
                message: message.clone(),
            }],
        );
        eprintln!("{message}");
        return 2;
    };

    match analyze_one(cli, file, &type_load) {
        Ok(report) => match emit_single_report(cli, &report) {
            Ok(()) => 0,
            Err(message) => {
                let _ = write_errors(
                    cli,
                    &[BatchError {
                        path: file.display().to_string(),
                        message: message.clone(),
                    }],
                );
                eprintln!("导出失败：{message}");
                1
            }
        },
        Err(message) => {
            let _ = write_errors(
                cli,
                &[BatchError {
                    path: file.display().to_string(),
                    message: message.clone(),
                }],
            );
            eprintln!("{message}");
            1
        }
    }
}

fn run_batch(cli: &Cli, batch_dir: &Path, type_load: &CliTypeLoad) -> i32 {
    let started = Instant::now();
    let files = match collect_batch_files(batch_dir, cli.recursive) {
        Ok(files) => files,
        Err(message) => {
            let _ = write_errors(
                cli,
                &[BatchError {
                    path: batch_dir.display().to_string(),
                    message: message.clone(),
                }],
            );
            eprintln!("批量分析失败：{message}");
            return 1;
        }
    };

    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for file in files {
        let file_started = Instant::now();
        match analyze_one(cli, &file, type_load) {
            Ok(report) => {
                let elapsed_ms = file_started.elapsed().as_millis();
                if timed_out(cli, file_started.elapsed()) {
                    let message = format!("分析超过 timeout-ms {}", cli.timeout_ms);
                    errors.push(BatchError {
                        path: file.display().to_string(),
                        message: message.clone(),
                    });
                    entries.push(BatchFileReport {
                        path: file.display().to_string(),
                        status: "timeout".to_owned(),
                        elapsed_ms,
                        functions: 0,
                        strings: 0,
                        imports: 0,
                        exports: 0,
                        xrefs: 0,
                        search_results: 0,
                        pdb_symbols: 0,
                        pdb_types: 0,
                        error: Some(message),
                        report: None,
                    });
                } else {
                    entries.push(batch_success(
                        file.display().to_string(),
                        elapsed_ms,
                        report,
                    ));
                }
            }
            Err(message) => {
                let elapsed_ms = file_started.elapsed().as_millis();
                errors.push(BatchError {
                    path: file.display().to_string(),
                    message: message.clone(),
                });
                entries.push(BatchFileReport {
                    path: file.display().to_string(),
                    status: "error".to_owned(),
                    elapsed_ms,
                    functions: 0,
                    strings: 0,
                    imports: 0,
                    exports: 0,
                    xrefs: 0,
                    search_results: 0,
                    pdb_symbols: 0,
                    pdb_types: 0,
                    error: Some(message),
                    report: None,
                });
            }
        }
    }

    let report = BatchReport {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        root: batch_dir.display().to_string(),
        recursive: cli.recursive,
        files: entries,
        errors,
        elapsed_ms: started.elapsed().as_millis(),
    };
    if let Err(message) = write_errors(cli, &report.errors) {
        eprintln!("错误报告写入失败：{message}");
        return 1;
    }
    match emit_batch_report(cli, &report) {
        Ok(()) if report.errors.is_empty() => 0,
        Ok(()) => 1,
        Err(message) => {
            eprintln!("批量报告导出失败：{message}");
            1
        }
    }
}

fn batch_success(path: String, elapsed_ms: u128, report: HeadlessReport) -> BatchFileReport {
    BatchFileReport {
        path,
        status: "ok".to_owned(),
        elapsed_ms,
        functions: report.analysis.functions.len(),
        strings: report.analysis.strings.len(),
        imports: report.analysis.imports.len(),
        exports: report.analysis.exports.len(),
        xrefs: report.analysis.xrefs.len(),
        search_results: report
            .search
            .as_ref()
            .map(|search| search.result_count)
            .unwrap_or(0),
        pdb_symbols: report.analysis.pdb_symbols.len(),
        pdb_types: report.analysis.pdb_types.len(),
        error: None,
        report: Some(report),
    }
}

fn analyze_one(cli: &Cli, file: &Path, type_load: &CliTypeLoad) -> Result<HeadlessReport, String> {
    let started = Instant::now();
    if cli.raw {
        let options = raw_options(cli)?;
        let loaded = fyida_loader::load_raw_file_with_bytes(file, options)
            .map_err(|error| format!("Raw Binary 加载失败：{error}"))?;
        let mut analysis = fyida_analysis::analyze_raw(&loaded.image, &loaded.bytes);
        let mut messages = type_load.messages.clone();
        apply_signature_libraries(cli, &mut analysis, &mut messages);
        let input = raw_input_report(&loaded.image, &loaded.bytes);
        let analysis = analysis_report(&analysis);
        let type_library = type_library_report(&type_load.types);
        let search = build_search_report(
            cli.search.as_deref(),
            &input,
            &loaded.bytes,
            &analysis,
            &type_library,
        );
        let mut report = HeadlessReport {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            input,
            analysis,
            type_library,
            search,
            messages,
            elapsed_ms: started.elapsed().as_millis(),
        };
        run_python_automation(cli, &mut report)?;
        return timeout_checked(cli, started, report);
    }

    let loaded = fyida_loader::load_pe_file_with_bytes(file)
        .map_err(|error| format!("PE 加载失败：{error}"))?;
    let mut analysis = fyida_analysis::analyze_pe(&loaded.image, &loaded.bytes);
    let mut messages = type_load.messages.clone();
    if let Some(pdb_path) = &cli.pdb {
        match fyida_analysis::apply_pdb_file(&loaded.image, &mut analysis, pdb_path) {
            Ok(summary) => messages.push(format!(
                "PDB 已加载：{} / symbols {} / types {} / sources {} / match {}",
                summary.loaded.path,
                summary.symbol_count,
                summary.type_count,
                summary.source_count,
                match summary.loaded.matched_pe {
                    Some(true) => "yes",
                    Some(false) => "no",
                    None => "unknown",
                }
            )),
            Err(error) => messages.push(format!("PDB 加载失败：{error}")),
        }
    }

    apply_signature_libraries(cli, &mut analysis, &mut messages);

    let input = pe_input_report(&loaded.image, &loaded.bytes);
    let analysis = analysis_report(&analysis);
    let type_library = type_library_report(&type_load.types);
    let search = build_search_report(
        cli.search.as_deref(),
        &input,
        &loaded.bytes,
        &analysis,
        &type_library,
    );
    let mut report = HeadlessReport {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        input,
        analysis,
        type_library,
        search,
        messages,
        elapsed_ms: started.elapsed().as_millis(),
    };
    run_python_automation(cli, &mut report)?;
    timeout_checked(cli, started, report)
}

fn apply_signature_libraries(cli: &Cli, analysis: &mut StaticAnalysis, messages: &mut Vec<String>) {
    for path in &cli.signature_library {
        match fyida_analysis::load_signature_library_file(path) {
            Ok(library) => {
                let count = fyida_analysis::apply_signature_library(analysis, &library);
                messages.push(format!(
                    "签名库已导入：{} / rules {} / matches {}",
                    library.name,
                    library.rules.len(),
                    count
                ));
            }
            Err(error) => messages.push(format!("签名库导入失败：{} ({error})", path.display())),
        }
    }
}

fn run_python_automation(cli: &Cli, report: &mut HeadlessReport) -> Result<(), String> {
    let mut scripts = Vec::new();
    if let Some(script) = &cli.python_script {
        scripts.push(("script".to_owned(), script.clone()));
    }
    for plugin in selected_plugins(cli)? {
        let label = format!(
            "plugin:{}:{}",
            plugin.id,
            plugin.version.as_deref().unwrap_or("dev")
        );
        if let Some(description) = &plugin.description {
            report
                .messages
                .push(format!("插件 {} - {}", plugin.name, description));
        }
        if let Some(menu) = &plugin.menu {
            report
                .messages
                .push(format!("插件菜单入口 {} -> {}", plugin.name, menu));
        }
        scripts.push((label, plugin.script));
    }

    for (label, script) in scripts {
        let output = run_python_script(&script, report)
            .map_err(|message| format!("Python {label} 运行失败：{message}"))?;
        report
            .messages
            .push(format!("Python {label} stdout:\n{}", output.0));
        if !output.1.trim().is_empty() {
            report
                .messages
                .push(format!("Python {label} stderr:\n{}", output.1));
        }
    }
    Ok(())
}

fn selected_plugins(cli: &Cli) -> Result<Vec<PluginManifest>, String> {
    let Some(directory) = &cli.plugins_dir else {
        return Ok(Vec::new());
    };
    let mut manifests = scan_plugin_manifests(directory)?;
    if !cli.plugins.is_empty() {
        manifests.retain(|manifest| cli.plugins.iter().any(|id| id == &manifest.id));
    }
    Ok(manifests)
}

fn scan_plugin_manifests(directory: &Path) -> Result<Vec<PluginManifest>, String> {
    let entries = std::fs::read_dir(directory)
        .map_err(|error| format!("无法扫描插件目录 {}：{error}", directory.display()))?;
    let mut manifests = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("插件目录枚举失败：{error}"))?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("无法读取插件 manifest {}：{error}", path.display()))?;
        let mut manifest: PluginManifest = serde_json::from_str(&text)
            .map_err(|error| format!("插件 manifest 格式无效 {}：{error}", path.display()))?;
        if manifest.script.is_relative() {
            let base = path.parent().unwrap_or(directory);
            manifest.script = base.join(&manifest.script);
        }
        manifests.push(manifest);
    }
    manifests.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(manifests)
}

fn run_python_script(script: &Path, report: &HeadlessReport) -> Result<(String, String), String> {
    let report_path = std::env::temp_dir().join(format!(
        "fyida_python_report_{}_{}.json",
        std::process::id(),
        safe_temp_name(&report.input.path)
    ));
    let report_json = serde_json::to_string_pretty(report)
        .map_err(|error| format!("无法编码脚本报告 JSON：{error}"))?;
    std::fs::write(&report_path, report_json)
        .map_err(|error| format!("无法写入脚本报告 {}：{error}", report_path.display()))?;

    let output = Command::new("python")
        .arg(script)
        .env("FYIDA_REPORT_JSON", &report_path)
        .env("FYIDA_INPUT_PATH", &report.input.path)
        .env("FYIDA_INPUT_KIND", &report.input.kind)
        .output()
        .map_err(|error| format!("无法启动 python：{error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if output.status.success() {
        Ok((stdout, stderr))
    } else {
        Err(format!(
            "退出码 {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            stdout,
            stderr
        ))
    }
}

fn safe_temp_name(path: &str) -> String {
    path.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .take(80)
        .collect()
}

fn timeout_checked(
    cli: &Cli,
    started: Instant,
    report: HeadlessReport,
) -> Result<HeadlessReport, String> {
    if timed_out(cli, started.elapsed()) {
        Err(format!("分析超过 timeout-ms {}", cli.timeout_ms))
    } else {
        Ok(report)
    }
}

fn timed_out(cli: &Cli, elapsed: Duration) -> bool {
    cli.timeout_ms > 0 && elapsed > Duration::from_millis(cli.timeout_ms)
}

fn pe_input_report(image: &fyida_core::PeImage, bytes: &[u8]) -> InputReport {
    InputReport {
        path: image.file().path().display().to_string(),
        kind: "PE".to_owned(),
        size_bytes: image.file().size_bytes(),
        sha256: sha256_hex(bytes),
        arch: Some("x64".to_owned()),
        base_address: Some(image.image_base()),
        entry_va: Some(image.entry_point_va()),
        entry_rva_or_offset: Some(u64::from(image.entry_point_rva())),
        image_base: Some(image.image_base()),
        machine: Some(image.machine_label().to_owned()),
        subsystem: Some(image.subsystem_label().to_owned()),
        sections: image
            .sections
            .iter()
            .map(|section| SectionReport {
                name: section.name.clone(),
                rva: section.virtual_address,
                va: section.virtual_address_va(image.image_base()),
                file_offset: section.pointer_to_raw_data,
                virtual_size: section.virtual_size,
                raw_size: section.size_of_raw_data,
                permissions: section.permissions(),
            })
            .collect(),
    }
}

fn raw_input_report(image: &fyida_core::RawImage, bytes: &[u8]) -> InputReport {
    InputReport {
        path: image.file().path().display().to_string(),
        kind: "Raw Binary".to_owned(),
        size_bytes: image.file().size_bytes(),
        sha256: sha256_hex(bytes),
        arch: Some(image.arch.label().to_owned()),
        base_address: Some(image.base_address),
        entry_va: Some(image.entry_address),
        entry_rva_or_offset: image.entry_offset(),
        image_base: None,
        machine: None,
        subsystem: None,
        sections: Vec::new(),
    }
}

fn analysis_report(analysis: &StaticAnalysis) -> AnalysisReport {
    AnalysisReport {
        functions: analysis
            .functions
            .iter()
            .map(|function| FunctionRecord {
                start_va: function.start_va,
                name: function.name.clone(),
                size: function.size,
                instruction_count: function.instruction_count,
                call_count: function.call_count,
            })
            .collect(),
        strings: analysis
            .strings
            .iter()
            .map(|string| StringRecord {
                address: string.address,
                file_offset: string.file_offset,
                encoding: string.encoding.label().to_owned(),
                value: string.value.clone(),
            })
            .collect(),
        imports: analysis
            .imports
            .iter()
            .map(|import| ImportRecord {
                thunk_va: import.thunk_va,
                thunk_rva: import.thunk_rva,
                dll: import.dll.clone(),
                name: import.name.clone(),
                ordinal: import.ordinal,
                hint: import.hint,
                display_name: import.display_name(),
            })
            .collect(),
        exports: analysis
            .exports
            .iter()
            .map(|export| ExportRecord {
                va: export.va,
                rva: export.rva,
                ordinal: export.ordinal,
                name: export.name.clone(),
            })
            .collect(),
        relocations: analysis
            .relocations
            .iter()
            .map(|relocation| RelocationRecord {
                va: relocation.va,
                rva: relocation.rva,
                page_rva: relocation.page_rva,
                kind: relocation.kind_label().to_owned(),
            })
            .collect(),
        xrefs: analysis
            .xrefs
            .iter()
            .map(|xref| XrefRecord {
                from_va: xref.from_va,
                to_va: xref.to_va,
                kind: xref.kind.label().to_owned(),
                label: xref.label.clone(),
            })
            .collect(),
        cfg_count: analysis.function_cfgs.len(),
        call_graph_nodes: analysis.call_graph.nodes.len(),
        call_graph_edges: analysis.call_graph.edges.len(),
        pseudocode_functions: analysis
            .pseudocode_functions
            .iter()
            .map(|function| PseudocodeRecord {
                function_start: function.function_start,
                name: function.name.clone(),
                lines: function
                    .lines
                    .iter()
                    .map(|line| line.text.clone())
                    .collect(),
                line_addresses: function.lines.iter().map(|line| line.address).collect(),
                ir: function
                    .ir
                    .iter()
                    .map(|instruction| IrRecord {
                        address: instruction.address,
                        op: instruction.op.clone(),
                        args: instruction.args.clone(),
                        comment: instruction.comment.clone(),
                    })
                    .collect(),
            })
            .collect(),
        runtime_signatures: analysis
            .runtime_signatures
            .iter()
            .map(|signature| RuntimeSignatureRecord {
                address: signature.address,
                name: signature.name.clone(),
                kind: signature.kind.label().to_owned(),
                target: signature.target.label().to_owned(),
                library: signature.library.clone(),
                evidence: signature.evidence.clone(),
                confidence: signature.confidence,
            })
            .collect(),
        pdb_records: analysis
            .pe_pdb_records
            .iter()
            .map(|record| PdbRecord {
                format: record.format.label().to_owned(),
                path: record.path.clone(),
                guid: record.guid.clone(),
                age: record.age,
                signature: record.signature,
                debug_rva: record.debug_rva,
                debug_file_offset: record.debug_file_offset,
            })
            .collect(),
        pdb_symbols: analysis
            .pdb_symbols
            .iter()
            .map(|symbol| PdbSymbolRecord {
                address: symbol.address,
                rva: symbol.rva,
                kind: symbol.kind.label().to_owned(),
                name: symbol.display_name().to_owned(),
                original_name: symbol.name.clone(),
                source: symbol.source.clone(),
            })
            .collect(),
        pdb_types: analysis
            .pdb_types
            .iter()
            .map(|type_item| PdbTypeRecord {
                name: type_item.name.clone(),
                kind: type_item.kind.clone(),
                source: type_item.source.clone(),
            })
            .collect(),
    }
}

fn type_library_report(types: &[fyida_core::ProjectType]) -> TypeLibraryReport {
    TypeLibraryReport {
        count: types.len(),
        types: types
            .iter()
            .map(|type_item| TypeRecord {
                name: type_item.name.clone(),
                kind: type_item.kind.clone(),
                source: type_item.source.clone(),
                signature: type_item.display_signature(),
            })
            .collect(),
    }
}

const MAX_SEARCH_RESULTS: usize = 512;
const MAX_BYTE_PATTERN_RESULTS: usize = 64;

fn build_search_report(
    query: Option<&str>,
    input: &InputReport,
    bytes: &[u8],
    analysis: &AnalysisReport,
    type_library: &TypeLibraryReport,
) -> Option<SearchReport> {
    let query = query?.trim();
    let mut results = Vec::new();
    if query.is_empty() {
        return Some(SearchReport {
            query: String::new(),
            result_count: 0,
            results,
        });
    }

    if let Some(address) = parse_number(query) {
        push_search(
            &mut results,
            "address",
            Some(address),
            format!("VA 0x{address:016X}"),
            format!("address query `{query}`"),
        );
    }

    if let Some(pattern) = parse_byte_pattern(query) {
        for file_offset in find_byte_pattern(bytes, &pattern)
            .into_iter()
            .take(MAX_BYTE_PATTERN_RESULTS)
        {
            let address = file_offset_to_va(input, file_offset);
            push_search(
                &mut results,
                "bytes",
                address,
                format!("FO 0x{file_offset:08X}"),
                format_byte_pattern(&pattern),
            );
        }
    }

    for section in &input.sections {
        let label = format!(
            "{} RVA 0x{:08X} FO 0x{:08X} {}",
            section.name, section.rva, section.file_offset, section.permissions
        );
        if matches_text(query, [&section.name, &section.permissions])
            || address_matches(section.va, query)
            || address_matches(u64::from(section.rva), query)
            || address_matches(u64::from(section.file_offset), query)
        {
            push_search(&mut results, "section", Some(section.va), label, "section");
        }
    }

    for function in &analysis.functions {
        if matches_text(query, [&function.name]) || address_matches(function.start_va, query) {
            push_search(
                &mut results,
                "function",
                Some(function.start_va),
                function.name.clone(),
                format!(
                    "size 0x{:X}, instructions {}, calls {}",
                    function.size, function.instruction_count, function.call_count
                ),
            );
        }
    }

    for string in &analysis.strings {
        if matches_text(query, [&string.value, &string.encoding])
            || address_matches(string.address, query)
            || address_matches(string.file_offset, query)
        {
            push_search(
                &mut results,
                "string",
                Some(string.address),
                format!("{} string", string.encoding),
                string.value.clone(),
            );
        }
    }

    for import in &analysis.imports {
        let name = import.name.as_deref().unwrap_or("");
        if matches_text(query, [&import.display_name, &import.dll, name])
            || address_matches(import.thunk_va, query)
            || address_matches(u64::from(import.thunk_rva), query)
        {
            push_search(
                &mut results,
                "import",
                Some(import.thunk_va),
                import.display_name.clone(),
                format!("{} hint {:?}", import.dll, import.hint),
            );
        }
    }

    for export in &analysis.exports {
        if matches_text(query, [&export.name])
            || address_matches(export.va, query)
            || address_matches(u64::from(export.rva), query)
        {
            push_search(
                &mut results,
                "export",
                Some(export.va),
                export.name.clone(),
                format!("ordinal {}", export.ordinal),
            );
        }
    }

    for relocation in &analysis.relocations {
        if matches_text(query, [&relocation.kind])
            || address_matches(relocation.va, query)
            || address_matches(u64::from(relocation.rva), query)
        {
            push_search(
                &mut results,
                "relocation",
                Some(relocation.va),
                relocation.kind.clone(),
                format!("page RVA 0x{:08X}", relocation.page_rva),
            );
        }
    }

    for xref in &analysis.xrefs {
        if matches_text(query, [&xref.kind, &xref.label])
            || address_matches(xref.from_va, query)
            || address_matches(xref.to_va, query)
        {
            push_search(
                &mut results,
                "xref",
                Some(xref.from_va),
                format!("{:016X} -> {:016X}", xref.from_va, xref.to_va),
                format!("{} {}", xref.kind, xref.label),
            );
        }
    }

    for signature in &analysis.runtime_signatures {
        if matches_text(
            query,
            [
                &signature.name,
                &signature.kind,
                &signature.target,
                &signature.library,
                &signature.evidence,
            ],
        ) || address_matches(signature.address, query)
        {
            push_search(
                &mut results,
                "runtime_signature",
                Some(signature.address),
                signature.name.clone(),
                format!(
                    "{} / {} / confidence {} / {}",
                    signature.kind, signature.library, signature.confidence, signature.evidence
                ),
            );
        }
    }

    for function in &analysis.pseudocode_functions {
        if matches_text(query, [&function.name]) || address_matches(function.function_start, query)
        {
            push_search(
                &mut results,
                "pseudocode_function",
                Some(function.function_start),
                function.name.clone(),
                "generated pseudocode function",
            );
        }
        for (index, line) in function.lines.iter().enumerate() {
            let address = function.line_addresses.get(index).copied().flatten();
            if matches_text(query, [line.as_str()])
                || address
                    .map(|address| address_matches(address, query))
                    .unwrap_or(false)
            {
                push_search(
                    &mut results,
                    "pseudocode",
                    address,
                    function.name.clone(),
                    line.clone(),
                );
            }
        }

        for instruction in &function.ir {
            let text = ir_search_text(&instruction.op, &instruction.args, &instruction.comment);
            if matches_text(query, [text.as_str()]) || address_matches(instruction.address, query) {
                push_search(
                    &mut results,
                    "ir",
                    Some(instruction.address),
                    function.name.clone(),
                    text,
                );
            }
        }
    }

    for record in &analysis.pdb_records {
        if matches_text(query, [&record.format, &record.path])
            || address_matches(u64::from(record.debug_rva), query)
            || address_matches(u64::from(record.debug_file_offset), query)
        {
            push_search(
                &mut results,
                "pdb_record",
                None,
                record.format.clone(),
                record.path.clone(),
            );
        }
    }

    for symbol in &analysis.pdb_symbols {
        if matches_text(
            query,
            [
                &symbol.kind,
                &symbol.name,
                &symbol.original_name,
                &symbol.source,
            ],
        ) || symbol
            .address
            .map(|address| address_matches(address, query))
            .unwrap_or(false)
            || symbol
                .rva
                .map(|rva| address_matches(u64::from(rva), query))
                .unwrap_or(false)
        {
            push_search(
                &mut results,
                "pdb_symbol",
                symbol.address,
                symbol.name.clone(),
                format!("{} {}", symbol.kind, symbol.source),
            );
        }
    }

    for type_item in &analysis.pdb_types {
        if matches_text(query, [&type_item.name, &type_item.kind, &type_item.source]) {
            push_search(
                &mut results,
                "pdb_type",
                None,
                type_item.name.clone(),
                format!("{} {}", type_item.kind, type_item.source),
            );
        }
    }

    for type_item in &type_library.types {
        if matches_text(
            query,
            [
                &type_item.name,
                &type_item.kind,
                &type_item.source,
                &type_item.signature,
            ],
        ) {
            push_search(
                &mut results,
                "type",
                None,
                type_item.name.clone(),
                type_item.signature.clone(),
            );
        }
    }

    Some(SearchReport {
        query: query.to_owned(),
        result_count: results.len(),
        results,
    })
}

fn push_search(
    results: &mut Vec<SearchRecord>,
    category: &str,
    address: Option<u64>,
    label: impl Into<String>,
    snippet: impl Into<String>,
) {
    if results.len() >= MAX_SEARCH_RESULTS {
        return;
    }
    results.push(SearchRecord {
        category: category.to_owned(),
        address,
        label: label.into(),
        snippet: search_snippet(&snippet.into()),
    });
}

fn matches_text<T>(query: &str, fields: impl IntoIterator<Item = T>) -> bool
where
    T: AsRef<str>,
{
    let query = query.to_lowercase();
    fields
        .into_iter()
        .any(|field| field.as_ref().to_lowercase().contains(&query))
}

fn address_matches(address: u64, query: &str) -> bool {
    let query = query
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_lowercase();
    if query.is_empty() {
        return false;
    }
    format!("{address:016X}").to_lowercase().contains(&query)
}

fn file_offset_to_va(input: &InputReport, file_offset: u64) -> Option<u64> {
    if input.kind.starts_with("Raw") {
        return input
            .base_address
            .and_then(|base| base.checked_add(file_offset));
    }

    if let Some(first_section_offset) = input
        .sections
        .iter()
        .map(|section| u64::from(section.file_offset))
        .min()
    {
        if file_offset < first_section_offset {
            return input
                .image_base
                .and_then(|base| base.checked_add(file_offset));
        }
    }

    input.sections.iter().find_map(|section| {
        let start = u64::from(section.file_offset);
        let delta = file_offset.checked_sub(start)?;
        (delta < u64::from(section.raw_size)).then_some(section.va + delta)
    })
}

fn ir_search_text(op: &str, args: &[String], comment: &str) -> String {
    let args = args.join(", ");
    if comment.trim().is_empty() {
        format!("{op} {args}")
    } else {
        format!("{op} {args} ; {comment}")
    }
}

fn search_snippet(text: &str) -> String {
    let trimmed = text.trim();
    let mut chars = trimmed.chars();
    let snippet = chars.by_ref().take(96).collect::<String>();
    if chars.next().is_some() {
        format!("{snippet}...")
    } else {
        snippet
    }
}

fn emit_single_report(cli: &Cli, report: &HeadlessReport) -> Result<(), String> {
    let encoded = match cli.export_format {
        ExportFormat::Text => text_report(report, cli.export),
        ExportFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| format!("JSON 编码失败：{error}"))?,
        ExportFormat::Csv => csv_report(report, cli.export),
    };
    emit_output(cli.output.as_deref(), &encoded)
}

fn emit_batch_report(cli: &Cli, report: &BatchReport) -> Result<(), String> {
    let encoded = match cli.export_format {
        ExportFormat::Text => text_batch_report(report),
        ExportFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| format!("JSON 编码失败：{error}"))?,
        ExportFormat::Csv => csv_batch_report(report),
    };
    emit_output(cli.output.as_deref(), &encoded)
}

fn emit_output(path: Option<&Path>, encoded: &str) -> Result<(), String> {
    if let Some(path) = path {
        std::fs::write(path, encoded)
            .map_err(|error| format!("无法写入 {}：{error}", path.display()))
    } else {
        print!("{encoded}");
        Ok(())
    }
}

fn write_errors(cli: &Cli, errors: &[BatchError]) -> Result<(), String> {
    if errors.is_empty() {
        return Ok(());
    }
    let Some(path) = &cli.error_report else {
        return Ok(());
    };
    let encoded = serde_json::to_string_pretty(errors)
        .map_err(|error| format!("错误报告编码失败：{error}"))?;
    std::fs::write(path, encoded).map_err(|error| format!("无法写入 {}：{error}", path.display()))
}

fn text_report(report: &HeadlessReport, kind: ExportKind) -> String {
    match kind {
        ExportKind::All => text_full_report(report),
        ExportKind::Summary => text_summary_report(report),
        ExportKind::Functions => text_functions(&report.analysis.functions),
        ExportKind::Strings => text_strings(&report.analysis.strings),
        ExportKind::Imports => text_imports(&report.analysis.imports),
        ExportKind::Exports => text_exports(&report.analysis.exports),
        ExportKind::Xrefs => text_xrefs(&report.analysis.xrefs),
        ExportKind::RuntimeSignatures => {
            text_runtime_signatures(&report.analysis.runtime_signatures)
        }
        ExportKind::Pseudocode => text_pseudocode(&report.analysis.pseudocode_functions),
        ExportKind::Ir => text_ir(&report.analysis.pseudocode_functions),
        ExportKind::Search => text_search(report.search.as_ref()),
        ExportKind::Types => text_types(&report.type_library.types),
    }
}

fn text_full_report(report: &HeadlessReport) -> String {
    let mut text = String::new();
    let _ = writeln!(
        text,
        "{} 加载完成：{}",
        report.input.kind, report.input.path
    );
    if let Some(machine) = &report.input.machine {
        let _ = writeln!(text, "Machine：{machine}");
    }
    if let Some(base) = report.input.base_address {
        let _ = writeln!(text, "Base：0x{base:016X}");
    }
    if let Some(entry) = report.input.entry_va {
        let _ = writeln!(text, "Entry：0x{entry:016X}");
    }
    let _ = writeln!(text, "Size：{}", report.input.size_bytes);
    for message in &report.messages {
        let _ = writeln!(text, "{message}");
    }
    let _ = writeln!(text, "基础静态分析：");
    let _ = writeln!(text, "  Functions：{}", report.analysis.functions.len());
    for function in report.analysis.functions.iter().take(64) {
        let _ = writeln!(
            text,
            "    {:016X} {:<24} size 0x{:X} insns {} calls {}",
            function.start_va,
            function.name,
            function.size,
            function.instruction_count,
            function.call_count
        );
    }
    let _ = writeln!(text, "  Strings：{}", report.analysis.strings.len());
    let _ = writeln!(text, "  Imports：{}", report.analysis.imports.len());
    let _ = writeln!(text, "  Exports：{}", report.analysis.exports.len());
    let _ = writeln!(text, "  Relocations：{}", report.analysis.relocations.len());
    let _ = writeln!(text, "  Xrefs：{}", report.analysis.xrefs.len());
    let _ = writeln!(text, "  CFGs：{}", report.analysis.cfg_count);
    let _ = writeln!(
        text,
        "  CallGraph：{} nodes / {} edges",
        report.analysis.call_graph_nodes, report.analysis.call_graph_edges
    );
    let _ = writeln!(
        text,
        "  Pseudocode：{} functions",
        report.analysis.pseudocode_functions.len()
    );
    let _ = writeln!(
        text,
        "  RuntimeSignatures: {}",
        report.analysis.runtime_signatures.len()
    );
    if let Some(search) = &report.search {
        let _ = writeln!(
            text,
            "  Search: {} matches for `{}`",
            search.result_count, search.query
        );
    }
    for signature in report.analysis.runtime_signatures.iter().take(32) {
        let _ = writeln!(
            text,
            "    {:016X} [{}:{}] {} {} confidence {}",
            signature.address,
            signature.target,
            signature.kind,
            signature.library,
            signature.name,
            signature.confidence
        );
    }
    let _ = writeln!(text, "  PDBRecords：{}", report.analysis.pdb_records.len());
    let _ = writeln!(text, "  PDBSymbols：{}", report.analysis.pdb_symbols.len());
    let _ = writeln!(text, "  PDBTypes：{}", report.analysis.pdb_types.len());
    let _ = writeln!(text, "  TypeLibrary：{}", report.type_library.count);
    for type_item in report.type_library.types.iter().take(32) {
        let _ = writeln!(
            text,
            "    [{}] {} - {}",
            type_item.kind, type_item.name, type_item.signature
        );
    }
    text
}

fn text_summary_report(report: &HeadlessReport) -> String {
    let mut text = String::new();
    let _ = writeln!(text, "Path: {}", report.input.path);
    let _ = writeln!(text, "Kind: {}", report.input.kind);
    let _ = writeln!(text, "Functions: {}", report.analysis.functions.len());
    let _ = writeln!(text, "Strings: {}", report.analysis.strings.len());
    let _ = writeln!(text, "Imports: {}", report.analysis.imports.len());
    let _ = writeln!(text, "Exports: {}", report.analysis.exports.len());
    let _ = writeln!(text, "Xrefs: {}", report.analysis.xrefs.len());
    let _ = writeln!(
        text,
        "Pseudocode: {}",
        report.analysis.pseudocode_functions.len()
    );
    let _ = writeln!(
        text,
        "RuntimeSignatures: {}",
        report.analysis.runtime_signatures.len()
    );
    if let Some(search) = &report.search {
        let _ = writeln!(text, "SearchResults: {}", search.result_count);
    }
    let _ = writeln!(text, "TypeLibrary: {}", report.type_library.count);
    text
}

fn text_functions(functions: &[FunctionRecord]) -> String {
    let mut text = String::from("Functions\n");
    for function in functions {
        let _ = writeln!(
            text,
            "{:016X}\t{}\tsize 0x{:X}\tinsns {}\tcalls {}",
            function.start_va,
            function.name,
            function.size,
            function.instruction_count,
            function.call_count
        );
    }
    text
}

fn text_strings(strings: &[StringRecord]) -> String {
    let mut text = String::from("Strings\n");
    for string in strings {
        let _ = writeln!(
            text,
            "{:016X}\t{:08X}\t{}\t{}",
            string.address, string.file_offset, string.encoding, string.value
        );
    }
    text
}

fn text_imports(imports: &[ImportRecord]) -> String {
    let mut text = String::from("Imports\n");
    for import in imports {
        let _ = writeln!(
            text,
            "{:016X}\t{}\t{}",
            import.thunk_va, import.dll, import.display_name
        );
    }
    text
}

fn text_exports(exports: &[ExportRecord]) -> String {
    let mut text = String::from("Exports\n");
    for export in exports {
        let _ = writeln!(
            text,
            "{:016X}\t{:08X}\t{}\t{}",
            export.va, export.rva, export.ordinal, export.name
        );
    }
    text
}

fn text_xrefs(xrefs: &[XrefRecord]) -> String {
    let mut text = String::from("Xrefs\n");
    for xref in xrefs {
        let _ = writeln!(
            text,
            "{:016X}\t{:016X}\t{}\t{}",
            xref.from_va, xref.to_va, xref.kind, xref.label
        );
    }
    text
}

fn text_runtime_signatures(signatures: &[RuntimeSignatureRecord]) -> String {
    let mut text = String::from("RuntimeSignatures\n");
    for signature in signatures {
        let _ = writeln!(
            text,
            "{:016X}\t{}\t{}\t{}\t{}\tconfidence {}\t{}",
            signature.address,
            signature.name,
            signature.kind,
            signature.target,
            signature.library,
            signature.confidence,
            signature.evidence
        );
    }
    text
}

fn text_pseudocode(functions: &[PseudocodeRecord]) -> String {
    let mut text = String::from("Pseudocode\n");
    for function in functions {
        let _ = writeln!(text, "\n{:016X} {}", function.function_start, function.name);
        for (index, line) in function.lines.iter().enumerate() {
            let address = function
                .line_addresses
                .get(index)
                .copied()
                .flatten()
                .map(format_va)
                .unwrap_or_else(|| "-".to_owned());
            let _ = writeln!(text, "  {:>4} {}\t{}", index, address, line);
        }
    }
    text
}

fn text_ir(functions: &[PseudocodeRecord]) -> String {
    let mut text = String::from("IR\n");
    for function in functions {
        let _ = writeln!(text, "\n{:016X} {}", function.function_start, function.name);
        for instruction in &function.ir {
            let args = instruction.args.join(", ");
            if instruction.comment.is_empty() {
                let _ = writeln!(
                    text,
                    "  {:016X}\t{}\t{}",
                    instruction.address, instruction.op, args
                );
            } else {
                let _ = writeln!(
                    text,
                    "  {:016X}\t{}\t{}\t; {}",
                    instruction.address, instruction.op, args, instruction.comment
                );
            }
        }
    }
    text
}

fn text_types(types: &[TypeRecord]) -> String {
    let mut text = String::from("Types\n");
    for type_item in types {
        let _ = writeln!(
            text,
            "{}\t{}\t{}\t{}",
            type_item.kind, type_item.name, type_item.source, type_item.signature
        );
    }
    text
}

fn text_search(search: Option<&SearchReport>) -> String {
    let mut text = String::from("Search\n");
    let Some(search) = search else {
        let _ = writeln!(text, "No search query.");
        return text;
    };
    let _ = writeln!(
        text,
        "Query: {}\nResults: {}",
        search.query, search.result_count
    );
    if search.results.is_empty() {
        let _ = writeln!(text, "No matches.");
        return text;
    }
    for result in &search.results {
        let address = result
            .address
            .map(format_va)
            .unwrap_or_else(|| "-".to_owned());
        let _ = writeln!(
            text,
            "{}\t{}\t{}\t{}",
            result.category, address, result.label, result.snippet
        );
    }
    text
}

fn text_batch_report(report: &BatchReport) -> String {
    let mut text = String::new();
    let ok_count = report
        .files
        .iter()
        .filter(|entry| entry.status == "ok")
        .count();
    let _ = writeln!(
        text,
        "批量分析完成：{} / ok {} / errors {}",
        report.root,
        ok_count,
        report.errors.len()
    );
    for entry in &report.files {
        let _ = writeln!(
            text,
            "{}\t{}\tfunctions {}\tstrings {}\timports {}\txrefs {}\tsearch {}\t{}",
            entry.status,
            entry.path,
            entry.functions,
            entry.strings,
            entry.imports,
            entry.xrefs,
            entry.search_results,
            entry.error.as_deref().unwrap_or("")
        );
    }
    text
}

fn csv_report(report: &HeadlessReport, kind: ExportKind) -> String {
    match kind {
        ExportKind::Summary => csv_summary(report),
        ExportKind::Functions => csv_functions(&report.analysis.functions),
        ExportKind::Strings => csv_strings(&report.analysis.strings),
        ExportKind::Imports => csv_imports(&report.analysis.imports),
        ExportKind::Exports => csv_exports(&report.analysis.exports),
        ExportKind::Xrefs => csv_xrefs(&report.analysis.xrefs),
        ExportKind::RuntimeSignatures => {
            csv_runtime_signatures(&report.analysis.runtime_signatures)
        }
        ExportKind::Pseudocode => csv_pseudocode(&report.analysis.pseudocode_functions),
        ExportKind::Ir => csv_ir(&report.analysis.pseudocode_functions),
        ExportKind::Search => csv_search(report.search.as_ref()),
        ExportKind::Types => csv_types(&report.type_library.types),
        ExportKind::All => {
            let mut csv = String::new();
            csv.push_str("section,key,value\n");
            push_csv_row(&mut csv, &["summary", "path", &report.input.path]);
            push_csv_row(&mut csv, &["summary", "kind", &report.input.kind]);
            push_csv_row(
                &mut csv,
                &[
                    "summary",
                    "functions",
                    &report.analysis.functions.len().to_string(),
                ],
            );
            push_csv_row(
                &mut csv,
                &[
                    "summary",
                    "strings",
                    &report.analysis.strings.len().to_string(),
                ],
            );
            push_csv_row(
                &mut csv,
                &[
                    "summary",
                    "imports",
                    &report.analysis.imports.len().to_string(),
                ],
            );
            push_csv_row(
                &mut csv,
                &["summary", "xrefs", &report.analysis.xrefs.len().to_string()],
            );
            push_csv_row(
                &mut csv,
                &[
                    "summary",
                    "pseudocode_functions",
                    &report.analysis.pseudocode_functions.len().to_string(),
                ],
            );
            push_csv_row(
                &mut csv,
                &[
                    "summary",
                    "runtime_signatures",
                    &report.analysis.runtime_signatures.len().to_string(),
                ],
            );
            if let Some(search) = &report.search {
                push_csv_row(
                    &mut csv,
                    &[
                        "summary",
                        "search_results",
                        &search.result_count.to_string(),
                    ],
                );
            }
            push_csv_row(
                &mut csv,
                &[
                    "summary",
                    "type_library",
                    &report.type_library.count.to_string(),
                ],
            );
            csv
        }
    }
}

fn csv_summary(report: &HeadlessReport) -> String {
    let mut csv = String::from("key,value\n");
    push_csv_row(&mut csv, &["path", &report.input.path]);
    push_csv_row(&mut csv, &["kind", &report.input.kind]);
    push_csv_row(
        &mut csv,
        &["functions", &report.analysis.functions.len().to_string()],
    );
    push_csv_row(
        &mut csv,
        &["strings", &report.analysis.strings.len().to_string()],
    );
    push_csv_row(
        &mut csv,
        &["imports", &report.analysis.imports.len().to_string()],
    );
    push_csv_row(
        &mut csv,
        &["xrefs", &report.analysis.xrefs.len().to_string()],
    );
    push_csv_row(
        &mut csv,
        &[
            "pseudocode_functions",
            &report.analysis.pseudocode_functions.len().to_string(),
        ],
    );
    push_csv_row(
        &mut csv,
        &[
            "runtime_signatures",
            &report.analysis.runtime_signatures.len().to_string(),
        ],
    );
    if let Some(search) = &report.search {
        push_csv_row(
            &mut csv,
            &["search_results", &search.result_count.to_string()],
        );
    }
    push_csv_row(
        &mut csv,
        &["type_library", &report.type_library.count.to_string()],
    );
    csv
}

fn csv_functions(functions: &[FunctionRecord]) -> String {
    let mut csv = String::from("start_va,name,size,instruction_count,call_count\n");
    for function in functions {
        push_csv_row(
            &mut csv,
            &[
                &format!("{:016X}", function.start_va),
                &function.name,
                &format!("0x{:X}", function.size),
                &function.instruction_count.to_string(),
                &function.call_count.to_string(),
            ],
        );
    }
    csv
}

fn csv_strings(strings: &[StringRecord]) -> String {
    let mut csv = String::from("address,file_offset,encoding,value\n");
    for string in strings {
        push_csv_row(
            &mut csv,
            &[
                &format!("{:016X}", string.address),
                &format!("{:08X}", string.file_offset),
                &string.encoding,
                &string.value,
            ],
        );
    }
    csv
}

fn csv_imports(imports: &[ImportRecord]) -> String {
    let mut csv = String::from("thunk_va,dll,name,ordinal,hint,display_name\n");
    for import in imports {
        push_csv_row(
            &mut csv,
            &[
                &format!("{:016X}", import.thunk_va),
                &import.dll,
                import.name.as_deref().unwrap_or(""),
                &import
                    .ordinal
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                &import
                    .hint
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                &import.display_name,
            ],
        );
    }
    csv
}

fn csv_exports(exports: &[ExportRecord]) -> String {
    let mut csv = String::from("va,rva,ordinal,name\n");
    for export in exports {
        push_csv_row(
            &mut csv,
            &[
                &format!("{:016X}", export.va),
                &format!("{:08X}", export.rva),
                &export.ordinal.to_string(),
                &export.name,
            ],
        );
    }
    csv
}

fn csv_xrefs(xrefs: &[XrefRecord]) -> String {
    let mut csv = String::from("from_va,to_va,kind,label\n");
    for xref in xrefs {
        push_csv_row(
            &mut csv,
            &[
                &format!("{:016X}", xref.from_va),
                &format!("{:016X}", xref.to_va),
                &xref.kind,
                &xref.label,
            ],
        );
    }
    csv
}

fn csv_runtime_signatures(signatures: &[RuntimeSignatureRecord]) -> String {
    let mut csv = String::from("address,name,kind,target,library,evidence,confidence\n");
    for signature in signatures {
        push_csv_row(
            &mut csv,
            &[
                &format!("{:016X}", signature.address),
                &signature.name,
                &signature.kind,
                &signature.target,
                &signature.library,
                &signature.evidence,
                &signature.confidence.to_string(),
            ],
        );
    }
    csv
}

fn csv_pseudocode(functions: &[PseudocodeRecord]) -> String {
    let mut csv = String::from("function_start,function_name,line_index,address,text\n");
    for function in functions {
        for (index, line) in function.lines.iter().enumerate() {
            let address = function
                .line_addresses
                .get(index)
                .copied()
                .flatten()
                .map(format_va)
                .unwrap_or_default();
            push_csv_row(
                &mut csv,
                &[
                    &format!("{:016X}", function.function_start),
                    &function.name,
                    &index.to_string(),
                    &address,
                    line,
                ],
            );
        }
    }
    csv
}

fn csv_ir(functions: &[PseudocodeRecord]) -> String {
    let mut csv = String::from("function_start,function_name,address,op,args,comment\n");
    for function in functions {
        for instruction in &function.ir {
            push_csv_row(
                &mut csv,
                &[
                    &format!("{:016X}", function.function_start),
                    &function.name,
                    &format!("{:016X}", instruction.address),
                    &instruction.op,
                    &instruction.args.join(", "),
                    &instruction.comment,
                ],
            );
        }
    }
    csv
}

fn csv_types(types: &[TypeRecord]) -> String {
    let mut csv = String::from("name,kind,source,signature\n");
    for type_item in types {
        push_csv_row(
            &mut csv,
            &[
                &type_item.name,
                &type_item.kind,
                &type_item.source,
                &type_item.signature,
            ],
        );
    }
    csv
}

fn csv_search(search: Option<&SearchReport>) -> String {
    let mut csv = String::from("query,category,address,label,snippet\n");
    let Some(search) = search else {
        return csv;
    };
    for result in &search.results {
        let address = result.address.map(format_va).unwrap_or_default();
        push_csv_row(
            &mut csv,
            &[
                &search.query,
                &result.category,
                &address,
                &result.label,
                &result.snippet,
            ],
        );
    }
    csv
}

fn csv_batch_report(report: &BatchReport) -> String {
    let mut csv = String::from(
        "path,status,elapsed_ms,functions,strings,imports,exports,xrefs,search_results,pdb_symbols,pdb_types,error\n",
    );
    for entry in &report.files {
        push_csv_row(
            &mut csv,
            &[
                &entry.path,
                &entry.status,
                &entry.elapsed_ms.to_string(),
                &entry.functions.to_string(),
                &entry.strings.to_string(),
                &entry.imports.to_string(),
                &entry.exports.to_string(),
                &entry.xrefs.to_string(),
                &entry.search_results.to_string(),
                &entry.pdb_symbols.to_string(),
                &entry.pdb_types.to_string(),
                entry.error.as_deref().unwrap_or(""),
            ],
        );
    }
    csv
}

fn push_csv_row(csv: &mut String, cells: &[&str]) {
    for (index, cell) in cells.iter().enumerate() {
        if index > 0 {
            csv.push(',');
        }
        csv.push_str(&csv_escape(cell));
    }
    csv.push('\n');
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

fn format_va(address: u64) -> String {
    format!("{address:016X}")
}

fn collect_batch_files(root: &Path, recursive: bool) -> Result<Vec<PathBuf>, String> {
    let metadata = std::fs::metadata(root)
        .map_err(|error| format!("无法读取目录 {}：{error}", root.display()))?;
    if !metadata.is_dir() {
        return Err(format!("不是目录：{}", root.display()));
    }

    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| format!("无法枚举目录 {}：{error}", directory.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("枚举目录失败：{error}"))?;
            let path = entry.path();
            let metadata = entry
                .metadata()
                .map_err(|error| format!("无法读取 {}：{error}", path.display()))?;
            if metadata.is_file() {
                files.push(path);
            } else if recursive && metadata.is_dir() {
                stack.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

fn load_cli_types(cli: &Cli) -> Result<CliTypeLoad, String> {
    let mut types = fyida_core::builtin_type_library();
    let mut messages = Vec::new();
    if let Some(header_path) = &cli.type_header {
        let text = std::fs::read_to_string(header_path)
            .map_err(|source| format!("无法读取 C Header {}：{source}", header_path.display()))?;
        let source_name = header_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("header");
        merge_types(
            &mut types,
            fyida_core::import_c_header_types(source_name, &text),
        );
        messages.push(format!(
            "C Header 类型已导入：{} / total {}",
            header_path.display(),
            types.len()
        ));
    }

    if let Some(export_path) = &cli.export_types {
        let header = fyida_core::export_c_header_types(&types);
        std::fs::write(export_path, header)
            .map_err(|source| format!("无法导出 C Header {}：{source}", export_path.display()))?;
        messages.push(format!("C Header 类型已导出：{}", export_path.display()));
    }

    Ok(CliTypeLoad { types, messages })
}

fn merge_types(
    target: &mut Vec<fyida_core::ProjectType>,
    incoming: impl IntoIterator<Item = fyida_core::ProjectType>,
) {
    let mut by_name = target
        .drain(..)
        .map(|type_item| (type_item.name.clone(), type_item))
        .collect::<BTreeMap<_, _>>();
    for type_item in incoming {
        by_name.insert(type_item.name.clone(), type_item);
    }
    *target = by_name.into_values().collect();
}

fn raw_options(cli: &Cli) -> Result<RawLoadOptions, String> {
    let base_address =
        parse_number(&cli.base).ok_or_else(|| "base 需要是十六进制或十进制地址".to_owned())?;
    let entry_address =
        parse_number(&cli.entry).ok_or_else(|| "entry 需要是十六进制或十进制地址".to_owned())?;
    let arch = match cli.arch.trim().to_lowercase().as_str() {
        "x64" | "amd64" | "x86_64" => RawArch::X64,
        _ => return Err("当前版本 Raw Binary 仅支持 x64".to_owned()),
    };

    Ok(RawLoadOptions {
        base_address,
        entry_address,
        arch,
    })
}

fn parse_number(text: &str) -> Option<u64> {
    let text = text.trim();
    let hex = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);

    u64::from_str_radix(hex, 16)
        .ok()
        .or_else(|| text.parse::<u64>().ok())
}

fn parse_byte_pattern(text: &str) -> Option<Vec<u8>> {
    let normalized = text
        .replace("\\x", " ")
        .replace("\\X", " ")
        .replace(',', " ")
        .replace('-', " ");
    let tokens = normalized
        .split_whitespace()
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        return None;
    }

    let mut bytes = Vec::new();
    for token in tokens {
        let token = token
            .strip_prefix("0x")
            .or_else(|| token.strip_prefix("0X"))
            .unwrap_or(token);
        if token.len() > 2 || token.is_empty() || !token.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return None;
        }
        let value = u8::from_str_radix(token, 16).ok()?;
        bytes.push(value);
    }
    Some(bytes)
}

fn find_byte_pattern(bytes: &[u8], pattern: &[u8]) -> Vec<u64> {
    if pattern.is_empty() || pattern.len() > bytes.len() {
        return Vec::new();
    }
    bytes
        .windows(pattern.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == pattern).then_some(offset as u64))
        .collect()
}

fn format_byte_pattern(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_legacy_headless_file_argument() {
        let cli = Cli::try_parse_from(["fy_ida", "--headless", "sample.exe"]).unwrap();

        assert_eq!(
            cli.headless_input_file().unwrap(),
            Some(Path::new("sample.exe"))
        );
        assert_eq!(cli.gui_file(), Some(PathBuf::from("sample.exe")));
    }

    #[test]
    fn parses_headless_analyze_command() {
        let cli = Cli::try_parse_from(["fy_ida", "--headless", "analyze", "sample.exe"]).unwrap();

        assert_eq!(
            cli.headless_input_file().unwrap(),
            Some(Path::new("sample.exe"))
        );
        assert_eq!(cli.gui_file(), Some(PathBuf::from("sample.exe")));
    }

    #[test]
    fn allows_analyze_command_with_batch_dir() {
        let cli =
            Cli::try_parse_from(["fy_ida", "--headless", "analyze", "--batch-dir", "samples"])
                .unwrap();

        assert_eq!(cli.headless_input_file().unwrap(), None);
        assert_eq!(cli.batch_dir, Some(PathBuf::from("samples")));
    }

    #[test]
    fn rejects_unknown_headless_command_shape() {
        let cli = Cli::try_parse_from(["fy_ida", "--headless", "inspect", "sample.exe"]).unwrap();

        assert!(cli.headless_input_file().is_err());
    }

    #[test]
    fn parses_pseudocode_and_ir_export_kinds() {
        let pseudocode = Cli::try_parse_from([
            "fy_ida",
            "--headless",
            "--export",
            "pseudocode",
            "sample.exe",
        ])
        .unwrap();
        let ir =
            Cli::try_parse_from(["fy_ida", "--headless", "--export", "ir", "sample.exe"]).unwrap();

        assert_eq!(pseudocode.export, ExportKind::Pseudocode);
        assert_eq!(ir.export, ExportKind::Ir);
    }

    #[test]
    fn parses_search_query_and_export_kind() {
        let cli = Cli::try_parse_from([
            "fy_ida",
            "--headless",
            "--search",
            "MessageBoxW",
            "--export",
            "search",
            "sample.exe",
        ])
        .unwrap();

        assert_eq!(cli.search.as_deref(), Some("MessageBoxW"));
        assert_eq!(cli.export, ExportKind::Search);
    }

    #[test]
    fn search_report_finds_pseudocode_ir_runtime_and_types() {
        let input = sample_input_report();
        let analysis = sample_analysis_report();
        let types = sample_type_library_report();

        let search =
            build_search_report(Some("quoted"), &input, b"MZ\x90\x00", &analysis, &types).unwrap();

        assert!(
            search
                .results
                .iter()
                .any(|result| result.category == "ir"
                    && result.address == Some(0x0000_0001_4000_1004))
        );
        assert!(search
            .results
            .iter()
            .any(|result| result.category == "runtime_signature"));
        assert!(search
            .results
            .iter()
            .any(|result| result.category == "type" && result.label == "QUOTED_TYPE"));
    }

    #[test]
    fn search_report_maps_byte_pattern_offsets_to_va() {
        let input = sample_input_report();
        let analysis = sample_analysis_report();
        let types = sample_type_library_report();

        let search =
            build_search_report(Some("4D 5A"), &input, b"MZ\x90\x00", &analysis, &types).unwrap();

        assert!(search.results.iter().any(|result| {
            result.category == "bytes"
                && result.address == Some(0x0000_0001_4000_1000)
                && result.label == "FO 0x00000000"
        }));
    }

    #[test]
    fn csv_search_export_includes_category_address_label_and_snippet() {
        let search = SearchReport {
            query: "quoted".to_owned(),
            result_count: 1,
            results: vec![SearchRecord {
                category: "ir".to_owned(),
                address: Some(0x0000_0001_4000_1004),
                label: "sub_test".to_owned(),
                snippet: "ret rax ; returns, quoted \"value\"".to_owned(),
            }],
        };

        let csv = csv_search(Some(&search));

        assert!(csv.starts_with("query,category,address,label,snippet\n"));
        assert!(csv.contains(
            "quoted,ir,0000000140001004,sub_test,\"ret rax ; returns, quoted \"\"value\"\"\""
        ));
    }

    #[test]
    fn csv_pseudocode_export_includes_function_line_and_address() {
        let functions = vec![sample_pseudocode_record()];

        let csv = csv_pseudocode(&functions);

        assert!(csv.starts_with("function_start,function_name,line_index,address,text\n"));
        assert!(csv.contains("0000000140001000,sub_test,0,,uint64_t sub_test(void) {"));
        assert!(csv.contains("0000000140001000,sub_test,1,0000000140001004,return rax;"));
    }

    #[test]
    fn csv_ir_export_includes_operation_arguments_and_comments() {
        let functions = vec![sample_pseudocode_record()];

        let csv = csv_ir(&functions);

        assert!(csv.starts_with("function_start,function_name,address,op,args,comment\n"));
        assert!(csv.contains(
            "0000000140001000,sub_test,0000000140001004,ret,rax,\"returns, quoted \"\"value\"\"\""
        ));
    }

    #[test]
    fn text_ir_export_prints_function_blocks() {
        let functions = vec![sample_pseudocode_record()];

        let text = text_ir(&functions);

        assert!(text.contains("0000000140001000 sub_test"));
        assert!(text.contains("0000000140001004\tret\trax\t; returns, quoted \"value\""));
    }

    fn sample_pseudocode_record() -> PseudocodeRecord {
        PseudocodeRecord {
            function_start: 0x0000_0001_4000_1000,
            name: "sub_test".to_owned(),
            lines: vec![
                "uint64_t sub_test(void) {".to_owned(),
                "return rax;".to_owned(),
                "}".to_owned(),
            ],
            line_addresses: vec![None, Some(0x0000_0001_4000_1004), None],
            ir: vec![IrRecord {
                address: 0x0000_0001_4000_1004,
                op: "ret".to_owned(),
                args: vec!["rax".to_owned()],
                comment: "returns, quoted \"value\"".to_owned(),
            }],
        }
    }

    fn sample_input_report() -> InputReport {
        InputReport {
            path: "sample.exe".to_owned(),
            kind: "PE".to_owned(),
            size_bytes: 4,
            sha256: "test".to_owned(),
            arch: Some("x64".to_owned()),
            base_address: Some(0x0000_0001_4000_0000),
            entry_va: Some(0x0000_0001_4000_1000),
            entry_rva_or_offset: Some(0x1000),
            image_base: Some(0x0000_0001_4000_0000),
            machine: Some("x64".to_owned()),
            subsystem: Some("console".to_owned()),
            sections: vec![SectionReport {
                name: ".text".to_owned(),
                rva: 0x1000,
                va: 0x0000_0001_4000_1000,
                file_offset: 0,
                virtual_size: 4,
                raw_size: 4,
                permissions: "R-X".to_owned(),
            }],
        }
    }

    fn sample_analysis_report() -> AnalysisReport {
        AnalysisReport {
            functions: vec![FunctionRecord {
                start_va: 0x0000_0001_4000_1000,
                name: "sub_test".to_owned(),
                size: 0x10,
                instruction_count: 3,
                call_count: 1,
            }],
            strings: vec![StringRecord {
                address: 0x0000_0001_4000_2000,
                file_offset: 0x200,
                encoding: "ASCII".to_owned(),
                value: "MessageBoxW quoted".to_owned(),
            }],
            imports: vec![ImportRecord {
                thunk_va: 0x0000_0001_4000_3000,
                thunk_rva: 0x3000,
                dll: "USER32.dll".to_owned(),
                name: Some("MessageBoxW".to_owned()),
                ordinal: None,
                hint: Some(1),
                display_name: "USER32.dll!MessageBoxW".to_owned(),
            }],
            exports: Vec::new(),
            relocations: Vec::new(),
            xrefs: vec![XrefRecord {
                from_va: 0x0000_0001_4000_1004,
                to_va: 0x0000_0001_4000_3000,
                kind: "call".to_owned(),
                label: "quoted import".to_owned(),
            }],
            cfg_count: 1,
            call_graph_nodes: 1,
            call_graph_edges: 1,
            pseudocode_functions: vec![sample_pseudocode_record()],
            runtime_signatures: vec![RuntimeSignatureRecord {
                address: 0x0000_0001_4000_1000,
                name: "sub_test".to_owned(),
                kind: "user signature".to_owned(),
                target: "function".to_owned(),
                library: "test".to_owned(),
                evidence: "quoted evidence".to_owned(),
                confidence: 80,
            }],
            pdb_records: Vec::new(),
            pdb_symbols: Vec::new(),
            pdb_types: Vec::new(),
        }
    }

    fn sample_type_library_report() -> TypeLibraryReport {
        TypeLibraryReport {
            count: 1,
            types: vec![TypeRecord {
                name: "QUOTED_TYPE".to_owned(),
                kind: "typedef".to_owned(),
                source: "test".to_owned(),
                signature: "typedef int QUOTED_TYPE;".to_owned(),
            }],
        }
    }
}
