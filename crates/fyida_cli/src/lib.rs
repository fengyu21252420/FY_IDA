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
    long_about = "FY_IDA 是面向 Windows x64 PE / Raw Binary 的轻量逆向分析工具。当前 v0.16.0-alpha.1 已提供 `--headless analyze <FILE>`、本地 JSON 签名库导入、运行库签名识别、GUI 运行库函数过滤、基础 x64 伪 C/IR 输出、Python 脚本 API、headless JSON/CSV 导出和基础静态分析。"
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
    Types,
}

#[derive(Debug, Serialize)]
struct HeadlessReport {
    version: String,
    input: InputReport,
    analysis: AnalysisReport,
    type_library: TypeLibraryReport,
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
        let mut report = HeadlessReport {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            input: raw_input_report(&loaded.image, &loaded.bytes),
            analysis: analysis_report(&analysis),
            type_library: type_library_report(&type_load.types),
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

    let mut report = HeadlessReport {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        input: pe_input_report(&loaded.image, &loaded.bytes),
        analysis: analysis_report(&analysis),
        type_library: type_library_report(&type_load.types),
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

fn emit_single_report(cli: &Cli, report: &HeadlessReport) -> Result<(), String> {
    let encoded = match cli.export_format {
        ExportFormat::Text => text_report(report),
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

fn text_report(report: &HeadlessReport) -> String {
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
            "{}\t{}\tfunctions {}\tstrings {}\timports {}\txrefs {}\t{}",
            entry.status,
            entry.path,
            entry.functions,
            entry.strings,
            entry.imports,
            entry.xrefs,
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
                    "runtime_signatures",
                    &report.analysis.runtime_signatures.len().to_string(),
                ],
            );
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
            "runtime_signatures",
            &report.analysis.runtime_signatures.len().to_string(),
        ],
    );
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

fn csv_batch_report(report: &BatchReport) -> String {
    let mut csv = String::from(
        "path,status,elapsed_ms,functions,strings,imports,exports,xrefs,pdb_symbols,pdb_types,error\n",
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
}
