use std::collections::{BTreeSet, VecDeque};
use std::path::PathBuf;
use std::process::Command;

use eframe::egui::{
    self, Align, CentralPanel, Color32, Context, DragValue, FontData, FontDefinitions, FontFamily,
    Frame, Grid, Key, Layout, RichText, ScrollArea, SidePanel, Stroke, TextEdit, TopBottomPanel,
    Ui, Visuals, Window,
};
use fyida_analysis::{
    analyze_pe, analyze_raw, apply_pdb_file, apply_pdb_snapshot, apply_signature_library,
    empty_workspace_disassembly, file_error_log_lines, load_signature_library_file,
    pdb_candidate_paths, pe_entry_disassembly, pe_loaded_log_lines, raw_entry_disassembly,
    raw_loaded_log_lines, startup_log_lines, static_analysis_log_lines, DisassemblyRow,
    LoadedPdbInfo, PdbSourceFile as AnalysisPdbSourceFile, PdbSymbol, PdbSymbolKind,
    PdbTypeSummary, RuntimeSignature, RuntimeSignatureTarget, SignatureLibrary, StaticAnalysis,
};
use fyida_core::{
    export_c_header_types, format_address, import_c_header_types, sha256_hex, EnumVariant,
    FileSelection, ManualDefinitionKind, ProjectDebugInfo, ProjectDocument, ProjectFunction,
    ProjectInput, ProjectInputKind, ProjectSourceFile as ProjectSourceFileRecord, ProjectState,
    ProjectSymbol, ProjectType, ProjectTypeTarget, RawArch, RawImage, TypeDefinition, TypeField,
    APP_NAME,
};
use fyida_loader::{
    load_file_metadata, load_pe_file_with_bytes, load_pe_from_selection_with_bytes,
    load_raw_file_with_bytes, load_raw_from_selection_with_bytes, RawLoadOptions,
};
use rfd::FileDialog;

const LEFT_TABS: [&str; 7] = ["函数", "名称", "字符串", "导入", "导出", "段", "书签"];
const CENTER_TABS: [&str; 6] = [
    "反汇编",
    "十六进制",
    "伪代码",
    "函数图",
    "调用图",
    "IR 视图",
];
const RIGHT_TABS: [&str; 5] = ["交叉引用", "属性", "局部类型", "结构体", "注释"];
const BOTTOM_TABS: [&str; 5] = ["输出", "搜索结果", "Python 控制台", "日志", "任务"];

pub fn run(initial_file: Option<PathBuf>) -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([960.0, 620.0]),
        ..Default::default()
    };

    eframe::run_native(
        "FY_IDA - 中文逆向分析工作台",
        options,
        Box::new(move |creation_context| {
            Box::new(FyIdaApp::new(creation_context, initial_file.clone()))
        }),
    )
}

struct FyIdaApp {
    project: ProjectState,
    left_tab: usize,
    center_tab: usize,
    right_tab: usize,
    bottom_tab: usize,
    left_filter: String,
    quick_jump_open: bool,
    quick_jump_text: String,
    search_open: bool,
    search_text: String,
    graph_zoom: f32,
    graph_pan_x: f32,
    graph_pan_y: f32,
    raw_dialog_open: bool,
    pending_raw_selection: Option<FileSelection>,
    raw_base_text: String,
    raw_entry_text: String,
    raw_arch_text: String,
    raw_error_text: String,
    rename_open: bool,
    rename_text: String,
    comment_open: bool,
    comment_text: String,
    python_code: String,
    python_output: String,
    type_editor_open: bool,
    type_editor_kind: TypeEditorKind,
    type_name_text: String,
    type_body_text: String,
    type_error_text: String,
    type_apply_open: bool,
    type_apply_name: String,
    project_path: Option<PathBuf>,
    source_hash: Option<String>,
    input_bytes: Vec<u8>,
    logs: Vec<String>,
    search_results: Vec<SearchResult>,
    disassembly_rows: Vec<DisassemblyRow>,
    analysis: Option<StaticAnalysis>,
    signature_libraries: Vec<SignatureLibrary>,
    hide_runtime_library_functions: bool,
    recent_files: VecDeque<PathBuf>,
}

enum ProjectLoadResult {
    Pe(fyida_core::PeImage, Vec<u8>),
    Raw(RawImage, Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypeEditorKind {
    Struct,
    Enum,
    Function,
}

impl TypeEditorKind {
    fn title(self) -> &'static str {
        match self {
            Self::Struct => "新建结构体",
            Self::Enum => "新建枚举",
            Self::Function => "编辑函数原型",
        }
    }

    fn default_body(self) -> &'static str {
        match self {
            Self::Struct => "DWORD flags\nuint8_t key[16]",
            Self::Enum => "MODE_A = 0\nMODE_B = 1",
            Self::Function => "int __cdecl function_name(void *context)",
        }
    }
}

#[derive(Debug, Clone)]
struct SearchResult {
    label: String,
    address: Option<u64>,
    context: Option<String>,
}

impl SearchResult {
    fn plain(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            address: None,
            context: None,
        }
    }

    fn jump(label: impl Into<String>, address: u64, context: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            address: Some(address),
            context: Some(context.into()),
        }
    }
}

impl FyIdaApp {
    fn new(creation_context: &eframe::CreationContext<'_>, initial_file: Option<PathBuf>) -> Self {
        configure_fonts(&creation_context.egui_ctx);
        configure_style(&creation_context.egui_ctx);

        let mut app = Self {
            project: ProjectState::default(),
            left_tab: 0,
            center_tab: 0,
            right_tab: 0,
            bottom_tab: 0,
            left_filter: String::new(),
            quick_jump_open: false,
            quick_jump_text: String::new(),
            search_open: false,
            search_text: String::new(),
            graph_zoom: 1.0,
            graph_pan_x: 0.0,
            graph_pan_y: 0.0,
            raw_dialog_open: false,
            pending_raw_selection: None,
            raw_base_text: "0x140000000".to_owned(),
            raw_entry_text: "0x140000000".to_owned(),
            raw_arch_text: "x64".to_owned(),
            raw_error_text: String::new(),
            rename_open: false,
            rename_text: String::new(),
            comment_open: false,
            comment_text: String::new(),
            python_code: "import os\nprint('FY_IDA file:', os.environ.get('FYIDA_SELECTED_FILE', '-'))\nprint('Current VA:', os.environ.get('FYIDA_CURRENT_VA', '-'))".to_owned(),
            python_output: "Python 控制台待运行。".to_owned(),
            type_editor_open: false,
            type_editor_kind: TypeEditorKind::Struct,
            type_name_text: String::new(),
            type_body_text: TypeEditorKind::Struct.default_body().to_owned(),
            type_error_text: String::new(),
            type_apply_open: false,
            type_apply_name: String::new(),
            project_path: None,
            source_hash: None,
            input_bytes: Vec::new(),
            logs: startup_log_lines(),
            search_results: vec![SearchResult::plain("尚未执行搜索。")],
            disassembly_rows: empty_workspace_disassembly(),
            analysis: None,
            signature_libraries: Vec::new(),
            hide_runtime_library_functions: false,
            recent_files: VecDeque::new(),
        };

        if let Some(path) = initial_file {
            app.select_path(path);
        }

        app
    }

    fn open_file_dialog(&mut self) {
        if let Some(path) = FileDialog::new()
            .set_title("打开文件")
            .add_filter("可执行文件与二进制", &["exe", "dll", "sys", "bin", "dat"])
            .add_filter("所有文件", &["*"])
            .pick_file()
        {
            self.select_path(path);
        }
    }

    fn open_raw_file_dialog(&mut self) {
        if let Some(path) = FileDialog::new()
            .set_title("打开 Raw Binary")
            .add_filter("Raw Binary", &["bin", "dat", "raw", "dump"])
            .add_filter("所有文件", &["*"])
            .pick_file()
        {
            match load_file_metadata(&path) {
                Ok(selection) => {
                    self.pending_raw_selection = Some(selection);
                    self.raw_dialog_open = true;
                    self.raw_error_text.clear();
                    if self.raw_base_text.trim().is_empty() {
                        self.raw_base_text = "0x140000000".to_owned();
                    }
                    if self.raw_entry_text.trim().is_empty() {
                        self.raw_entry_text = self.raw_base_text.clone();
                    }
                }
                Err(error) => {
                    let message = error.to_string();
                    self.project.set_error(message.clone());
                    self.disassembly_rows = file_error_disassembly_row(&message);
                    self.analysis = None;
                    self.source_hash = None;
                    self.input_bytes.clear();
                    self.project_path = None;
                    self.logs.push(message);
                    self.right_tab = 1;
                    self.bottom_tab = 0;
                }
            }
        }
    }

    fn open_pdb_dialog(&mut self) {
        if let Some(path) = FileDialog::new()
            .set_title("加载 PDB")
            .add_filter("Program Database", &["pdb"])
            .add_filter("所有文件", &["*"])
            .pick_file()
        {
            self.apply_pdb_path(path);
        }
    }

    fn open_signature_library_dialog(&mut self) {
        if let Some(path) = FileDialog::new()
            .set_title("导入签名库")
            .add_filter("FY_IDA 签名库", &["json"])
            .add_filter("所有文件", &["*"])
            .pick_file()
        {
            match load_signature_library_file(&path) {
                Ok(library) => {
                    let mut applied = 0usize;
                    if let Some(analysis) = self.analysis.as_mut() {
                        applied = apply_signature_library(analysis, &library);
                    }
                    self.logs.push(format!(
                        "签名库已导入：{}（规则 {}，当前命中 {}）",
                        library.name,
                        library.rules.len(),
                        applied
                    ));
                    self.signature_libraries.push(library);
                    self.left_tab = 1;
                    self.bottom_tab = 0;
                }
                Err(error) => {
                    self.logs
                        .push(format!("签名库导入失败：{} ({error})", path.display()));
                    self.bottom_tab = 0;
                }
            }
        }
    }

    fn open_project_dialog(&mut self) {
        if let Some(path) = FileDialog::new()
            .set_title("打开项目")
            .add_filter("FY_IDA 项目", &["json"])
            .add_filter("所有文件", &["*"])
            .pick_file()
        {
            match ProjectDocument::load_from_path(&path) {
                Ok(document) => self.apply_project_document(path, document),
                Err(error) => {
                    self.logs.push(error.to_string());
                    self.bottom_tab = 0;
                }
            }
        }
    }

    fn save_project(&mut self) {
        if let Some(path) = self.project_path.clone() {
            self.save_project_to(path);
        } else {
            self.save_project_as_dialog();
        }
    }

    fn save_project_as_dialog(&mut self) {
        if let Some(path) = FileDialog::new()
            .set_title("项目另存为")
            .add_filter("FY_IDA 项目", &["fyida.json", "json"])
            .set_file_name("analysis.fyida.json")
            .save_file()
        {
            self.save_project_to(path);
        }
    }

    fn save_project_to(&mut self, path: PathBuf) {
        match self.current_project_document() {
            Ok(document) => match document.save_to_path(&path) {
                Ok(()) => {
                    self.project_path = Some(path.clone());
                    self.project.mark_saved();
                    self.logs.push(format!("项目已保存：{}", path.display()));
                    self.bottom_tab = 0;
                }
                Err(error) => {
                    self.logs.push(error.to_string());
                    self.bottom_tab = 0;
                }
            },
            Err(message) => {
                self.logs.push(format!("项目保存失败：{message}"));
                self.bottom_tab = 0;
            }
        }
    }

    fn current_project_document(&self) -> Result<ProjectDocument, String> {
        let selection = self
            .project
            .selected_file()
            .ok_or_else(|| "尚未打开 PE 或 Raw Binary 文件。".to_owned())?;
        let sha256 = self
            .source_hash
            .clone()
            .ok_or_else(|| "当前文件缺少 hash，无法保存项目。".to_owned())?;
        let kind = if self.project.pe_image().is_some() {
            ProjectInputKind::Pe
        } else if let Some(raw) = self.project.raw_image() {
            ProjectInputKind::Raw {
                base_address: raw.base_address,
                entry_address: raw.entry_address,
                arch: raw.arch,
            }
        } else {
            return Err("当前输入不是可保存的 PE 或 Raw Binary。".to_owned());
        };
        let functions = self
            .analysis
            .as_ref()
            .map(|analysis| {
                analysis
                    .functions
                    .iter()
                    .map(|function| ProjectFunction {
                        start_va: function.start_va,
                        name: self
                            .project
                            .name_for(function.start_va)
                            .unwrap_or(&function.name)
                            .to_owned(),
                        size: function.size,
                        instruction_count: function.instruction_count,
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let (debug_info, symbols, pdb_types, source_files) = self.current_pdb_project_snapshot();
        let mut types = self.project.project_types();
        merge_project_type_records(&mut types, pdb_types);
        let type_applications = self.project.type_applications();

        Ok(ProjectDocument::new(
            env!("CARGO_PKG_VERSION"),
            ProjectInput {
                path: selection.path().display().to_string(),
                size_bytes: selection.size_bytes(),
                sha256,
                kind,
            },
            functions,
            debug_info,
            symbols,
            types,
            type_applications,
            source_files,
            self.project.annotations(),
        ))
    }

    fn current_pdb_project_snapshot(
        &self,
    ) -> (
        Option<ProjectDebugInfo>,
        Vec<ProjectSymbol>,
        Vec<ProjectType>,
        Vec<ProjectSourceFileRecord>,
    ) {
        let Some(analysis) = &self.analysis else {
            return (None, Vec::new(), Vec::new(), Vec::new());
        };

        let pe_record = analysis.pe_pdb_records.first();
        let loaded = analysis.loaded_pdb.as_ref();
        let debug_info = if pe_record.is_some() || loaded.is_some() {
            Some(ProjectDebugInfo {
                pe_pdb_path: pe_record.map(|record| record.path.clone()),
                pe_pdb_guid: pe_record.and_then(|record| record.guid.clone()),
                pe_pdb_age: pe_record.and_then(|record| record.age),
                loaded_pdb_path: loaded.map(|info| info.path.clone()),
                loaded_pdb_guid: loaded.and_then(|info| info.guid.clone()),
                loaded_pdb_age: loaded.map(|info| info.age),
                matched: loaded.and_then(|info| info.matched_pe),
            })
        } else {
            None
        };
        let symbols = analysis
            .pdb_symbols
            .iter()
            .map(|symbol| ProjectSymbol {
                address: symbol.address,
                rva: symbol.rva,
                name: symbol.display_name().to_owned(),
                original_name: symbol.name.clone(),
                kind: symbol.kind.label().to_owned(),
                source: symbol.source.clone(),
            })
            .collect::<Vec<_>>();
        let types = analysis
            .pdb_types
            .iter()
            .map(|type_item| ProjectType {
                name: type_item.name.clone(),
                kind: type_item.kind.clone(),
                source: type_item.source.clone(),
                definition: None,
            })
            .collect::<Vec<_>>();
        let source_files = analysis
            .pdb_sources
            .iter()
            .map(|source| ProjectSourceFileRecord {
                path: source.path.clone(),
            })
            .collect::<Vec<_>>();

        (debug_info, symbols, types, source_files)
    }

    fn apply_project_document(&mut self, project_path: PathBuf, document: ProjectDocument) {
        let input_path = PathBuf::from(&document.input.path);
        let expected_hash = document.input.sha256.clone();
        let load_result = match document.input.kind.clone() {
            ProjectInputKind::Pe => load_pe_file_with_bytes(&input_path)
                .map(|loaded| ProjectLoadResult::Pe(loaded.image, loaded.bytes)),
            ProjectInputKind::Raw {
                base_address,
                entry_address,
                arch,
            } => load_raw_file_with_bytes(
                &input_path,
                RawLoadOptions {
                    base_address,
                    entry_address,
                    arch,
                },
            )
            .map(|loaded| ProjectLoadResult::Raw(loaded.image, loaded.bytes)),
        };

        match load_result {
            Ok(ProjectLoadResult::Pe(image, bytes)) => {
                let actual_hash = sha256_hex(&bytes);
                self.apply_pe_image(image, &bytes);
                self.finish_project_document_load(
                    project_path,
                    document,
                    actual_hash,
                    expected_hash,
                );
            }
            Ok(ProjectLoadResult::Raw(image, bytes)) => {
                let actual_hash = sha256_hex(&bytes);
                self.apply_raw_image(image, &bytes);
                self.finish_project_document_load(
                    project_path,
                    document,
                    actual_hash,
                    expected_hash,
                );
            }
            Err(error) => {
                self.logs.push(format!(
                    "打开项目失败，无法加载原始文件 {}：{error}",
                    input_path.display()
                ));
                self.bottom_tab = 0;
            }
        }
    }

    fn finish_project_document_load(
        &mut self,
        project_path: PathBuf,
        document: ProjectDocument,
        actual_hash: String,
        expected_hash: String,
    ) {
        let saved_debug_info = document.debug_info.clone();
        let saved_symbols = document.symbols.clone();
        let saved_types = document.types.clone();
        let saved_type_applications = document.type_applications.clone();
        let saved_sources = document.source_files.clone();
        self.project.apply_annotations(document.annotations);
        self.project.replace_project_types(saved_types.clone());
        self.project
            .replace_type_applications(saved_type_applications);
        let pdb_snapshot_types = saved_types
            .into_iter()
            .filter(is_pdb_project_type)
            .collect::<Vec<_>>();
        self.apply_project_pdb_snapshot(
            saved_debug_info,
            saved_symbols,
            pdb_snapshot_types,
            saved_sources,
        );
        self.project_path = Some(project_path.clone());
        self.source_hash = Some(actual_hash.clone());
        self.project.mark_saved();
        if actual_hash != expected_hash {
            self.logs.push(format!(
                "项目已打开，但原始文件 hash 不一致：期望 {expected_hash}，实际 {actual_hash}"
            ));
        }
        self.logs
            .push(format!("项目已打开：{}", project_path.display()));
        self.bottom_tab = 0;
    }

    fn apply_project_pdb_snapshot(
        &mut self,
        debug_info: Option<ProjectDebugInfo>,
        symbols: Vec<ProjectSymbol>,
        types: Vec<ProjectType>,
        sources: Vec<ProjectSourceFileRecord>,
    ) {
        if symbols.is_empty() && types.is_empty() && sources.is_empty() {
            return;
        }
        let Some(analysis) = self.analysis.as_mut() else {
            return;
        };

        let loaded = debug_info.and_then(|info| {
            info.loaded_pdb_path.map(|path| LoadedPdbInfo {
                path,
                guid: info.loaded_pdb_guid,
                age: info.loaded_pdb_age.unwrap_or(0),
                signature: 0,
                matched_pe: info.matched,
            })
        });
        let symbols = symbols
            .into_iter()
            .map(|symbol| {
                let demangled_name =
                    (symbol.name != symbol.original_name).then_some(symbol.name.clone());
                PdbSymbol {
                    address: symbol.address,
                    rva: symbol.rva,
                    name: symbol.original_name,
                    demangled_name,
                    kind: pdb_symbol_kind_from_label(&symbol.kind),
                    source: symbol.source,
                }
            })
            .collect::<Vec<_>>();
        let types = types
            .into_iter()
            .map(|type_item| PdbTypeSummary {
                name: type_item.name,
                kind: type_item.kind,
                source: type_item.source,
            })
            .collect::<Vec<_>>();
        let sources = sources
            .into_iter()
            .map(|source| AnalysisPdbSourceFile { path: source.path })
            .collect::<Vec<_>>();
        apply_pdb_snapshot(analysis, loaded, symbols, types, sources);
        self.logs.push("已从项目文件恢复 PDB 符号快照。".to_owned());
    }

    fn select_path(&mut self, path: PathBuf) {
        match load_file_metadata(&path) {
            Ok(selection) => self.load_selected_file(selection),
            Err(error) => {
                let message = error.to_string();
                self.project.set_error(message.clone());
                self.disassembly_rows = file_error_disassembly_row(&message);
                self.analysis = None;
                self.source_hash = None;
                self.input_bytes.clear();
                self.project_path = None;
                self.logs.push(message);
                self.right_tab = 1;
                self.bottom_tab = 0;
            }
        }
    }

    fn load_selected_file(&mut self, selection: FileSelection) {
        self.add_recent_file(selection.path().to_path_buf());

        match load_pe_from_selection_with_bytes(selection.clone()) {
            Ok(loaded) => self.apply_pe_image(loaded.image, &loaded.bytes),
            Err(error) => self.apply_file_error(selection, error.to_string()),
        }
    }

    fn load_raw_selected_file(&mut self, selection: FileSelection, options: RawLoadOptions) {
        self.add_recent_file(selection.path().to_path_buf());

        match load_raw_from_selection_with_bytes(selection.clone(), options) {
            Ok(loaded) => self.apply_raw_image(loaded.image, &loaded.bytes),
            Err(error) => self.apply_file_error(selection, error.to_string()),
        }
    }

    fn apply_loaded_signature_libraries(&self, analysis: &mut StaticAnalysis) -> Vec<String> {
        self.signature_libraries
            .iter()
            .map(|library| {
                let count = apply_signature_library(analysis, library);
                format!(
                    "签名库应用：{}（规则 {}，命中 {}）",
                    library.name,
                    library.rules.len(),
                    count
                )
            })
            .collect()
    }

    fn apply_pe_image(&mut self, image: fyida_core::PeImage, bytes: &[u8]) {
        let mut analysis = analyze_pe(&image, bytes);
        let pdb_logs = self.try_autoload_pdb(&image, &mut analysis);
        let signature_logs = self.apply_loaded_signature_libraries(&mut analysis);
        let disassembly = pe_entry_disassembly(&image, bytes);
        self.source_hash = Some(sha256_hex(bytes));
        self.input_bytes = bytes.to_vec();
        self.project_path = None;
        self.logs.extend(pe_loaded_log_lines(&image));
        self.logs.extend(static_analysis_log_lines(&analysis));
        self.logs.extend(pdb_logs);
        self.logs.extend(signature_logs);
        self.logs.extend(disassembly.log_lines);
        self.disassembly_rows = disassembly.rows;
        self.analysis = Some(analysis);
        self.project.load_pe(image);
        self.sync_pdb_types_to_project();
        self.center_tab = 0;
        self.right_tab = 1;
        self.bottom_tab = 0;
    }

    fn try_autoload_pdb(
        &self,
        image: &fyida_core::PeImage,
        analysis: &mut StaticAnalysis,
    ) -> Vec<String> {
        for path in pdb_candidate_paths(image, analysis) {
            if !path.is_file() {
                continue;
            }
            return match apply_pdb_file(image, analysis, &path) {
                Ok(summary) => vec![format!(
                    "自动加载 PDB：{}（符号 {}，类型 {}，来源 {}）",
                    summary.loaded.path,
                    summary.symbol_count,
                    summary.type_count,
                    summary.source_count
                )],
                Err(error) => vec![format!("自动加载 PDB 失败：{} ({error})", path.display())],
            };
        }

        analysis
            .pe_pdb_records
            .first()
            .map(|record| {
                vec![format!(
                    "发现 PE PDB 线索：{}，本机未自动找到文件。",
                    record.path
                )]
            })
            .unwrap_or_default()
    }

    fn apply_pdb_path(&mut self, path: PathBuf) {
        let Some(image) = self.project.pe_image().cloned() else {
            self.logs
                .push("加载 PDB 失败：请先打开 Windows PE 文件。".to_owned());
            self.bottom_tab = 0;
            return;
        };
        let Some(analysis) = self.analysis.as_mut() else {
            self.logs
                .push("加载 PDB 失败：当前没有可更新的分析结果。".to_owned());
            self.bottom_tab = 0;
            return;
        };

        match apply_pdb_file(&image, analysis, &path) {
            Ok(summary) => {
                self.logs.push(format!(
                    "PDB 已加载：{}（符号 {}，类型 {}，来源 {}，匹配 {}）",
                    summary.loaded.path,
                    summary.symbol_count,
                    summary.type_count,
                    summary.source_count,
                    match summary.loaded.matched_pe {
                        Some(true) => "是",
                        Some(false) => "否",
                        None => "未知",
                    }
                ));
                for library in &self.signature_libraries {
                    let count = apply_signature_library(analysis, library);
                    self.logs.push(format!(
                        "签名库应用：{}（规则 {}，命中 {}）",
                        library.name,
                        library.rules.len(),
                        count
                    ));
                }
                self.sync_pdb_types_to_project();
                self.left_tab = 1;
                self.right_tab = 2;
            }
            Err(error) => {
                self.logs
                    .push(format!("加载 PDB 失败：{} ({error})", path.display()));
            }
        }
        self.bottom_tab = 0;
    }

    fn apply_raw_image(&mut self, image: RawImage, bytes: &[u8]) {
        let mut analysis = analyze_raw(&image, bytes);
        let signature_logs = self.apply_loaded_signature_libraries(&mut analysis);
        let disassembly = raw_entry_disassembly(&image, bytes);
        self.source_hash = Some(sha256_hex(bytes));
        self.input_bytes = bytes.to_vec();
        self.project_path = None;
        self.logs.extend(raw_loaded_log_lines(&image));
        self.logs.extend(static_analysis_log_lines(&analysis));
        self.logs.extend(signature_logs);
        self.logs.extend(disassembly.log_lines);
        self.disassembly_rows = disassembly.rows;
        self.analysis = Some(analysis);
        self.project.load_raw(image);
        self.center_tab = 0;
        self.right_tab = 1;
        self.bottom_tab = 0;
    }

    fn apply_file_error(&mut self, selection: FileSelection, message: String) {
        self.logs.extend(file_error_log_lines(&selection, &message));
        self.project.set_file_error(selection, message);
        self.disassembly_rows =
            file_error_disassembly_row("不是有效的 PE 文件，无法进行 x64 反汇编。");
        self.analysis = None;
        self.source_hash = None;
        self.input_bytes.clear();
        self.project_path = None;
        self.center_tab = 0;
        self.right_tab = 1;
        self.bottom_tab = 0;
    }

    fn add_recent_file(&mut self, path: PathBuf) {
        self.recent_files.retain(|existing| existing != &path);
        self.recent_files.push_front(path);
        while self.recent_files.len() > 8 {
            self.recent_files.pop_back();
        }
    }

    fn open_rename_dialog(&mut self) {
        let Some(address) = self.project.current_address() else {
            self.logs.push("重命名失败：尚未选择地址。".to_owned());
            return;
        };
        self.rename_text = self
            .project
            .name_for(address)
            .or_else(|| self.project.current_function())
            .unwrap_or("")
            .to_owned();
        self.rename_open = true;
    }

    fn open_comment_dialog(&mut self) {
        let Some(address) = self.project.current_address() else {
            self.logs.push("添加注释失败：尚未选择地址。".to_owned());
            return;
        };
        self.comment_text = self
            .project
            .address_comment(address)
            .unwrap_or("")
            .to_owned();
        self.comment_open = true;
    }

    fn open_type_editor(&mut self, kind: TypeEditorKind) {
        self.type_editor_kind = kind;
        self.type_error_text.clear();
        self.type_name_text = match kind {
            TypeEditorKind::Struct => "CONFIG".to_owned(),
            TypeEditorKind::Enum => "MODE".to_owned(),
            TypeEditorKind::Function => self
                .current_function_start()
                .and_then(|address| {
                    self.project
                        .name_for(address)
                        .map(str::to_owned)
                        .or_else(|| {
                            self.analysis.as_ref().and_then(|analysis| {
                                analysis
                                    .functions
                                    .iter()
                                    .find(|function| function.start_va == address)
                                    .map(|function| function.name.clone())
                            })
                        })
                })
                .unwrap_or_else(|| "function_name".to_owned()),
        };
        self.type_body_text = match kind {
            TypeEditorKind::Function => format!("int __cdecl {}(void)", self.type_name_text),
            _ => kind.default_body().to_owned(),
        };
        self.type_editor_open = true;
    }

    fn open_type_apply_dialog(&mut self) {
        let Some(target) = self.current_type_target() else {
            self.logs
                .push("应用类型失败：尚未选择地址或函数。".to_owned());
            return;
        };
        self.type_apply_name = self
            .project
            .applied_type(target)
            .map(str::to_owned)
            .or_else(|| {
                self.project
                    .project_types()
                    .into_iter()
                    .find(|type_item| {
                        !type_item.source.starts_with("builtin:")
                            && matches!(
                                type_item.definition,
                                Some(TypeDefinition::Struct { .. })
                                    | Some(TypeDefinition::Union { .. })
                                    | Some(TypeDefinition::Enum { .. })
                                    | Some(TypeDefinition::Function { .. })
                            )
                    })
                    .map(|type_item| type_item.name)
            })
            .unwrap_or_default();
        self.type_apply_open = true;
    }

    fn commit_type_editor(&mut self) {
        match self.build_type_from_editor() {
            Ok(type_item) => {
                let type_name = type_item.name.clone();
                self.project.upsert_project_type(type_item);
                if self.type_editor_kind == TypeEditorKind::Function {
                    if let Some(function_start) = self.current_function_start() {
                        self.project.apply_type_to_target(
                            ProjectTypeTarget::Function(function_start),
                            type_name.clone(),
                        );
                    }
                }
                self.logs.push(format!("已更新类型：{type_name}"));
                self.type_editor_open = false;
                self.right_tab = 2;
                self.bottom_tab = 0;
            }
            Err(message) => {
                self.type_error_text = message;
            }
        }
    }

    fn build_type_from_editor(&self) -> Result<ProjectType, String> {
        match self.type_editor_kind {
            TypeEditorKind::Struct => {
                let name = require_type_name(&self.type_name_text)?;
                Ok(ProjectType::with_definition(
                    name,
                    "user",
                    TypeDefinition::Struct {
                        fields: parse_type_fields(&self.type_body_text)?,
                    },
                ))
            }
            TypeEditorKind::Enum => {
                let name = require_type_name(&self.type_name_text)?;
                Ok(ProjectType::with_definition(
                    name,
                    "user",
                    TypeDefinition::Enum {
                        variants: parse_enum_variants(&self.type_body_text)?,
                    },
                ))
            }
            TypeEditorKind::Function => {
                let prototype = self.type_body_text.trim();
                if prototype.is_empty() {
                    return Err("函数原型不能为空。".to_owned());
                }
                let imported = import_c_header_types("prototype", &format!("{prototype};"));
                let mut type_item = imported
                    .into_iter()
                    .find(|item| matches!(item.definition, Some(TypeDefinition::Function { .. })))
                    .ok_or_else(|| {
                        "无法解析函数原型，请使用类似 int __cdecl fn(void)。".to_owned()
                    })?;
                let explicit_name = self.type_name_text.trim();
                if !explicit_name.is_empty() {
                    type_item.name = explicit_name.to_owned();
                }
                type_item.source = "user".to_owned();
                Ok(type_item)
            }
        }
    }

    fn import_c_header_dialog(&mut self) {
        if let Some(path) = FileDialog::new()
            .add_filter("C Header", &["h", "hpp", "hh"])
            .pick_file()
        {
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    let source = path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("header");
                    let types = import_c_header_types(source, &text);
                    let count = self.project.upsert_project_types(types);
                    self.logs.push(format!(
                        "已导入 C Header：{}，类型 {} 个",
                        path.display(),
                        count
                    ));
                    self.right_tab = 2;
                    self.bottom_tab = 0;
                }
                Err(error) => {
                    self.logs
                        .push(format!("导入 C Header 失败：{} ({error})", path.display()));
                    self.bottom_tab = 0;
                }
            }
        }
    }

    fn export_c_header_dialog(&mut self) {
        if let Some(path) = FileDialog::new()
            .set_file_name("fyida_types.h")
            .add_filter("C Header", &["h"])
            .save_file()
        {
            let header = export_c_header_types(&self.project.project_types());
            match std::fs::write(&path, header) {
                Ok(()) => {
                    self.logs
                        .push(format!("已导出 C Header：{}", path.display()));
                    self.bottom_tab = 0;
                }
                Err(error) => {
                    self.logs
                        .push(format!("导出 C Header 失败：{} ({error})", path.display()));
                    self.bottom_tab = 0;
                }
            }
        }
    }

    fn import_type_library_dialog(&mut self) {
        if let Some(path) = FileDialog::new()
            .add_filter(
                "FY_IDA Project or Header",
                &["fyida", "json", "h", "hpp", "hh"],
            )
            .pick_file()
        {
            let extension = path
                .extension()
                .and_then(|extension| extension.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            let imported = if matches!(extension.as_str(), "h" | "hpp" | "hh") {
                match std::fs::read_to_string(&path) {
                    Ok(text) => {
                        let source = path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("header");
                        Ok(import_c_header_types(source, &text))
                    }
                    Err(error) => Err(format!("{error}")),
                }
            } else {
                ProjectDocument::load_from_path(&path)
                    .map(|document| document.types)
                    .map_err(|error| error.to_string())
            };

            match imported {
                Ok(types) => {
                    let count = self.project.upsert_project_types(types);
                    self.logs.push(format!(
                        "已导入类型库：{}，类型 {} 个",
                        path.display(),
                        count
                    ));
                    self.right_tab = 2;
                    self.bottom_tab = 0;
                }
                Err(error) => {
                    self.logs
                        .push(format!("导入类型库失败：{} ({error})", path.display()));
                    self.bottom_tab = 0;
                }
            }
        }
    }

    fn apply_type_to_current_target(&mut self) {
        let Some(target) = self.current_type_target() else {
            self.logs
                .push("应用类型失败：尚未选择地址或函数。".to_owned());
            return;
        };
        let type_name = self.type_apply_name.trim().to_owned();
        if type_name.is_empty() {
            self.logs.push("应用类型失败：类型名不能为空。".to_owned());
            return;
        }
        self.project.apply_type_to_target(target, type_name.clone());
        self.logs.push(format!(
            "已应用类型：{} 0x{:016X} -> {}",
            target.label(),
            target.address(),
            type_name
        ));
        self.type_apply_open = false;
        self.right_tab = 1;
        self.bottom_tab = 0;
    }

    fn sync_pdb_types_to_project(&mut self) {
        let Some(analysis) = &self.analysis else {
            return;
        };
        let types = analysis
            .pdb_types
            .iter()
            .map(|type_item| ProjectType {
                name: type_item.name.clone(),
                kind: type_item.kind.clone(),
                source: type_item.source.clone(),
                definition: None,
            })
            .collect::<Vec<_>>();
        self.project.upsert_project_types(types);
    }

    fn current_type_target(&self) -> Option<ProjectTypeTarget> {
        self.current_function_start()
            .map(ProjectTypeTarget::Function)
            .or_else(|| {
                self.project
                    .current_address()
                    .map(ProjectTypeTarget::Address)
            })
    }

    fn toggle_current_bookmark(&mut self) {
        let Some(address) = self.project.current_address() else {
            self.logs.push("书签操作失败：尚未选择地址。".to_owned());
            return;
        };
        let was_bookmarked = self.project.is_bookmarked(address);
        self.project.toggle_bookmark(address);
        self.logs.push(if was_bookmarked {
            format!("已删除书签：0x{address:016X}")
        } else {
            format!("已添加书签：0x{address:016X}")
        });
    }

    fn set_current_manual_definition(&mut self, kind: ManualDefinitionKind) {
        let Some(address) = self.project.current_address() else {
            self.logs.push("手动定义失败：尚未选择地址。".to_owned());
            return;
        };
        self.project.set_manual_definition(address, kind);
        self.logs
            .push(format!("已标记 0x{address:016X} 为{}。", kind.label()));
    }

    fn undo_annotation(&mut self) {
        if self.project.undo() {
            self.logs.push("已撤销上一项人工标注。".to_owned());
        }
    }

    fn redo_annotation(&mut self) {
        if self.project.redo() {
            self.logs.push("已重做上一项人工标注。".to_owned());
        }
    }

    fn go_back(&mut self) {
        if self.project.go_back() {
            self.logs.push("已后退到上一位置。".to_owned());
        }
    }

    fn go_forward(&mut self) {
        if self.project.go_forward() {
            self.logs.push("已前进到下一位置。".to_owned());
        }
    }

    fn handle_shortcuts(&mut self, ctx: &Context) {
        if ctx.input(|input| input.key_pressed(Key::O) && input.modifiers.ctrl) {
            self.open_file_dialog();
        }
        if ctx.input(|input| input.key_pressed(Key::S) && input.modifiers.ctrl) {
            self.save_project();
        }
        if ctx.input(|input| input.key_pressed(Key::Z) && input.modifiers.ctrl) {
            self.undo_annotation();
        }
        if ctx.input(|input| input.key_pressed(Key::Y) && input.modifiers.ctrl) {
            self.redo_annotation();
        }
        if ctx.input(|input| input.key_pressed(Key::Escape)) {
            self.go_back();
        }
        if ctx.input(|input| input.key_pressed(Key::ArrowLeft) && input.modifiers.alt) {
            self.go_back();
        }
        if ctx.input(|input| input.key_pressed(Key::ArrowRight) && input.modifiers.alt) {
            self.go_forward();
        }
        if ctx.input(|input| input.key_pressed(Key::N)) {
            self.open_rename_dialog();
        }
        if ctx.input(|input| input.key_pressed(Key::Semicolon)) {
            self.open_comment_dialog();
        }
        if ctx.input(|input| input.key_pressed(Key::G)) {
            self.quick_jump_open = true;
        }
        if ctx.input(|input| input.key_pressed(Key::F) && input.modifiers.ctrl) {
            self.search_open = true;
        }
    }

    fn top_menu(&mut self, ctx: &Context) {
        TopBottomPanel::top("menu_bar")
            .exact_height(26.0)
            .frame(panel_frame())
            .show(ctx, |ui| {
                egui::menu::bar(ui, |ui| {
                    ui.menu_button("文件", |ui| {
                        if ui.button("打开文件...").clicked() {
                            self.open_file_dialog();
                            ui.close_menu();
                        }
                        if ui.button("打开 Raw Binary...").clicked() {
                            self.open_raw_file_dialog();
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("打开项目...").clicked() {
                            self.open_project_dialog();
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(
                                self.project.pe_image().is_some(),
                                egui::Button::new("加载 PDB..."),
                            )
                            .clicked()
                        {
                            self.open_pdb_dialog();
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(
                                self.project.selected_file().is_some(),
                                egui::Button::new("保存项目"),
                            )
                            .clicked()
                        {
                            self.save_project();
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(
                                self.project.selected_file().is_some(),
                                egui::Button::new("项目另存为..."),
                            )
                            .clicked()
                        {
                            self.save_project_as_dialog();
                            ui.close_menu();
                        }
                        ui.separator();
                        ui.menu_button("最近打开", |ui| self.recent_files_menu(ui));
                        ui.separator();
                        if ui.button("退出").clicked() {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });

                    ui.menu_button("编辑", |ui| {
                        if ui
                            .add_enabled(self.project.can_undo(), egui::Button::new("撤销"))
                            .clicked()
                        {
                            self.undo_annotation();
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(self.project.can_redo(), egui::Button::new("重做"))
                            .clicked()
                        {
                            self.redo_annotation();
                            ui.close_menu();
                        }
                        ui.separator();
                        let has_address = self.project.current_address().is_some();
                        if ui
                            .add_enabled(has_address, egui::Button::new("重命名"))
                            .clicked()
                        {
                            self.open_rename_dialog();
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(has_address, egui::Button::new("添加注释"))
                            .clicked()
                        {
                            self.open_comment_dialog();
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(has_address, egui::Button::new("添加/删除书签"))
                            .clicked()
                        {
                            self.toggle_current_bookmark();
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui
                            .add_enabled(has_address, egui::Button::new("转为代码"))
                            .clicked()
                        {
                            self.set_current_manual_definition(ManualDefinitionKind::Code);
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(has_address, egui::Button::new("转为数据"))
                            .clicked()
                        {
                            self.set_current_manual_definition(ManualDefinitionKind::Data);
                            ui.close_menu();
                        }
                        ui.separator();
                        disabled_menu_items(ui, &["复制地址", "复制反汇编行"]);
                    });

                    ui.menu_button("视图", |ui| {
                        for (index, label) in CENTER_TABS.iter().enumerate() {
                            if ui.button(*label).clicked() {
                                self.center_tab = index;
                                ui.close_menu();
                            }
                        }
                        ui.separator();
                        if ui
                            .checkbox(&mut self.hide_runtime_library_functions, "隐藏运行库函数")
                            .clicked()
                        {
                            ui.close_menu();
                        }
                        ui.separator();
                        ui.add_enabled(false, egui::Button::new("重置布局"));
                    });

                    ui.menu_button("分析", |ui| {
                        disabled_menu_items(
                            ui,
                            &[
                                "开始分析",
                                "重新分析当前函数",
                                "重新分析全部",
                                "识别函数",
                                "提取字符串",
                                "重建交叉引用",
                                "识别 switch",
                            ],
                        );
                        ui.separator();
                        if ui.button("应用签名库...").clicked() {
                            self.open_signature_library_dialog();
                            ui.close_menu();
                        }
                    });

                    ui.menu_button("类型", |ui| {
                        if ui.button("局部类型").clicked() {
                            self.right_tab = 2;
                            ui.close_menu();
                        }
                        if ui.button("新建结构体").clicked() {
                            self.open_type_editor(TypeEditorKind::Struct);
                            ui.close_menu();
                        }
                        if ui.button("新建枚举").clicked() {
                            self.open_type_editor(TypeEditorKind::Enum);
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(
                                self.project.current_address().is_some(),
                                egui::Button::new("编辑函数原型"),
                            )
                            .clicked()
                        {
                            self.open_type_editor(TypeEditorKind::Function);
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(
                                self.project.current_address().is_some(),
                                egui::Button::new("应用类型到当前位置"),
                            )
                            .clicked()
                        {
                            self.open_type_apply_dialog();
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("导入 C Header").clicked() {
                            self.import_c_header_dialog();
                            ui.close_menu();
                        }
                        if ui.button("导出 C Header").clicked() {
                            self.export_c_header_dialog();
                            ui.close_menu();
                        }
                        if ui.button("导入类型库").clicked() {
                            self.import_type_library_dialog();
                            ui.close_menu();
                        }
                    });

                    ui.menu_button("脚本", |ui| {
                        disabled_menu_items(
                            ui,
                            &[
                                "Python 控制台",
                                "运行脚本...",
                                "插件管理",
                                "重新加载插件",
                                "示例脚本",
                            ],
                        );
                    });

                    ui.menu_button("工具", |ui| {
                        if ui.button("快速跳转").clicked() {
                            self.quick_jump_open = true;
                            ui.close_menu();
                        }
                        if ui.button("搜索").clicked() {
                            self.search_open = true;
                            ui.close_menu();
                        }
                        ui.add_enabled(false, egui::Button::new("项目统计"));
                        ui.add_enabled(false, egui::Button::new("选项"));
                    });

                    ui.menu_button("帮助", |ui| {
                        ui.label("FY_IDA v0.18.0-alpha.1");
                        ui.label(
                            "伪代码/IR headless 导出、伪代码/IR 搜索、正式 headless analyze 入口、运行库过滤、本地签名库、Runtime 识别与基础 x64 伪 C/IR MVP。",
                        );
                        ui.separator();
                        disabled_menu_items(ui, &["快捷键", "Python API 文档", "关于 FY_IDA"]);
                    });
                });
            });
    }

    fn recent_files_menu(&mut self, ui: &mut Ui) {
        if self.recent_files.is_empty() {
            ui.add_enabled(false, egui::Button::new("暂无最近文件"));
            return;
        }

        let files: Vec<PathBuf> = self.recent_files.iter().cloned().collect();
        for path in files {
            if ui.button(path.display().to_string()).clicked() {
                self.select_path(path);
                ui.close_menu();
            }
        }
    }

    fn toolbar(&mut self, ctx: &Context) {
        TopBottomPanel::top("toolbar")
            .exact_height(34.0)
            .frame(panel_frame())
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    if toolbar_button(ui, "打开", "打开 PE 文件或 Raw Binary").clicked() {
                        self.open_file_dialog();
                    }
                    if toolbar_button(ui, "保存", "保存项目 (Ctrl+S)").clicked() {
                        self.save_project();
                    }
                    ui.separator();
                    if toolbar_enabled_button(
                        ui,
                        self.project.can_go_back(),
                        "后退",
                        "返回上一位置 (Esc / Alt+Left)",
                    )
                    .clicked()
                    {
                        self.go_back();
                    }
                    if toolbar_enabled_button(
                        ui,
                        self.project.can_go_forward(),
                        "前进",
                        "前进到下一位置 (Alt+Right)",
                    )
                    .clicked()
                    {
                        self.go_forward();
                    }
                    if toolbar_button(ui, "跳转", "快速跳转 (G)").clicked() {
                        self.quick_jump_open = true;
                    }
                    if toolbar_button(ui, "搜索", "搜索 (Ctrl+F)").clicked() {
                        self.search_open = true;
                    }
                    ui.separator();
                    if toolbar_button(ui, "重命名", "重命名当前符号 (N)").clicked() {
                        self.open_rename_dialog();
                    }
                    if toolbar_button(ui, "注释", "添加注释 (;)").clicked() {
                        self.open_comment_dialog();
                    }
                    if toolbar_button(ui, "交叉引用", "查看交叉引用").clicked() {
                        self.right_tab = 0;
                    }
                    if toolbar_button(ui, "重新分析", "重新分析当前目标").clicked() {
                        self.logs.push("当前版本自动分析在加载时执行。".to_owned());
                        self.bottom_tab = 0;
                    }
                    if toolbar_button(ui, "函数图", "切换到函数图").clicked() {
                        self.center_tab = 3;
                    }
                    if toolbar_button(ui, "伪代码", "切换到伪代码").clicked() {
                        self.center_tab = 2;
                    }
                });
            });
    }

    fn left_panel(&mut self, ctx: &Context) {
        SidePanel::left("left_navigation")
            .exact_width(260.0)
            .resizable(false)
            .frame(panel_frame())
            .show(ctx, |ui| {
                panel_title(ui, "左侧导航区");
                tab_strip(ui, &LEFT_TABS, &mut self.left_tab);
                ui.add_space(6.0);
                ui.add(TextEdit::singleline(&mut self.left_filter).hint_text("过滤"));
                ui.checkbox(&mut self.hide_runtime_library_functions, "隐藏运行库函数");
                ui.separator();
                self.left_content(ui);
            });
    }

    fn right_panel(&mut self, ctx: &Context) {
        SidePanel::right("right_information")
            .exact_width(320.0)
            .resizable(false)
            .frame(panel_frame())
            .show(ctx, |ui| {
                panel_title(ui, "右侧信息区");
                tab_strip(ui, &RIGHT_TABS, &mut self.right_tab);
                ui.separator();
                self.right_content(ui);
            });
    }

    fn bottom_panels(&mut self, ctx: &Context) {
        TopBottomPanel::bottom("status_bar")
            .exact_height(26.0)
            .frame(panel_frame())
            .show(ctx, |ui| self.status_bar(ui));

        TopBottomPanel::bottom("bottom_panel")
            .exact_height(180.0)
            .resizable(false)
            .frame(panel_frame())
            .show(ctx, |ui| {
                panel_title(ui, "底部面板");
                tab_strip(ui, &BOTTOM_TABS, &mut self.bottom_tab);
                ui.separator();
                self.bottom_content(ui);
            });
    }

    fn central_panel(&mut self, ctx: &Context) {
        CentralPanel::default()
            .frame(panel_frame())
            .show(ctx, |ui| {
                panel_title(ui, "中央工作区");
                tab_strip(ui, &CENTER_TABS, &mut self.center_tab);
                ui.separator();

                match self.center_tab {
                    0 => self.disassembly_view(ui),
                    1 => self.hex_view(ui),
                    2 => self.pseudocode_view(ui),
                    3 => self.function_graph_view(ui),
                    4 => self.call_graph_view(ui),
                    _ => self.ir_view(ui),
                }
            });
    }

    fn left_content(&mut self, ui: &mut Ui) {
        ScrollArea::vertical().show(ui, |ui| match LEFT_TABS[self.left_tab] {
            "函数" => self.function_list(ui),
            "名称" => self.name_list(ui),
            "字符串" => self.string_list(ui),
            "导入" => self.import_list(ui),
            "导出" => self.export_list(ui),
            "段" => self.section_list(ui),
            _ => self.bookmark_list(ui),
        });
    }

    fn function_list(&mut self, ui: &mut Ui) {
        let filter = normalized_filter(&self.left_filter);
        let mut hidden_runtime_count = 0usize;
        let rows = if let Some(analysis) = &self.analysis {
            let mut rows = Vec::new();
            for function in &analysis.functions {
                let runtime_signature =
                    runtime_function_signature_in(&analysis.runtime_signatures, function.start_va);
                if self.hide_runtime_library_functions && runtime_signature.is_some() {
                    hidden_runtime_count += 1;
                    continue;
                }

                let block_count = analysis
                    .function_cfgs
                    .iter()
                    .find(|cfg| cfg.function_start == function.start_va)
                    .map(|cfg| cfg.blocks.len())
                    .unwrap_or(0);
                let runtime_label = runtime_signature
                    .map(|signature| format!(" / runtime {}", signature.kind.label()))
                    .unwrap_or_default();
                let address = format!("{:016X}", function.start_va);
                let name = self
                    .project
                    .name_for(function.start_va)
                    .unwrap_or(&function.name)
                    .to_owned();
                let status = format!(
                    "{} 条指令 / {} 个块 / {} 次调用",
                    function.instruction_count, block_count, function.call_count
                ) + &runtime_label;
                if row_matches_filter(&filter, &[&address, &name, &status]) {
                    rows.push((function.start_va, address, name, status));
                }
            }
            rows
        } else if self.project.selected_file().is_some() {
            vec![(
                0,
                "--------".to_owned(),
                "无法分析".to_owned(),
                "非 PE 或加载失败".to_owned(),
            )]
        } else {
            vec![(
                0x1400_01000,
                "140001000".to_owned(),
                "示例入口".to_owned(),
                "占位".to_owned(),
            )]
        };

        if self.analysis.is_some() {
            ui.horizontal(|ui| {
                if self.hide_runtime_library_functions {
                    ui.label(format!("已隐藏运行库函数：{}", hidden_runtime_count));
                }
                if !filter.is_empty() {
                    ui.label(format!("过滤：{}", self.left_filter.trim()));
                }
            });
            if rows.is_empty() {
                placeholder_list(ui, &["当前过滤条件下没有可显示函数"]);
                return;
            }
        }

        Grid::new("function_list_grid")
            .num_columns(3)
            .striped(true)
            .spacing([10.0, 4.0])
            .show(ui, |ui| {
                ui.strong("地址");
                ui.strong("名称");
                ui.strong("状态");
                ui.end_row();

                for (va, address, name, status) in rows {
                    let address_clicked = ui.selectable_label(false, address).clicked();
                    let name_clicked = ui.selectable_label(false, &name).clicked();
                    if address_clicked || name_clicked {
                        self.project.jump_to(va, Some(name.clone()));
                        self.logs.push(format!("跳转到函数：{name}"));
                    }
                    ui.label(status);
                    ui.end_row();
                }
            });
    }

    fn name_list(&mut self, ui: &mut Ui) {
        let Some(analysis) = &self.analysis else {
            placeholder_list(ui, &["尚未建立名称索引"]);
            return;
        };

        let filter = normalized_filter(&self.left_filter);
        let mut hidden_runtime_count = 0usize;
        let mut rows = Vec::new();
        for function in &analysis.functions {
            if self.hide_runtime_library_functions
                && runtime_function_signature_in(&analysis.runtime_signatures, function.start_va)
                    .is_some()
            {
                hidden_runtime_count += 1;
                continue;
            }
            let address = format!("{:016X}", function.start_va);
            let name = self
                .project
                .name_for(function.start_va)
                .unwrap_or(&function.name)
                .to_owned();
            let kind = "函数".to_owned();
            if row_matches_filter(&filter, &[&address, &name, &kind]) {
                rows.push((function.start_va, name, kind));
            }
        }

        for export in &analysis.exports {
            let address = format!("{:016X}", export.va);
            let kind = "导出".to_owned();
            if row_matches_filter(&filter, &[&address, &export.name, &kind]) {
                rows.push((export.va, export.name.clone(), kind));
            }
        }

        for import in &analysis.imports {
            let address = format!("{:016X}", import.thunk_va);
            let name = import.display_name();
            let kind = "导入".to_owned();
            if row_matches_filter(&filter, &[&address, &name, &kind]) {
                rows.push((import.thunk_va, name, kind));
            }
        }

        for signature in &analysis.runtime_signatures {
            if self.hide_runtime_library_functions && is_runtime_function_signature(signature) {
                continue;
            }
            let address = format!("{:016X}", signature.address);
            let kind = format!("runtime {}", signature.kind.label());
            if row_matches_filter(&filter, &[&address, &signature.name, &kind]) {
                rows.push((signature.address, signature.name.clone(), kind));
            }
        }

        for symbol in &analysis.pdb_symbols {
            let Some(address_value) = symbol.address else {
                continue;
            };
            let address = format!("{:016X}", address_value);
            let name = symbol.display_name().to_owned();
            let kind = symbol.kind.label().to_owned();
            if row_matches_filter(&filter, &[&address, &name, &kind]) {
                rows.push((address_value, name, kind));
            }
        }

        if rows.is_empty() {
            placeholder_list(ui, &["当前过滤条件下没有可显示名称"]);
            return;
        }

        ui.horizontal(|ui| {
            if self.hide_runtime_library_functions {
                ui.label(format!("已隐藏运行库函数：{}", hidden_runtime_count));
            }
            if !filter.is_empty() {
                ui.label(format!("过滤：{}", self.left_filter.trim()));
            }
        });

        Grid::new("name_list_grid")
            .num_columns(3)
            .striped(true)
            .spacing([10.0, 4.0])
            .show(ui, |ui| {
                ui.strong("地址");
                ui.strong("名称");
                ui.strong("类型");
                ui.end_row();

                for (va, name, kind) in rows {
                    if ui.selectable_label(false, format!("{va:016X}")).clicked() {
                        self.project.jump_to(va, Some(name.clone()));
                    }
                    if ui.selectable_label(false, &name).clicked() {
                        self.project.jump_to(va, Some(name.clone()));
                    }
                    ui.label(kind);
                    ui.end_row();
                }
            });
    }

    fn string_list(&mut self, ui: &mut Ui) {
        let Some(analysis) = &self.analysis else {
            placeholder_list(ui, &["尚未扫描字符串", "打开 PE 后等待分析"]);
            return;
        };
        if analysis.strings.is_empty() {
            placeholder_list(ui, &["未发现长度足够的 ASCII 或 UTF-16LE 字符串"]);
            return;
        }

        let strings = analysis.strings.clone();
        Grid::new("string_list_grid")
            .num_columns(3)
            .striped(true)
            .spacing([10.0, 4.0])
            .show(ui, |ui| {
                ui.strong("地址");
                ui.strong("编码");
                ui.strong("内容");
                ui.end_row();

                for string in strings {
                    if ui
                        .selectable_label(false, format!("{:016X}", string.address))
                        .clicked()
                    {
                        self.project
                            .jump_to(string.address, Some("字符串".to_owned()));
                    }
                    ui.label(string.encoding.label());
                    if ui.selectable_label(false, &string.value).clicked() {
                        self.project
                            .jump_to(string.address, Some("字符串".to_owned()));
                    }
                    ui.end_row();
                }
            });
    }

    fn import_list(&mut self, ui: &mut Ui) {
        let Some(analysis) = &self.analysis else {
            placeholder_list(ui, &["尚未解析导入表"]);
            return;
        };
        if analysis.imports.is_empty() {
            placeholder_list(ui, &["当前 PE 没有导入符号或导入表不可用"]);
            return;
        }

        let imports = analysis.imports.clone();
        Grid::new("import_list_grid")
            .num_columns(3)
            .striped(true)
            .spacing([10.0, 4.0])
            .show(ui, |ui| {
                ui.strong("IAT VA");
                ui.strong("DLL");
                ui.strong("API");
                ui.end_row();

                for import in imports {
                    if ui
                        .selectable_label(false, format!("{:016X}", import.thunk_va))
                        .clicked()
                    {
                        self.project
                            .jump_to(import.thunk_va, Some(import.display_name()));
                    }
                    ui.label(&import.dll);
                    if ui.selectable_label(false, import.display_name()).clicked() {
                        self.project
                            .jump_to(import.thunk_va, Some(import.display_name()));
                    }
                    ui.end_row();
                }
            });
    }

    fn export_list(&mut self, ui: &mut Ui) {
        let Some(analysis) = &self.analysis else {
            placeholder_list(ui, &["尚未解析导出表"]);
            return;
        };
        if analysis.exports.is_empty() {
            placeholder_list(ui, &["当前 PE 没有导出符号或导出表不可用"]);
            return;
        }

        let exports = analysis.exports.clone();
        Grid::new("export_list_grid")
            .num_columns(3)
            .striped(true)
            .spacing([10.0, 4.0])
            .show(ui, |ui| {
                ui.strong("VA");
                ui.strong("名称");
                ui.strong("序号");
                ui.end_row();

                for export in exports {
                    if ui
                        .selectable_label(false, format!("{:016X}", export.va))
                        .clicked()
                    {
                        self.project.jump_to(export.va, Some(export.name.clone()));
                    }
                    if ui.selectable_label(false, &export.name).clicked() {
                        self.project.jump_to(export.va, Some(export.name.clone()));
                    }
                    ui.label(export.ordinal.to_string());
                    ui.end_row();
                }
            });
    }

    fn bookmark_list(&mut self, ui: &mut Ui) {
        let bookmarks = self.project.bookmarks();
        if bookmarks.is_empty() {
            placeholder_list(ui, &["暂无书签"]);
            return;
        }

        Grid::new("bookmark_list_grid")
            .num_columns(2)
            .striped(true)
            .spacing([10.0, 4.0])
            .show(ui, |ui| {
                ui.strong("地址");
                ui.strong("名称/注释");
                ui.end_row();

                for bookmark in bookmarks {
                    if ui
                        .selectable_label(false, format!("{:016X}", bookmark.address))
                        .clicked()
                    {
                        self.project
                            .jump_to(bookmark.address, Some("书签".to_owned()));
                    }
                    let label = self
                        .project
                        .name_for(bookmark.address)
                        .or_else(|| self.project.address_comment(bookmark.address))
                        .unwrap_or("书签");
                    ui.label(label);
                    ui.end_row();
                }
            });
    }

    fn section_list(&mut self, ui: &mut Ui) {
        let (image_base, sections) = match self.project.pe_image() {
            Some(image) => (image.image_base(), image.sections.clone()),
            None => {
                if let Some(raw) = self.project.raw_image() {
                    let base_address = raw.base_address;
                    let size_bytes = raw.size_bytes();
                    Grid::new("raw_segment_grid")
                        .num_columns(5)
                        .striped(true)
                        .spacing([10.0, 4.0])
                        .show(ui, |ui| {
                            ui.strong("名称");
                            ui.strong("Base");
                            ui.strong("FO");
                            ui.strong("大小");
                            ui.strong("权限");
                            ui.end_row();

                            if ui.selectable_label(false, "raw").clicked() {
                                self.project.jump_to(base_address, Some("raw".to_owned()));
                                self.logs.push("跳转到 Raw Binary 起始地址。".to_owned());
                            }
                            ui.label(format!("{:016X}", base_address));
                            ui.label("00000000");
                            ui.label(format!("0x{:X}", size_bytes));
                            ui.label("R-X");
                            ui.end_row();
                        });
                } else {
                    placeholder_list(ui, &["尚未解析 section table"]);
                }
                return;
            }
        };

        Grid::new("section_list_grid")
            .num_columns(5)
            .striped(true)
            .spacing([10.0, 4.0])
            .show(ui, |ui| {
                ui.strong("名称");
                ui.strong("RVA");
                ui.strong("FO");
                ui.strong("大小");
                ui.strong("权限");
                ui.end_row();

                for section in sections {
                    let va = section.virtual_address_va(image_base);
                    if ui.selectable_label(false, &section.name).clicked() {
                        self.project
                            .jump_to(va, Some(format!("section {}", section.name)));
                        self.logs.push(format!("跳转到 section：{}", section.name));
                    }
                    ui.label(format!("{:08X}", section.virtual_address));
                    ui.label(format!("{:08X}", section.pointer_to_raw_data));
                    ui.label(format!(
                        "V {:X} / R {:X}",
                        section.virtual_size, section.size_of_raw_data
                    ));
                    ui.label(section.permissions());
                    ui.end_row();
                }
            });
    }

    fn right_content(&mut self, ui: &mut Ui) {
        match RIGHT_TABS[self.right_tab] {
            "交叉引用" => {
                if let Some(analysis) = &self.analysis {
                    if analysis.xrefs.is_empty() {
                        ui.label("暂未发现 direct call / jump 交叉引用。");
                    } else {
                        let xrefs = analysis.xrefs.clone();
                        Grid::new("xref_grid")
                            .num_columns(3)
                            .striped(true)
                            .spacing([10.0, 4.0])
                            .show(ui, |ui| {
                                ui.strong("来源");
                                ui.strong("目标");
                                ui.strong("类型");
                                ui.end_row();

                                for xref in xrefs {
                                    if ui
                                        .selectable_label(false, format!("{:016X}", xref.from_va))
                                        .clicked()
                                    {
                                        self.project
                                            .jump_to(xref.from_va, Some("xref 来源".to_owned()));
                                    }
                                    if ui
                                        .selectable_label(false, format!("{:016X}", xref.to_va))
                                        .clicked()
                                    {
                                        self.project
                                            .jump_to(xref.to_va, Some("xref 目标".to_owned()));
                                    }
                                    ui.label(xref.kind.label());
                                    ui.end_row();
                                }
                            });
                    }
                } else {
                    ui.label("当前地址的交叉引用将在分析完成后显示。");
                    ui.label("状态：暂未分析");
                }
            }
            "属性" => {
                Grid::new("property_grid")
                    .num_columns(2)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("文件");
                        ui.label(
                            self.project
                                .selected_file()
                                .map(FileSelection::display_name)
                                .unwrap_or("未选择"),
                        );
                        ui.end_row();

                        ui.label("大小");
                        ui.label(
                            self.project
                                .selected_file()
                                .map(FileSelection::formatted_size)
                                .unwrap_or_else(|| "-".to_owned()),
                        );
                        ui.end_row();

                        ui.label("分析状态");
                        ui.label(self.project.analysis_state().label());
                        ui.end_row();

                        ui.label("项目文件");
                        ui.label(
                            self.project_path
                                .as_ref()
                                .map(|path| path.display().to_string())
                                .unwrap_or_else(|| "未保存".to_owned()),
                        );
                        ui.end_row();

                        ui.label("SHA-256");
                        ui.label(self.source_hash.as_deref().unwrap_or("尚未计算"));
                        ui.end_row();

                        if let Some(address) = self.project.current_address() {
                            ui.label("地址类型");
                            ui.label(self.project.applied_address_type(address).unwrap_or("-"));
                            ui.end_row();

                            if let Some(signature) = self.runtime_signature_at(address) {
                                ui.label("Runtime");
                                ui.label(format!(
                                    "{} / {} / {}%",
                                    signature.kind.label(),
                                    signature.library,
                                    signature.confidence
                                ));
                                ui.end_row();
                            }
                        }

                        if let Some(function_start) = self.current_function_start() {
                            ui.label("函数原型");
                            ui.label(
                                self.project
                                    .applied_function_type(function_start)
                                    .unwrap_or("-"),
                            );
                            ui.end_row();
                        }

                        if let Some(image) = self.project.pe_image() {
                            ui.separator();
                            ui.separator();
                            ui.end_row();

                            ui.label("DOS e_magic");
                            ui.label(format!("0x{:04X} (MZ)", image.dos_header.e_magic));
                            ui.end_row();

                            ui.label("DOS e_lfanew");
                            ui.label(format!("0x{:08X}", image.dos_header.e_lfanew));
                            ui.end_row();

                            ui.label("NT Signature");
                            ui.label(format!("0x{:08X} (PE)", image.nt_headers.signature));
                            ui.end_row();

                            ui.label("Machine");
                            ui.label(format!(
                                "{} / 0x{:04X}",
                                image.machine_label(),
                                image.nt_headers.file_header.machine
                            ));
                            ui.end_row();

                            ui.label("Characteristics");
                            let flags = image
                                .nt_headers
                                .file_header
                                .characteristics_labels()
                                .join(" | ");
                            ui.label(format!(
                                "0x{:04X} {}",
                                image.nt_headers.file_header.characteristics, flags
                            ));
                            ui.end_row();

                            ui.label("Optional Header");
                            ui.label(format!(
                                "{} / Magic 0x{:04X}",
                                image.nt_headers.optional_header.kind.label(),
                                image.nt_headers.optional_header.magic
                            ));
                            ui.end_row();

                            ui.label("ImageBase");
                            ui.label(format!("0x{:016X}", image.image_base()));
                            ui.end_row();

                            ui.label("EntryPoint");
                            ui.label(format!(
                                "VA 0x{:016X} / RVA 0x{:08X}",
                                image.entry_point_va(),
                                image.entry_point_rva()
                            ));
                            ui.end_row();

                            ui.label("Subsystem");
                            ui.label(format!(
                                "{} / 0x{:04X}",
                                image.subsystem_label(),
                                image.nt_headers.optional_header.subsystem
                            ));
                            ui.end_row();

                            ui.label("Sections");
                            ui.label(image.sections.len().to_string());
                            ui.end_row();
                        } else if let Some(raw) = self.project.raw_image() {
                            ui.separator();
                            ui.separator();
                            ui.end_row();

                            ui.label("格式");
                            ui.label("Raw Binary");
                            ui.end_row();

                            ui.label("Arch");
                            ui.label(raw.arch.label());
                            ui.end_row();

                            ui.label("Base");
                            ui.label(format!("0x{:016X}", raw.base_address));
                            ui.end_row();

                            ui.label("Entry");
                            ui.label(format!("0x{:016X}", raw.entry_address));
                            ui.end_row();

                            ui.label("Entry FO");
                            ui.label(format!("0x{:08X}", raw.entry_offset().unwrap_or(0)));
                            ui.end_row();

                            ui.label("End");
                            ui.label(format!("0x{:016X}", raw.end_address()));
                            ui.end_row();
                        }
                    });
            }
            "局部类型" => self.local_type_panel(ui),
            "结构体" => self.structure_panel(ui),
            _ => self.annotation_panel(ui),
        }
    }

    fn local_type_panel(&mut self, ui: &mut Ui) {
        let types = self.project.project_types();
        if types.is_empty() {
            placeholder_list(ui, &["暂无局部类型"]);
            return;
        }

        Grid::new("local_type_grid")
            .num_columns(4)
            .striped(true)
            .spacing([10.0, 4.0])
            .show(ui, |ui| {
                ui.strong("名称");
                ui.strong("类型");
                ui.strong("来源");
                ui.strong("签名");
                ui.end_row();

                for type_item in types {
                    ui.label(&type_item.name);
                    ui.label(&type_item.kind);
                    ui.label(&type_item.source);
                    ui.label(type_item.display_signature());
                    ui.end_row();
                }
            });

        ui.separator();
        if ui.button("应用类型到当前位置").clicked() {
            self.open_type_apply_dialog();
        }
    }

    fn structure_panel(&self, ui: &mut Ui) {
        let structures = self
            .project
            .project_types()
            .into_iter()
            .filter(|type_item| {
                matches!(
                    type_item.definition,
                    Some(TypeDefinition::Struct { .. }) | Some(TypeDefinition::Union { .. })
                )
            })
            .collect::<Vec<_>>();
        if structures.is_empty() {
            placeholder_list(ui, &["暂无结构体定义"]);
            return;
        }

        ScrollArea::vertical().show(ui, |ui| {
            for type_item in structures {
                ui.strong(type_item.display_signature());
                match type_item.definition {
                    Some(TypeDefinition::Struct { fields })
                    | Some(TypeDefinition::Union { fields }) => {
                        Grid::new(format!("structure_fields_{}", type_item.name))
                            .num_columns(3)
                            .striped(true)
                            .spacing([10.0, 4.0])
                            .show(ui, |ui| {
                                ui.label("字段");
                                ui.label("类型");
                                ui.label("偏移");
                                ui.end_row();

                                for field in fields {
                                    ui.label(field.name);
                                    ui.label(field.type_name);
                                    ui.label(
                                        field
                                            .offset
                                            .map(|offset| format!("0x{offset:X}"))
                                            .unwrap_or_else(|| "-".to_owned()),
                                    );
                                    ui.end_row();
                                }
                            });
                    }
                    _ => {}
                }
                ui.separator();
            }
        });
    }

    fn annotation_panel(&self, ui: &mut Ui) {
        let Some(address) = self.project.current_address() else {
            placeholder_list(ui, &["尚未选择地址"]);
            return;
        };

        Grid::new("annotation_grid")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label("当前地址");
                ui.label(format!("0x{address:016X}"));
                ui.end_row();

                ui.label("名称");
                ui.label(self.project.name_for(address).unwrap_or("-"));
                ui.end_row();

                ui.label("地址注释");
                ui.label(self.project.address_comment(address).unwrap_or("-"));
                ui.end_row();

                ui.label("函数注释");
                ui.label(
                    self.project
                        .function_comment(address)
                        .or_else(|| {
                            self.analysis.as_ref().and_then(|analysis| {
                                analysis
                                    .functions
                                    .iter()
                                    .find(|function| function.start_va == address)
                                    .and_then(|function| {
                                        self.project.function_comment(function.start_va)
                                    })
                            })
                        })
                        .unwrap_or("-"),
                );
                ui.end_row();

                ui.label("书签");
                ui.label(if self.project.is_bookmarked(address) {
                    "是"
                } else {
                    "否"
                });
                ui.end_row();

                ui.label("手动定义");
                ui.label(
                    self.project
                        .manual_definition(address)
                        .map(ManualDefinitionKind::label)
                        .unwrap_or("-"),
                );
                ui.end_row();
            });
    }

    fn bottom_content(&mut self, ui: &mut Ui) {
        match BOTTOM_TABS[self.bottom_tab] {
            "输出" => log_view(ui, &self.logs),
            "搜索结果" => self.search_results_view(ui),
            "Python 控制台" => self.python_console_panel(ui),
            "日志" => log_view(ui, &self.logs),
            _ => placeholder_list(ui, &["暂无后台任务"]),
        }
    }

    fn python_console_panel(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if ui.button("运行").clicked() {
                self.run_python_console();
            }
            if ui.button("清空输出").clicked() {
                self.python_output.clear();
            }
        });
        ui.add(TextEdit::multiline(&mut self.python_code).desired_rows(7));
        ui.separator();
        ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
            ui.monospace(&self.python_output);
        });
    }

    fn run_python_console(&mut self) {
        let script_path =
            std::env::temp_dir().join(format!("fyida_gui_console_{}.py", std::process::id()));
        if let Err(error) = std::fs::write(&script_path, &self.python_code) {
            self.python_output = format!("写入临时脚本失败：{error}");
            return;
        }

        let mut command = Command::new("python");
        command.arg(&script_path);
        if let Some(selection) = self.project.selected_file() {
            command.env("FYIDA_SELECTED_FILE", selection.path());
        }
        if let Some(address) = self.project.current_address() {
            command.env("FYIDA_CURRENT_VA", format!("0x{address:016X}"));
        }
        if let Some(function) = self.project.current_function() {
            command.env("FYIDA_CURRENT_FUNCTION", function);
        }

        match command.output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                self.python_output = format!(
                    "exit: {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                    output.status.code(),
                    stdout,
                    stderr
                );
                self.logs.push("Python 控制台脚本已运行。".to_owned());
            }
            Err(error) => {
                self.python_output = format!("启动 python 失败：{error}");
            }
        }
    }

    fn search_results_view(&mut self, ui: &mut Ui) {
        ScrollArea::vertical().show(ui, |ui| {
            for result in self.search_results.clone() {
                if let Some(address) = result.address {
                    if ui
                        .selectable_label(
                            false,
                            RichText::new(&result.label).color(address_color()),
                        )
                        .clicked()
                    {
                        self.project.jump_to(
                            address,
                            result.context.clone().or(Some("搜索结果".to_owned())),
                        );
                        self.center_tab = 0;
                        self.logs
                            .push(format!("从搜索结果跳转到 0x{address:016X}。"));
                    }
                } else {
                    ui.label(result.label);
                }
            }
        });
    }

    fn pseudocode_view(&mut self, ui: &mut Ui) {
        let Some(analysis) = &self.analysis else {
            placeholder_center(ui, "伪代码", "打开 PE 或 Raw Binary 后生成伪 C。");
            return;
        };
        let Some(function_start) = self.current_function_start() else {
            placeholder_center(ui, "伪代码", "当前地址没有匹配到函数。");
            return;
        };
        let Some(function) = analysis
            .pseudocode_functions
            .iter()
            .find(|function| function.function_start == function_start)
        else {
            placeholder_center(ui, "伪代码", "当前函数尚未生成伪 C。");
            return;
        };

        ScrollArea::both().show(ui, |ui| {
            ui.strong(format!(
                "{} / 0x{:016X}",
                function.name, function.function_start
            ));
            ui.separator();
            for line in &function.lines {
                ui.horizontal(|ui| {
                    if let Some(address) = line.address {
                        if ui
                            .selectable_label(
                                false,
                                RichText::new(format!("{address:016X}")).color(address_color()),
                            )
                            .clicked()
                        {
                            self.project.jump_to(address, Some("伪代码".to_owned()));
                        }
                    } else {
                        ui.label("                ");
                    }
                    ui.monospace(&line.text);
                });
            }
        });
    }

    fn ir_view(&mut self, ui: &mut Ui) {
        let Some(analysis) = &self.analysis else {
            placeholder_center(ui, "IR 视图", "打开 PE 或 Raw Binary 后生成 IR。");
            return;
        };
        let Some(function_start) = self.current_function_start() else {
            placeholder_center(ui, "IR 视图", "当前地址没有匹配到函数。");
            return;
        };
        let Some(function) = analysis
            .pseudocode_functions
            .iter()
            .find(|function| function.function_start == function_start)
        else {
            placeholder_center(ui, "IR 视图", "当前函数尚未生成 IR。");
            return;
        };

        Grid::new("ir_grid")
            .num_columns(4)
            .striped(true)
            .spacing([12.0, 5.0])
            .show(ui, |ui| {
                ui.strong("地址");
                ui.strong("OP");
                ui.strong("参数");
                ui.strong("原始指令");
                ui.end_row();

                for instruction in &function.ir {
                    if ui
                        .selectable_label(false, format!("{:016X}", instruction.address))
                        .clicked()
                    {
                        self.project
                            .jump_to(instruction.address, Some("IR".to_owned()));
                    }
                    ui.monospace(&instruction.op);
                    ui.label(instruction.args.join(", "));
                    ui.label(&instruction.comment);
                    ui.end_row();
                }
            });
    }

    fn function_graph_view(&mut self, ui: &mut Ui) {
        let Some(analysis) = &self.analysis else {
            placeholder_center(ui, "函数图", "打开 PE 或 Raw Binary 后生成 CFG。");
            return;
        };
        let Some(function_start) = self.current_function_start() else {
            placeholder_center(ui, "函数图", "当前地址没有匹配到函数。");
            return;
        };
        let Some(cfg) = analysis
            .function_cfgs
            .iter()
            .find(|cfg| cfg.function_start == function_start)
            .cloned()
        else {
            placeholder_center(ui, "函数图", "当前函数尚未生成 basic block。");
            return;
        };
        let function_name = self
            .project
            .name_for(function_start)
            .or_else(|| {
                analysis
                    .functions
                    .iter()
                    .find(|function| function.start_va == function_start)
                    .map(|function| function.name.as_str())
            })
            .unwrap_or("函数")
            .to_owned();

        ui.horizontal(|ui| {
            ui.strong(format!("函数图：{} 0x{function_start:016X}", function_name));
            ui.separator();
            ui.label(format!("Basic blocks：{}", cfg.blocks.len()));
            ui.label(format!("Edges：{}", cfg.edges.len()));
            if let Some(signature) =
                runtime_function_signature_in(&analysis.runtime_signatures, function_start)
            {
                ui.label(format!(
                    "运行库：{} {}%",
                    signature.kind.label(),
                    signature.confidence
                ));
            }
        });
        self.graph_controls(ui);
        ui.separator();

        let text_size = 12.0 * self.graph_zoom;
        ScrollArea::both().show(ui, |ui| {
            ui.add_space(self.graph_pan_y.max(0.0));
            ui.horizontal(|ui| {
                ui.add_space(self.graph_pan_x.max(0.0));
                ui.vertical(|ui| {
                    for block in &cfg.blocks {
                        Frame::group(ui.style())
                            .fill(panel_color())
                            .stroke(Stroke::new(1.0, Color32::from_rgb(200, 205, 210)))
                            .show(ui, |ui| {
                                ui.set_min_width(520.0 * self.graph_zoom);
                                if ui
                                    .selectable_label(
                                        false,
                                        RichText::new(format!(
                                            "BB 0x{:016X} - 0x{:016X}  / {} 条指令 / {} 次调用",
                                            block.start_va,
                                            block.end_va,
                                            block.instruction_count,
                                            block.call_count
                                        ))
                                        .color(address_color())
                                        .size(text_size)
                                        .strong(),
                                    )
                                    .clicked()
                                {
                                    self.project
                                        .jump_to(block.start_va, Some("Basic block".to_owned()));
                                    self.center_tab = 0;
                                }
                                for instruction in block.instructions.iter().take(8) {
                                    ui.label(
                                        RichText::new(format!(
                                            "{:016X}  {:<18} {:<8} {}",
                                            instruction.address,
                                            instruction.bytes,
                                            instruction.mnemonic,
                                            instruction.operands
                                        ))
                                        .size(text_size)
                                        .monospace(),
                                    );
                                }
                                if block.instructions.len() > 8 {
                                    ui.label(
                                        RichText::new(format!(
                                            "... 还有 {} 条指令",
                                            block.instructions.len() - 8
                                        ))
                                        .color(comment_color()),
                                    );
                                }
                            });
                        ui.add_space(8.0 * self.graph_zoom);
                    }

                    ui.separator();
                    ui.strong("CFG 边");
                    if cfg.edges.is_empty() {
                        ui.label("当前函数没有可显示 CFG 边。");
                    } else {
                        Grid::new("function_cfg_edges")
                            .num_columns(3)
                            .striped(true)
                            .spacing([12.0, 4.0])
                            .show(ui, |ui| {
                                ui.strong("来源");
                                ui.strong("目标");
                                ui.strong("类型");
                                ui.end_row();
                                for edge in &cfg.edges {
                                    if ui
                                        .selectable_label(false, format!("{:016X}", edge.from_va))
                                        .clicked()
                                    {
                                        self.project
                                            .jump_to(edge.from_va, Some("CFG 来源".to_owned()));
                                        self.center_tab = 0;
                                    }
                                    if ui
                                        .selectable_label(false, format!("{:016X}", edge.to_va))
                                        .clicked()
                                    {
                                        self.project
                                            .jump_to(edge.to_va, Some("CFG 目标".to_owned()));
                                        self.center_tab = 0;
                                    }
                                    ui.label(edge.kind.label());
                                    ui.end_row();
                                }
                            });
                    }
                });
            });
        });
    }

    fn call_graph_view(&mut self, ui: &mut Ui) {
        let Some(analysis) = &self.analysis else {
            placeholder_center(ui, "调用图", "打开 PE 或 Raw Binary 后生成调用关系。");
            return;
        };
        let call_graph = analysis.call_graph.clone();
        let runtime_signatures = analysis.runtime_signatures.clone();
        let mut hidden_addresses = BTreeSet::new();
        if self.hide_runtime_library_functions {
            hidden_addresses.extend(
                call_graph
                    .nodes
                    .iter()
                    .filter(|node| {
                        runtime_function_signature_in(&runtime_signatures, node.start_va).is_some()
                    })
                    .map(|node| node.start_va),
            );
        }
        let visible_nodes = call_graph
            .nodes
            .iter()
            .filter(|node| !hidden_addresses.contains(&node.start_va))
            .collect::<Vec<_>>();
        let visible_edges = call_graph
            .edges
            .iter()
            .filter(|edge| {
                !hidden_addresses.contains(&edge.caller_va)
                    && !hidden_addresses.contains(&edge.callee_va)
            })
            .collect::<Vec<_>>();

        ui.horizontal(|ui| {
            ui.strong("调用图");
            ui.separator();
            if self.hide_runtime_library_functions {
                ui.label(format!(
                    "节点：{} / {}",
                    visible_nodes.len(),
                    call_graph.nodes.len()
                ));
                ui.label(format!(
                    "边：{} / {}",
                    visible_edges.len(),
                    call_graph.edges.len()
                ));
                ui.label(format!("隐藏库函数：{}", hidden_addresses.len()));
            } else {
                ui.label(format!("节点：{}", visible_nodes.len()));
                ui.label(format!("边：{}", visible_edges.len()));
            }
        });
        self.graph_controls(ui);
        ui.separator();

        ScrollArea::both().show(ui, |ui| {
            ui.add_space(self.graph_pan_y.max(0.0));
            ui.horizontal(|ui| {
                ui.add_space(self.graph_pan_x.max(0.0));
                ui.vertical(|ui| {
                    ui.strong("函数节点");
                    Grid::new("call_graph_nodes")
                        .num_columns(4)
                        .striped(true)
                        .spacing([12.0, 4.0])
                        .show(ui, |ui| {
                            ui.strong("地址");
                            ui.strong("名称");
                            ui.strong("类型");
                            ui.strong("调用数");
                            ui.end_row();
                            for node in &visible_nodes {
                                if ui
                                    .selectable_label(false, format!("{:016X}", node.start_va))
                                    .clicked()
                                {
                                    self.project.jump_to(node.start_va, Some(node.name.clone()));
                                    self.center_tab = 0;
                                }
                                let name =
                                    self.project.name_for(node.start_va).unwrap_or(&node.name);
                                if ui.selectable_label(false, name).clicked() {
                                    self.project.jump_to(node.start_va, Some(name.to_owned()));
                                    self.center_tab = 0;
                                }
                                if let Some(signature) = runtime_function_signature_in(
                                    &runtime_signatures,
                                    node.start_va,
                                ) {
                                    ui.label(format!("运行库 {}", signature.kind.label()));
                                } else if node.is_external {
                                    ui.label("预留/外部");
                                } else {
                                    ui.label("已发现");
                                }
                                ui.label(node.call_count.to_string());
                                ui.end_row();
                            }
                        });

                    ui.separator();
                    ui.strong("调用边");
                    if visible_edges.is_empty() {
                        ui.label("当前样本没有 direct call 边，或尚未识别到可解析调用目标。");
                    } else {
                        Grid::new("call_graph_edges")
                            .num_columns(4)
                            .striped(true)
                            .spacing([12.0, 4.0])
                            .show(ui, |ui| {
                                ui.strong("Caller");
                                ui.strong("Callee");
                                ui.strong("Callsite");
                                ui.strong("类型");
                                ui.end_row();
                                for edge in &visible_edges {
                                    if ui
                                        .selectable_label(false, format!("{:016X}", edge.caller_va))
                                        .clicked()
                                    {
                                        self.project
                                            .jump_to(edge.caller_va, Some("调用者".to_owned()));
                                        self.center_tab = 0;
                                    }
                                    if ui
                                        .selectable_label(false, format!("{:016X}", edge.callee_va))
                                        .clicked()
                                    {
                                        self.project
                                            .jump_to(edge.callee_va, Some("被调用函数".to_owned()));
                                        self.center_tab = 0;
                                    }
                                    if ui
                                        .selectable_label(
                                            false,
                                            format!("{:016X}", edge.callsite_va),
                                        )
                                        .clicked()
                                    {
                                        self.project
                                            .jump_to(edge.callsite_va, Some("callsite".to_owned()));
                                        self.center_tab = 0;
                                    }
                                    ui.label(&edge.label);
                                    ui.end_row();
                                }
                            });
                    }
                });
            });
        });
    }

    fn graph_controls(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label("缩放");
            ui.add(
                DragValue::new(&mut self.graph_zoom)
                    .speed(0.05)
                    .clamp_range(0.6..=1.8),
            );
            ui.label("平移 X");
            ui.add(DragValue::new(&mut self.graph_pan_x).speed(4.0));
            ui.label("平移 Y");
            ui.add(DragValue::new(&mut self.graph_pan_y).speed(4.0));
            if ui.button("重置").clicked() {
                self.graph_zoom = 1.0;
                self.graph_pan_x = 0.0;
                self.graph_pan_y = 0.0;
            }
        });
    }

    fn current_function_start(&self) -> Option<u64> {
        let analysis = self.analysis.as_ref()?;
        let address = self.project.current_address()?;
        analysis
            .functions
            .iter()
            .find(|function| {
                let end = function.start_va.saturating_add(function.size.max(1));
                address >= function.start_va && address < end
            })
            .map(|function| function.start_va)
            .or_else(|| {
                analysis
                    .functions
                    .iter()
                    .filter(|function| function.start_va <= address)
                    .max_by_key(|function| function.start_va)
                    .map(|function| function.start_va)
            })
            .or_else(|| analysis.function_cfgs.first().map(|cfg| cfg.function_start))
    }

    fn disassembly_view(&mut self, ui: &mut Ui) {
        if self.project.selected_file().is_none() {
            self.empty_state(ui);
            ui.separator();
        }

        ScrollArea::both().show(ui, |ui| {
            Grid::new("disassembly_grid")
                .num_columns(5)
                .striped(true)
                .spacing([18.0, 6.0])
                .show(ui, |ui| {
                    ui.strong("地址");
                    ui.strong("字节");
                    ui.strong("指令");
                    ui.strong("操作数");
                    ui.strong("注释");
                    ui.end_row();

                    for row in self.disassembly_rows.clone() {
                        let address = format!("{:08X}", row.address);
                        if ui
                            .selectable_label(false, RichText::new(address).color(address_color()))
                            .clicked()
                        {
                            self.project
                                .jump_to(row.address, Some(row.mnemonic.clone()));
                        }
                        ui.label(RichText::new(&row.bytes).color(bytes_color()));
                        ui.label(
                            RichText::new(&row.mnemonic)
                                .color(mnemonic_color())
                                .strong(),
                        );
                        ui.label(&row.operands);
                        ui.label(RichText::new(self.row_comment(&row)).color(comment_color()));
                        ui.end_row();
                    }
                });
        });
    }

    fn row_comment(&self, row: &DisassemblyRow) -> String {
        let mut parts = Vec::new();
        if self.project.is_bookmarked(row.address) {
            parts.push("[书签]".to_owned());
        }
        if let Some(kind) = self.project.manual_definition(row.address) {
            parts.push(format!("[{}]", kind.label()));
        }
        if !row.comment.is_empty() {
            parts.push(row.comment.clone());
        }
        if let Some(symbol) = self.pdb_symbol_at(row.address) {
            parts.push(format!("PDB: {}", symbol.display_name()));
        }
        if let Some(signature) = self.runtime_signature_at(row.address) {
            parts.push(format!(
                "runtime: {} {}%",
                signature.kind.label(),
                signature.confidence
            ));
        }
        if let Some(type_name) = self.project.applied_address_type(row.address) {
            parts.push(format!("type: {type_name}"));
        }
        if let Some(type_name) = self.project.applied_function_type(row.address) {
            parts.push(format!("prototype: {type_name}"));
        }
        if let Some(comment) = self.project.address_comment(row.address) {
            parts.push(comment.to_owned());
        }
        parts.join(" ")
    }

    fn empty_state(&mut self, ui: &mut Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(18.0);
            ui.heading("尚未打开文件");
            ui.label("打开 PE 文件或 Raw Binary 开始分析");
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("打开文件").clicked() {
                    self.open_file_dialog();
                }
                if ui.button("打开 Raw Binary").clicked() {
                    self.open_raw_file_dialog();
                }
                ui.add_enabled(false, egui::Button::new("打开项目"));
            });

            if !self.recent_files.is_empty() {
                ui.add_space(12.0);
                ui.strong("最近文件");
                let files: Vec<PathBuf> = self.recent_files.iter().cloned().collect();
                for path in files {
                    if ui.link(path.display().to_string()).clicked() {
                        self.select_path(path);
                    }
                }
            }
            ui.add_space(12.0);
        });
    }

    fn hex_view(&mut self, ui: &mut Ui) {
        if self.input_bytes.is_empty() {
            placeholder_list(ui, &["尚未读取文件字节"]);
            return;
        }

        let current_offset = self
            .project
            .current_file_offset()
            .and_then(|offset| usize::try_from(offset).ok())
            .unwrap_or(0)
            .min(self.input_bytes.len().saturating_sub(1));
        let start_offset = current_offset.saturating_sub(0x40) & !0xF;
        let end_offset = start_offset
            .saturating_add(0x180)
            .min(self.input_bytes.len());

        ScrollArea::both().show(ui, |ui| {
            Grid::new("hex_grid")
                .num_columns(3)
                .striped(true)
                .spacing([18.0, 6.0])
                .show(ui, |ui| {
                    ui.strong("文件偏移 / VA");
                    ui.strong("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");
                    ui.strong("ASCII / UTF-16 预览");
                    ui.end_row();

                    for row_start in (start_offset..end_offset).step_by(16) {
                        let row_end = row_start.saturating_add(16).min(self.input_bytes.len());
                        let row = &self.input_bytes[row_start..row_end];
                        let file_offset = u64::try_from(row_start).unwrap_or(0);
                        let va = self.file_offset_to_va(file_offset);
                        let label = match va {
                            Some(va) => format!("FO {file_offset:08X} / VA {va:016X}"),
                            None => format!("FO {file_offset:08X}"),
                        };
                        let is_current = current_offset >= row_start && current_offset < row_end;
                        let label_text = if is_current {
                            RichText::new(label)
                                .color(address_color())
                                .background_color(Color32::from_rgb(255, 243, 176))
                        } else {
                            RichText::new(label).color(address_color())
                        };

                        if let Some(va) = va {
                            if ui.selectable_label(is_current, label_text).clicked() {
                                self.project.jump_to(va, Some("Hex".to_owned()));
                            }
                        } else {
                            ui.label(label_text);
                        }
                        ui.label(RichText::new(hex_bytes(row)).color(bytes_color()));
                        ui.label(ascii_preview(row));
                        ui.end_row();
                    }
                });
        });
    }

    fn status_bar(&self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label(format_address(self.project.current_address(), "VA"));
            ui.separator();
            ui.label(format_address(self.project.current_rva(), "RVA"));
            ui.separator();
            ui.label(format_address(self.project.current_file_offset(), "FO"));
            ui.separator();
            ui.label(format!(
                "当前函数 {}",
                self.project.current_function().unwrap_or("--------")
            ));
            ui.separator();
            ui.label(format!(
                "分析状态 {}",
                self.project.analysis_state().label()
            ));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(format!("项目状态 {}", self.project.project_status_label()));
            });
        });
    }

    fn dialogs(&mut self, ctx: &Context) {
        let mut jump_open = self.quick_jump_open;
        Window::new("快速跳转")
            .open(&mut jump_open)
            .resizable(false)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label("输入 VA、RVA、文件偏移、函数名或字符串关键词。");
                ui.add(TextEdit::singleline(&mut self.quick_jump_text).hint_text("140001000"));
                if ui.button("跳转").clicked() {
                    if let Some((va, label)) = self.resolve_jump_input() {
                        self.project.jump_to(va, Some(label));
                        self.logs
                            .push(format!("快速跳转完成：{}", self.quick_jump_text));
                    } else {
                        self.logs
                            .push(format!("快速跳转无法解析：{}", self.quick_jump_text));
                    }
                    self.quick_jump_open = false;
                }
            });
        self.quick_jump_open = jump_open && self.quick_jump_open;

        let mut search_open = self.search_open;
        Window::new("搜索")
            .open(&mut search_open)
            .resizable(false)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label("搜索文本、字符串、函数名、导入 API、注释、字节序列或地址。");
                ui.add(TextEdit::singleline(&mut self.search_text).hint_text("CreateFileW"));
                if ui.button("搜索").clicked() {
                    self.search_results = self.run_search();
                    self.bottom_tab = 1;
                    self.search_open = false;
                }
            });
        self.search_open = search_open && self.search_open;

        let mut raw_open = self.raw_dialog_open;
        Window::new("打开 Raw Binary")
            .open(&mut raw_open)
            .resizable(false)
            .collapsible(false)
            .show(ctx, |ui| {
                if let Some(selection) = &self.pending_raw_selection {
                    ui.label(format!("文件：{}", selection.path().display()));
                    ui.label(format!("大小：{}", selection.formatted_size()));
                } else {
                    ui.label("尚未选择 Raw Binary 文件。");
                }
                ui.separator();
                ui.label("Base");
                ui.add(TextEdit::singleline(&mut self.raw_base_text).hint_text("0x140000000"));
                ui.label("Entry");
                ui.add(TextEdit::singleline(&mut self.raw_entry_text).hint_text("0x140000000"));
                ui.label("Arch");
                ui.add_enabled(
                    false,
                    TextEdit::singleline(&mut self.raw_arch_text).hint_text("x64"),
                );
                if !self.raw_error_text.is_empty() {
                    ui.label(RichText::new(&self.raw_error_text).color(error_color()));
                }
                ui.horizontal(|ui| {
                    if ui.button("加载").clicked() {
                        match self.raw_options_from_dialog() {
                            Ok(options) => {
                                if let Some(selection) = self.pending_raw_selection.take() {
                                    self.load_raw_selected_file(selection, options);
                                    self.raw_dialog_open = false;
                                    self.raw_error_text.clear();
                                } else {
                                    self.raw_error_text = "尚未选择 Raw Binary 文件。".to_owned();
                                }
                            }
                            Err(message) => {
                                self.raw_error_text = message;
                            }
                        }
                    }
                    if ui.button("取消").clicked() {
                        self.raw_dialog_open = false;
                        self.pending_raw_selection = None;
                    }
                });
            });
        self.raw_dialog_open = raw_open && self.raw_dialog_open;

        let mut rename_open = self.rename_open;
        Window::new("重命名")
            .open(&mut rename_open)
            .resizable(false)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label("为当前地址设置用户名称。");
                ui.add(TextEdit::singleline(&mut self.rename_text).hint_text("decrypt_config"));
                if ui.button("确定").clicked() {
                    if let Some(address) = self.project.current_address() {
                        self.project
                            .rename_address(address, self.rename_text.clone());
                        self.logs
                            .push(format!("已重命名 0x{address:016X} 为 {}", self.rename_text));
                        self.rename_open = false;
                    }
                }
            });
        self.rename_open = rename_open && self.rename_open;

        let mut comment_open = self.comment_open;
        Window::new("添加注释")
            .open(&mut comment_open)
            .resizable(false)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label("为当前地址设置注释。");
                ui.add(TextEdit::multiline(&mut self.comment_text).desired_rows(3));
                if ui.button("确定").clicked() {
                    if let Some(address) = self.project.current_address() {
                        self.project
                            .set_address_comment(address, self.comment_text.clone());
                        if self
                            .analysis
                            .as_ref()
                            .map(|analysis| {
                                analysis
                                    .functions
                                    .iter()
                                    .any(|function| function.start_va == address)
                            })
                            .unwrap_or(false)
                        {
                            self.project
                                .set_function_comment(address, self.comment_text.clone());
                        }
                        self.logs
                            .push(format!("已更新 0x{address:016X} 的地址/函数注释。"));
                        self.comment_open = false;
                        self.right_tab = 4;
                    }
                }
            });
        self.comment_open = comment_open && self.comment_open;

        let mut type_editor_open = self.type_editor_open;
        Window::new(self.type_editor_kind.title())
            .open(&mut type_editor_open)
            .resizable(true)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label("类型名");
                ui.add(TextEdit::singleline(&mut self.type_name_text).hint_text("CONFIG"));
                ui.label(match self.type_editor_kind {
                    TypeEditorKind::Struct => "字段，每行一个：DWORD flags",
                    TypeEditorKind::Enum => "枚举值，每行一个：MODE_A = 0",
                    TypeEditorKind::Function => "函数原型：int __cdecl fn(void)",
                });
                ui.add(TextEdit::multiline(&mut self.type_body_text).desired_rows(8));
                if !self.type_error_text.is_empty() {
                    ui.label(RichText::new(&self.type_error_text).color(error_color()));
                }
                ui.horizontal(|ui| {
                    if ui.button("确定").clicked() {
                        self.commit_type_editor();
                    }
                    if ui.button("取消").clicked() {
                        self.type_editor_open = false;
                    }
                });
            });
        self.type_editor_open = type_editor_open && self.type_editor_open;

        let mut type_apply_open = self.type_apply_open;
        Window::new("应用类型")
            .open(&mut type_apply_open)
            .resizable(false)
            .collapsible(false)
            .show(ctx, |ui| {
                if let Some(target) = self.current_type_target() {
                    ui.label(format!(
                        "目标：{} 0x{:016X}",
                        target.label(),
                        target.address()
                    ));
                }
                ui.label("类型名");
                ui.add(TextEdit::singleline(&mut self.type_apply_name).hint_text("CONFIG *"));
                ui.horizontal(|ui| {
                    if ui.button("应用").clicked() {
                        self.apply_type_to_current_target();
                    }
                    if ui.button("取消").clicked() {
                        self.type_apply_open = false;
                    }
                });
            });
        self.type_apply_open = type_apply_open && self.type_apply_open;
    }

    fn resolve_jump_input(&self) -> Option<(u64, String)> {
        let text = self.quick_jump_text.trim();
        let text_lower = text.to_lowercase();

        if let Some(image) = self.project.pe_image() {
            if let Some(raw_rva) = text_lower
                .strip_prefix("rva:")
                .and_then(|_| text.split_once(':').map(|(_, value)| value))
            {
                let rva = parse_number(raw_rva.trim())?;
                return Some((image.rva_to_va(rva), format!("RVA 0x{rva:08X}")));
            }

            if let Some(raw_file_offset) = text_lower
                .strip_prefix("file:")
                .and_then(|_| text.split_once(':').map(|(_, value)| value))
            {
                let file_offset = parse_number(raw_file_offset.trim())?;
                let va = image.file_offset_to_va(file_offset)?;
                return Some((va, format!("FO 0x{file_offset:08X}")));
            }

            if let Some(va) = parse_number(text) {
                return Some((va, format!("VA 0x{va:016X}")));
            }
        }

        if let Some(raw) = self.project.raw_image() {
            if let Some(raw_file_offset) = text_lower
                .strip_prefix("file:")
                .and_then(|_| text.split_once(':').map(|(_, value)| value))
            {
                let file_offset = parse_number(raw_file_offset.trim())?;
                let va = raw.file_offset_to_va(file_offset)?;
                return Some((va, format!("FO 0x{file_offset:08X}")));
            }
            if let Some(raw_rva) = text_lower
                .strip_prefix("rva:")
                .and_then(|_| text.split_once(':').map(|(_, value)| value))
            {
                let rva = parse_number(raw_rva.trim())?;
                let va = raw.rva_to_va(rva)?;
                return Some((va, format!("Raw+0x{rva:X}")));
            }
            if let Some(va) = parse_number(text) {
                return raw
                    .contains_va(va)
                    .then_some((va, format!("VA 0x{va:016X}")));
            }
        }

        self.resolve_symbolic_jump(text)
    }

    fn resolve_symbolic_jump(&self, text: &str) -> Option<(u64, String)> {
        let analysis = self.analysis.as_ref()?;
        let query = text.trim().to_lowercase();
        if query.is_empty() {
            return None;
        }

        for name in self.project.user_names() {
            if name.name.to_lowercase().contains(&query) {
                return Some((name.address, format!("名称 {}", name.name)));
            }
        }

        for function in &analysis.functions {
            let name = self
                .project
                .name_for(function.start_va)
                .unwrap_or(&function.name);
            if name.to_lowercase().contains(&query) {
                return Some((function.start_va, format!("函数 {name}")));
            }
        }

        for import in &analysis.imports {
            let name = import.display_name();
            if name.to_lowercase().contains(&query)
                || import
                    .name
                    .as_ref()
                    .map(|api| api.to_lowercase().contains(&query))
                    .unwrap_or(false)
            {
                return Some((import.thunk_va, format!("导入 {name}")));
            }
        }

        for export in &analysis.exports {
            if export.name.to_lowercase().contains(&query) {
                return Some((export.va, format!("导出 {}", export.name)));
            }
        }

        for symbol in &analysis.pdb_symbols {
            let display_name = symbol.display_name();
            if display_name.to_lowercase().contains(&query)
                || symbol.name.to_lowercase().contains(&query)
            {
                if let Some(address) = symbol.address {
                    return Some((address, format!("PDB {display_name}")));
                }
            }
        }

        for string in &analysis.strings {
            if string.value.to_lowercase().contains(&query) {
                return Some((string.address, "字符串".to_owned()));
            }
        }

        None
    }

    fn raw_options_from_dialog(&self) -> Result<RawLoadOptions, String> {
        let base_address = parse_number(self.raw_base_text.trim())
            .ok_or_else(|| "Base 需要是十六进制或十进制地址。".to_owned())?;
        let entry_address = parse_number(self.raw_entry_text.trim())
            .ok_or_else(|| "Entry 需要是十六进制或十进制地址。".to_owned())?;
        let arch = match self.raw_arch_text.trim().to_lowercase().as_str() {
            "x64" | "amd64" | "x86_64" => RawArch::X64,
            _ => return Err("当前版本 Raw Binary 仅支持 x64。".to_owned()),
        };

        Ok(RawLoadOptions {
            base_address,
            entry_address,
            arch,
        })
    }

    fn run_search(&self) -> Vec<SearchResult> {
        let query = self.search_text.trim();
        if query.is_empty() {
            return vec![SearchResult::plain("请输入搜索内容。")];
        }

        let query_lower = query.to_lowercase();
        let mut results = Vec::new();
        results.push(SearchResult::plain(format!("搜索请求：{query}")));

        if let Some(address) = parse_number(query) {
            results.push(SearchResult::jump(
                format!("地址 0x{address:016X}"),
                address,
                format!("VA 0x{address:016X}"),
            ));
        }

        if let Some(pattern) = parse_byte_pattern(query) {
            for file_offset in find_byte_pattern(&self.input_bytes, &pattern)
                .into_iter()
                .take(64)
            {
                if let Some(va) = self.file_offset_to_va(file_offset) {
                    results.push(SearchResult::jump(
                        format!(
                            "字节序列 FO 0x{file_offset:08X} / VA 0x{va:016X} {}",
                            format_byte_pattern(&pattern)
                        ),
                        va,
                        "字节序列".to_owned(),
                    ));
                } else {
                    results.push(SearchResult::plain(format!(
                        "字节序列 FO 0x{file_offset:08X} {}",
                        format_byte_pattern(&pattern)
                    )));
                }
            }
        }

        for name in self.project.user_names() {
            if name.name.to_lowercase().contains(&query_lower)
                || address_matches(name.address, query)
            {
                results.push(SearchResult::jump(
                    format!("用户名称 0x{:016X} {}", name.address, name.name),
                    name.address,
                    name.name,
                ));
            }
        }

        for comment in self.project.address_comments() {
            if comment.text.to_lowercase().contains(&query_lower)
                || address_matches(comment.address, query)
            {
                results.push(SearchResult::jump(
                    format!("地址注释 0x{:016X} {}", comment.address, comment.text),
                    comment.address,
                    "地址注释".to_owned(),
                ));
            }
        }

        for comment in self.project.function_comments() {
            if comment.text.to_lowercase().contains(&query_lower)
                || address_matches(comment.function_start, query)
            {
                results.push(SearchResult::jump(
                    format!(
                        "函数注释 0x{:016X} {}",
                        comment.function_start, comment.text
                    ),
                    comment.function_start,
                    "函数注释".to_owned(),
                ));
            }
        }

        for definition in self.project.manual_definitions() {
            if definition.kind.label().contains(query) || address_matches(definition.address, query)
            {
                results.push(SearchResult::jump(
                    format!(
                        "手动定义 0x{:016X} {}",
                        definition.address,
                        definition.kind.label()
                    ),
                    definition.address,
                    definition.kind.label(),
                ));
            }
        }

        for type_item in self.project.project_types() {
            let signature = type_item.display_signature();
            if type_item.name.to_lowercase().contains(&query_lower)
                || type_item.kind.to_lowercase().contains(&query_lower)
                || type_item.source.to_lowercase().contains(&query_lower)
                || signature.to_lowercase().contains(&query_lower)
            {
                results.push(SearchResult::plain(format!(
                    "类型 [{}] {} - {}",
                    type_item.kind, type_item.name, signature
                )));
            }
        }

        for application in self.project.type_applications() {
            if application.type_name.to_lowercase().contains(&query_lower)
                || address_matches(application.target.address(), query)
            {
                results.push(SearchResult::jump(
                    format!(
                        "类型应用 {} 0x{:016X} -> {}",
                        application.target.label(),
                        application.target.address(),
                        application.type_name
                    ),
                    application.target.address(),
                    application.type_name,
                ));
            }
        }

        let Some(analysis) = &self.analysis else {
            if results.len() == 1 {
                results.push(SearchResult::plain(
                    "尚未打开可分析的 PE 或 Raw Binary 文件。",
                ));
            }
            return results;
        };

        for function in &analysis.functions {
            let name = self
                .project
                .name_for(function.start_va)
                .unwrap_or(&function.name);
            if name.to_lowercase().contains(&query_lower)
                || address_matches(function.start_va, query)
            {
                results.push(SearchResult::jump(
                    format!("函数 0x{:016X} {}", function.start_va, name),
                    function.start_va,
                    name.to_owned(),
                ));
            }
        }

        for bookmark in self.project.bookmarks() {
            if address_matches(bookmark.address, query)
                || self
                    .project
                    .address_comment(bookmark.address)
                    .map(|comment| comment.to_lowercase().contains(&query_lower))
                    .unwrap_or(false)
            {
                results.push(SearchResult::jump(
                    format!("书签 0x{:016X}", bookmark.address),
                    bookmark.address,
                    "书签".to_owned(),
                ));
            }
        }

        for string in &analysis.strings {
            if string.value.to_lowercase().contains(&query_lower)
                || address_matches(string.address, query)
            {
                results.push(SearchResult::jump(
                    format!(
                        "字符串 0x{:016X} [{}] {}",
                        string.address,
                        string.encoding.label(),
                        string.value
                    ),
                    string.address,
                    "字符串".to_owned(),
                ));
            }
        }

        for import in &analysis.imports {
            let name = import.display_name();
            if name.to_lowercase().contains(&query_lower) || address_matches(import.thunk_va, query)
            {
                results.push(SearchResult::jump(
                    format!("导入 0x{:016X} {}", import.thunk_va, name),
                    import.thunk_va,
                    name,
                ));
            }
        }

        for signature in &analysis.runtime_signatures {
            if signature.name.to_lowercase().contains(&query_lower)
                || signature.kind.label().to_lowercase().contains(&query_lower)
                || signature.library.to_lowercase().contains(&query_lower)
                || signature.evidence.to_lowercase().contains(&query_lower)
                || address_matches(signature.address, query)
            {
                results.push(SearchResult::jump(
                    format!(
                        "Runtime 0x{:016X} [{}] {} {}%",
                        signature.address,
                        signature.kind.label(),
                        signature.name,
                        signature.confidence
                    ),
                    signature.address,
                    signature.kind.label(),
                ));
            }
        }

        for function in &analysis.pseudocode_functions {
            let function_name = self
                .project
                .name_for(function.function_start)
                .unwrap_or(&function.name);
            for line in &function.lines {
                let address_match = line
                    .address
                    .map(|address| address_matches(address, query))
                    .unwrap_or(false);
                if line.text.to_lowercase().contains(&query_lower) || address_match {
                    let snippet = search_snippet(&line.text);
                    if let Some(address) = line.address {
                        results.push(SearchResult::jump(
                            format!("伪代码 0x{address:016X} {function_name}: {snippet}"),
                            address,
                            "伪代码".to_owned(),
                        ));
                    } else {
                        results.push(SearchResult::plain(format!(
                            "伪代码 {function_name}: {snippet}"
                        )));
                    }
                }
            }

            for instruction in &function.ir {
                let text = ir_search_text(&instruction.op, &instruction.args, &instruction.comment);
                if text.to_lowercase().contains(&query_lower)
                    || address_matches(instruction.address, query)
                {
                    results.push(SearchResult::jump(
                        format!(
                            "IR 0x{:016X} {}: {}",
                            instruction.address,
                            function_name,
                            search_snippet(&text)
                        ),
                        instruction.address,
                        "IR".to_owned(),
                    ));
                }
            }
        }

        for export in &analysis.exports {
            if export.name.to_lowercase().contains(&query_lower)
                || address_matches(export.va, query)
            {
                results.push(SearchResult::jump(
                    format!(
                        "导出 0x{:016X} {} ordinal {}",
                        export.va, export.name, export.ordinal
                    ),
                    export.va,
                    export.name.clone(),
                ));
            }
        }

        for symbol in &analysis.pdb_symbols {
            let display_name = symbol.display_name();
            let original_name = &symbol.name;
            if display_name.to_lowercase().contains(&query_lower)
                || original_name.to_lowercase().contains(&query_lower)
                || symbol
                    .address
                    .map(|address| address_matches(address, query))
                    .unwrap_or(false)
            {
                if let Some(address) = symbol.address {
                    results.push(SearchResult::jump(
                        format!(
                            "PDB 符号 0x{address:016X} {} {}",
                            symbol.kind.label(),
                            display_name
                        ),
                        address,
                        symbol.kind.label(),
                    ));
                } else {
                    results.push(SearchResult::plain(format!(
                        "PDB 符号 {} {}",
                        symbol.kind.label(),
                        display_name
                    )));
                }
            }
        }

        for type_item in &analysis.pdb_types {
            if type_item.name.to_lowercase().contains(&query_lower)
                || type_item.kind.to_lowercase().contains(&query_lower)
            {
                results.push(SearchResult::plain(format!(
                    "PDB 类型 [{}] {}",
                    type_item.kind, type_item.name
                )));
            }
        }

        for xref in &analysis.xrefs {
            if address_matches(xref.from_va, query)
                || address_matches(xref.to_va, query)
                || xref.kind.label().contains(query)
                || xref.label.to_lowercase().contains(&query_lower)
            {
                results.push(SearchResult::jump(
                    format!(
                        "交叉引用 {:016X} -> {:016X} {}",
                        xref.from_va,
                        xref.to_va,
                        xref.kind.label()
                    ),
                    xref.from_va,
                    xref.kind.label(),
                ));
            }
        }

        if results.len() == 1 {
            results.push(SearchResult::plain("没有匹配结果。"));
        }
        results
    }

    fn runtime_signature_at(&self, address: u64) -> Option<&RuntimeSignature> {
        self.analysis
            .as_ref()?
            .runtime_signatures
            .iter()
            .find(|signature| signature.address == address)
    }

    fn pdb_symbol_at(&self, address: u64) -> Option<&PdbSymbol> {
        self.analysis
            .as_ref()?
            .pdb_symbols
            .iter()
            .find(|symbol| symbol.address == Some(address))
    }

    fn file_offset_to_va(&self, file_offset: u64) -> Option<u64> {
        if let Some(image) = self.project.pe_image() {
            image.file_offset_to_va(file_offset)
        } else if let Some(raw) = self.project.raw_image() {
            raw.file_offset_to_va(file_offset)
        } else {
            None
        }
    }
}

fn normalized_filter(text: &str) -> String {
    text.trim().to_lowercase()
}

fn row_matches_filter(filter: &str, values: &[&str]) -> bool {
    filter.is_empty()
        || values
            .iter()
            .any(|value| value.to_lowercase().contains(filter))
}

fn is_runtime_function_signature(signature: &RuntimeSignature) -> bool {
    matches!(
        signature.target,
        RuntimeSignatureTarget::Function | RuntimeSignatureTarget::Pattern
    )
}

fn runtime_function_signature_in(
    signatures: &[RuntimeSignature],
    address: u64,
) -> Option<&RuntimeSignature> {
    signatures
        .iter()
        .find(|signature| signature.address == address && is_runtime_function_signature(signature))
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

fn require_type_name(text: &str) -> Result<String, String> {
    let name = text.trim();
    if name.is_empty() {
        return Err("类型名不能为空。".to_owned());
    }
    if !name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Err("类型名只能包含字母、数字和下划线。".to_owned());
    }
    Ok(name.to_owned())
}

fn parse_type_fields(text: &str) -> Result<Vec<TypeField>, String> {
    let mut fields = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim().trim_end_matches(';').trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let (type_name, name) = parse_named_type_line(line)
            .ok_or_else(|| format!("第 {} 行字段无法解析：{}", index + 1, line))?;
        fields.push(TypeField {
            name,
            type_name,
            offset: None,
            size: None,
        });
    }
    Ok(fields)
}

fn parse_enum_variants(text: &str) -> Result<Vec<EnumVariant>, String> {
    let mut variants = Vec::new();
    let mut next_value = 0i64;
    for (index, line) in text.lines().enumerate() {
        let line = line.trim().trim_end_matches(',').trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let (name, value) = match line.split_once('=') {
            Some((name, value)) => {
                let value = parse_signed_number(value.trim())
                    .ok_or_else(|| format!("第 {} 行枚举值无法解析：{}", index + 1, line))?;
                (name.trim(), value)
            }
            None => (line, next_value),
        };
        let name = require_type_name(name)?;
        variants.push(EnumVariant { name, value });
        next_value = value.saturating_add(1);
    }
    Ok(variants)
}

fn parse_named_type_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    let (without_array, array_suffix) = if let Some(open) = line.rfind('[') {
        let close = line.rfind(']')?;
        if close > open {
            (
                line[..open].trim(),
                Some(line[open..=close].trim().to_owned()),
            )
        } else {
            (line, None)
        }
    } else {
        (line, None)
    };
    let mut parts = without_array.split_whitespace().collect::<Vec<_>>();
    let mut name = parts.pop()?.trim().to_owned();
    let mut pointer_prefix = String::new();
    while name.starts_with('*') {
        pointer_prefix.push('*');
        name.remove(0);
    }
    let name = require_type_name(&name).ok()?;
    let mut type_name = parts.join(" ");
    if !pointer_prefix.is_empty() {
        if !type_name.is_empty() {
            type_name.push(' ');
        }
        type_name.push_str(&pointer_prefix);
    }
    if let Some(array_suffix) = array_suffix {
        type_name.push_str(&array_suffix);
    }
    (!type_name.trim().is_empty()).then_some((type_name, name))
}

fn parse_signed_number(text: &str) -> Option<i64> {
    let text = text.trim();
    let negative = text.starts_with('-');
    let digits = text.trim_start_matches('-').trim_start_matches('+');
    let value = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        digits.parse::<i64>().ok()?
    };
    Some(if negative { -value } else { value })
}

fn merge_project_type_records(target: &mut Vec<ProjectType>, incoming: Vec<ProjectType>) {
    for type_item in incoming {
        if !target
            .iter()
            .any(|existing| existing.name == type_item.name)
        {
            target.push(type_item);
        }
    }
}

fn is_pdb_project_type(type_item: &ProjectType) -> bool {
    type_item.definition.is_none()
        && (type_item.kind.eq_ignore_ascii_case("UDT")
            || type_item.source.eq_ignore_ascii_case("udt")
            || type_item.source.to_ascii_lowercase().contains("pdb"))
}

fn parse_byte_pattern(text: &str) -> Option<Vec<u8>> {
    let compact = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    if compact.len() < 2
        || compact.len() % 2 != 0
        || !compact
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return None;
    }

    let mut bytes = Vec::with_capacity(compact.len() / 2);
    for index in (0..compact.len()).step_by(2) {
        let byte = u8::from_str_radix(&compact[index..index + 2], 16).ok()?;
        bytes.push(byte);
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
        .filter_map(|(offset, window)| {
            (window == pattern).then(|| u64::try_from(offset).unwrap_or(0))
        })
        .collect()
}

fn format_byte_pattern(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn pdb_symbol_kind_from_label(label: &str) -> PdbSymbolKind {
    [
        PdbSymbolKind::Function,
        PdbSymbolKind::PublicCode,
        PdbSymbolKind::Data,
        PdbSymbolKind::PublicData,
        PdbSymbolKind::UserDefinedType,
        PdbSymbolKind::ProcedureReference,
        PdbSymbolKind::DataReference,
    ]
    .into_iter()
    .find(|kind| kind.label() == label)
    .unwrap_or(PdbSymbolKind::PublicData)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut parts = bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>();
    while parts.len() < 16 {
        parts.push("  ".to_owned());
    }
    parts.join(" ")
}

fn ascii_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            }
        })
        .collect()
}

impl eframe::App for FyIdaApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.handle_shortcuts(ctx);
        self.top_menu(ctx);
        self.toolbar(ctx);
        self.bottom_panels(ctx);
        self.left_panel(ctx);
        self.right_panel(ctx);
        self.central_panel(ctx);
        self.dialogs(ctx);
    }
}

fn configure_fonts(ctx: &Context) {
    let mut fonts = FontDefinitions::default();

    for font_path in [
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\simhei.ttf",
        r"C:\Windows\Fonts\simsun.ttc",
    ] {
        if let Ok(bytes) = std::fs::read(font_path) {
            fonts
                .font_data
                .insert("fy_cjk".to_owned(), FontData::from_owned(bytes));
            fonts
                .families
                .entry(FontFamily::Proportional)
                .or_default()
                .insert(0, "fy_cjk".to_owned());
            fonts
                .families
                .entry(FontFamily::Monospace)
                .or_default()
                .insert(0, "fy_cjk".to_owned());
            break;
        }
    }

    ctx.set_fonts(fonts);
}

fn configure_style(ctx: &Context) {
    let mut visuals = Visuals::light();
    visuals.panel_fill = background_color();
    visuals.window_fill = panel_color();
    visuals.extreme_bg_color = panel_color();
    visuals.widgets.noninteractive.bg_fill = title_color();
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(245, 246, 248);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(221, 235, 255);
    visuals.widgets.active.bg_fill = Color32::from_rgb(179, 212, 255);
    visuals.selection.bg_fill = Color32::from_rgb(221, 235, 255);
    visuals.selection.stroke = Stroke::new(1.0, Color32::from_rgb(0, 90, 156));
    ctx.set_visuals(visuals);
}

fn panel_frame() -> Frame {
    Frame::none()
        .fill(background_color())
        .stroke(Stroke::new(1.0, Color32::from_rgb(200, 205, 210)))
        .inner_margin(egui::Margin::same(6.0))
}

fn panel_title(ui: &mut Ui, title: &str) {
    ui.horizontal(|ui| {
        ui.strong(title);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(APP_NAME).color(comment_color()));
        });
    });
}

fn tab_strip(ui: &mut Ui, labels: &[&str], selected: &mut usize) {
    ui.horizontal_wrapped(|ui| {
        for (index, label) in labels.iter().enumerate() {
            if ui.selectable_label(*selected == index, *label).clicked() {
                *selected = index;
            }
        }
    });
}

fn toolbar_button(ui: &mut Ui, label: &str, tooltip: &str) -> egui::Response {
    ui.add_sized([72.0, 24.0], egui::Button::new(label))
        .on_hover_text(tooltip)
}

fn toolbar_enabled_button(
    ui: &mut Ui,
    enabled: bool,
    label: &str,
    tooltip: &str,
) -> egui::Response {
    ui.add_enabled_ui(enabled, |ui| {
        ui.add_sized([72.0, 24.0], egui::Button::new(label))
    })
    .inner
    .on_hover_text(tooltip)
}

fn disabled_menu_items(ui: &mut Ui, labels: &[&str]) {
    for label in labels {
        ui.add_enabled(false, egui::Button::new(*label));
    }
}

fn placeholder_center(ui: &mut Ui, title: &str, body: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(60.0);
        ui.heading(title);
        ui.label(body);
        ui.label("当前版本仅提供布局占位。");
    });
}

fn placeholder_list(ui: &mut Ui, rows: &[&str]) {
    for row in rows {
        ui.label(*row);
    }
}

fn file_error_disassembly_row(message: &str) -> Vec<DisassemblyRow> {
    vec![DisassemblyRow {
        address: 0,
        bytes: "--".to_owned(),
        mnemonic: "错误".to_owned(),
        operands: String::new(),
        comment: message.to_owned(),
    }]
}

fn log_view(ui: &mut Ui, logs: &[String]) {
    ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
        for line in logs {
            ui.label(line);
        }
    });
}

fn background_color() -> Color32 {
    Color32::from_rgb(247, 247, 244)
}

fn panel_color() -> Color32 {
    Color32::from_rgb(255, 255, 255)
}

fn title_color() -> Color32 {
    Color32::from_rgb(232, 235, 239)
}

fn address_color() -> Color32 {
    Color32::from_rgb(94, 107, 120)
}

fn bytes_color() -> Color32 {
    Color32::from_rgb(138, 111, 61)
}

fn mnemonic_color() -> Color32 {
    Color32::from_rgb(20, 61, 115)
}

fn comment_color() -> Color32 {
    Color32::from_rgb(106, 115, 125)
}

fn error_color() -> Color32 {
    Color32::from_rgb(215, 58, 73)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fyida_analysis::RuntimeSignatureKind;

    fn signature(address: u64, target: RuntimeSignatureTarget) -> RuntimeSignature {
        RuntimeSignature {
            address,
            name: format!("sig_{address:X}"),
            kind: RuntimeSignatureKind::MemoryRoutine,
            target,
            library: "test".to_owned(),
            evidence: "unit test".to_owned(),
            confidence: 90,
        }
    }

    #[test]
    fn runtime_function_filter_matches_functions_and_patterns_only() {
        let signatures = vec![
            signature(0x1000, RuntimeSignatureTarget::Function),
            signature(0x2000, RuntimeSignatureTarget::Pattern),
            signature(0x3000, RuntimeSignatureTarget::Import),
        ];

        assert!(runtime_function_signature_in(&signatures, 0x1000).is_some());
        assert!(runtime_function_signature_in(&signatures, 0x2000).is_some());
        assert!(runtime_function_signature_in(&signatures, 0x3000).is_none());
        assert!(runtime_function_signature_in(&signatures, 0x4000).is_none());
    }

    #[test]
    fn left_filter_matches_any_visible_cell_case_insensitively() {
        assert!(row_matches_filter("mem", &["140001000", "memcpy", "函数"]));
        assert!(row_matches_filter(
            "runtime",
            &["140001000", "sub_140001000", "Runtime CRT"]
        ));
        assert!(!row_matches_filter(
            "crypto",
            &["140001000", "memcpy", "函数"]
        ));
    }

    #[test]
    fn ir_search_text_includes_arguments_and_comments() {
        let text = ir_search_text(
            "call",
            &["CreateFileW".to_owned(), "rcx".to_owned()],
            "source 140001000 call CreateFileW",
        );

        assert!(text.contains("CreateFileW"));
        assert!(text.contains("rcx"));
        assert!(text.contains("source 140001000"));
    }

    #[test]
    fn search_snippet_trims_and_bounds_long_text() {
        let long = format!("  {}  ", "a".repeat(120));
        let snippet = search_snippet(&long);

        assert_eq!(snippet.chars().count(), 99);
        assert!(snippet.ends_with("..."));
    }
}
