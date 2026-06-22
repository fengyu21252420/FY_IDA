use std::collections::VecDeque;
use std::path::PathBuf;

use eframe::egui::{
    self, Align, CentralPanel, Color32, Context, FontData, FontDefinitions, FontFamily, Frame,
    Grid, Key, Layout, RichText, ScrollArea, SidePanel, Stroke, TextEdit, TopBottomPanel, Ui,
    Visuals, Window,
};
use fyida_analysis::{
    analyze_pe, analyze_raw, empty_workspace_disassembly, file_error_log_lines,
    pe_entry_disassembly, pe_loaded_log_lines, raw_entry_disassembly, raw_loaded_log_lines,
    startup_log_lines, static_analysis_log_lines, DisassemblyRow, StaticAnalysis,
};
use fyida_core::{
    format_address, sha256_hex, FileSelection, ManualDefinitionKind, ProjectDocument,
    ProjectFunction, ProjectInput, ProjectInputKind, ProjectState, RawArch, RawImage, APP_NAME,
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
    project_path: Option<PathBuf>,
    source_hash: Option<String>,
    logs: Vec<String>,
    search_results: Vec<String>,
    disassembly_rows: Vec<DisassemblyRow>,
    analysis: Option<StaticAnalysis>,
    recent_files: VecDeque<PathBuf>,
}

enum ProjectLoadResult {
    Pe(fyida_core::PeImage, Vec<u8>),
    Raw(RawImage, Vec<u8>),
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
            project_path: None,
            source_hash: None,
            logs: startup_log_lines(),
            search_results: vec!["尚未执行搜索。".to_owned()],
            disassembly_rows: empty_workspace_disassembly(),
            analysis: None,
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
                    self.project_path = None;
                    self.logs.push(message);
                    self.right_tab = 1;
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

        Ok(ProjectDocument::new(
            env!("CARGO_PKG_VERSION"),
            ProjectInput {
                path: selection.path().display().to_string(),
                size_bytes: selection.size_bytes(),
                sha256,
                kind,
            },
            functions,
            self.project.annotations(),
        ))
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
        self.project.apply_annotations(document.annotations);
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

    fn select_path(&mut self, path: PathBuf) {
        match load_file_metadata(&path) {
            Ok(selection) => self.load_selected_file(selection),
            Err(error) => {
                let message = error.to_string();
                self.project.set_error(message.clone());
                self.disassembly_rows = file_error_disassembly_row(&message);
                self.analysis = None;
                self.source_hash = None;
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

    fn apply_pe_image(&mut self, image: fyida_core::PeImage, bytes: &[u8]) {
        let analysis = analyze_pe(&image, bytes);
        let disassembly = pe_entry_disassembly(&image, bytes);
        self.source_hash = Some(sha256_hex(bytes));
        self.project_path = None;
        self.logs.extend(pe_loaded_log_lines(&image));
        self.logs.extend(static_analysis_log_lines(&analysis));
        self.logs.extend(disassembly.log_lines);
        self.disassembly_rows = disassembly.rows;
        self.analysis = Some(analysis);
        self.project.load_pe(image);
        self.center_tab = 0;
        self.right_tab = 1;
        self.bottom_tab = 0;
    }

    fn apply_raw_image(&mut self, image: RawImage, bytes: &[u8]) {
        let analysis = analyze_raw(&image, bytes);
        let disassembly = raw_entry_disassembly(&image, bytes);
        self.source_hash = Some(sha256_hex(bytes));
        self.project_path = None;
        self.logs.extend(raw_loaded_log_lines(&image));
        self.logs.extend(static_analysis_log_lines(&analysis));
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
                                "应用签名库",
                            ],
                        );
                    });

                    ui.menu_button("类型", |ui| {
                        disabled_menu_items(
                            ui,
                            &[
                                "局部类型",
                                "新建结构体",
                                "新建枚举",
                                "编辑函数原型",
                                "导入 C Header",
                                "导出 C Header",
                                "导入类型库",
                            ],
                        );
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
                        ui.label("FY_IDA v0.5.0-alpha.1");
                        ui.label("项目文件与人工标注 MVP。");
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
                    toolbar_button(ui, "后退", "返回上一位置");
                    toolbar_button(ui, "前进", "前进到下一位置");
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
                    toolbar_button(ui, "交叉引用", "查看交叉引用");
                    toolbar_button(ui, "重新分析", "重新分析当前目标");
                    toolbar_button(ui, "函数图", "切换到函数图");
                    toolbar_button(ui, "伪代码", "切换到伪代码");
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
                    2 => placeholder_center(ui, "伪代码", "反编译器将在后续版本启用。"),
                    3 => placeholder_center(
                        ui,
                        "函数图",
                        "CFG 图视图将在反汇编与 basic block 识别后启用。",
                    ),
                    4 => placeholder_center(ui, "调用图", "调用关系图将在分析引擎完成后启用。"),
                    _ => placeholder_center(ui, "IR 视图", "中间表示视图将在反编译器阶段启用。"),
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
        let rows = if let Some(analysis) = &self.analysis {
            analysis
                .functions
                .iter()
                .map(|function| {
                    (
                        function.start_va,
                        format!("{:016X}", function.start_va),
                        self.project
                            .name_for(function.start_va)
                            .unwrap_or(&function.name)
                            .to_owned(),
                        format!(
                            "{} 条指令 / {} 次调用",
                            function.instruction_count, function.call_count
                        ),
                    )
                })
                .collect::<Vec<_>>()
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

        let mut rows = analysis
            .functions
            .iter()
            .map(|function| {
                (
                    function.start_va,
                    self.project
                        .name_for(function.start_va)
                        .unwrap_or(&function.name)
                        .to_owned(),
                    "函数".to_owned(),
                )
            })
            .collect::<Vec<_>>();
        rows.extend(
            analysis
                .exports
                .iter()
                .map(|export| (export.va, export.name.clone(), "导出".to_owned())),
        );
        rows.extend(
            analysis
                .imports
                .iter()
                .map(|import| (import.thunk_va, import.display_name(), "导入".to_owned())),
        );

        if rows.is_empty() {
            placeholder_list(ui, &["当前文件没有可显示名称"]);
            return;
        }

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

    fn right_content(&self, ui: &mut Ui) {
        match RIGHT_TABS[self.right_tab] {
            "交叉引用" => {
                if let Some(analysis) = &self.analysis {
                    if analysis.xrefs.is_empty() {
                        ui.label("暂未发现 direct call / jump 交叉引用。");
                    } else {
                        Grid::new("xref_grid")
                            .num_columns(3)
                            .striped(true)
                            .spacing([10.0, 4.0])
                            .show(ui, |ui| {
                                ui.strong("来源");
                                ui.strong("目标");
                                ui.strong("类型");
                                ui.end_row();

                                for xref in &analysis.xrefs {
                                    ui.label(format!("{:016X}", xref.from_va));
                                    ui.label(format!("{:016X}", xref.to_va));
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
            "局部类型" => placeholder_list(ui, &["暂无局部类型", "后续支持函数原型与结构体"]),
            "结构体" => placeholder_list(ui, &["暂无结构体定义"]),
            _ => self.annotation_panel(ui),
        }
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
            "搜索结果" => log_view(ui, &self.search_results),
            "Python 控制台" => {
                ui.label("Python 控制台将在脚本系统阶段启用。");
                ui.add_enabled(
                    false,
                    TextEdit::singleline(&mut String::new()).hint_text(">>>"),
                );
            }
            "日志" => log_view(ui, &self.logs),
            _ => placeholder_list(ui, &["暂无后台任务"]),
        }
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

    fn hex_view(&self, ui: &mut Ui) {
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

                    if let Some(image) = self.project.pe_image() {
                        ui.label("FO 00000000");
                        ui.label("4D 5A");
                        ui.label("DOS Header / MZ");
                        ui.end_row();

                        ui.label(format!("FO {:08X}", image.dos_header.e_lfanew));
                        ui.label("50 45 00 00");
                        ui.label("NT Header / PE");
                        ui.end_row();

                        ui.label(format!("VA {:016X}", image.entry_point_va()));
                        ui.label(format!("RVA {:08X}", image.entry_point_rva()));
                        ui.label("EntryPoint");
                        ui.end_row();
                    } else if let Some(raw) = self.project.raw_image() {
                        ui.label("FO 00000000");
                        ui.label("Raw Binary 起始字节");
                        ui.label(format!("VA {:016X}", raw.base_address));
                        ui.end_row();

                        ui.label(format!("FO {:08X}", raw.entry_offset().unwrap_or(0)));
                        ui.label("Raw EntryPoint");
                        ui.label(format!("VA {:016X}", raw.entry_address));
                        ui.end_row();
                    } else {
                        ui.label("00001000");
                        ui.label("4D 5A 90 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??");
                        ui.label("MZ..");
                        ui.end_row();
                        ui.label("00001010");
                        ui.label("尚未读取文件字节");
                        ui.label("等待 loader");
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
    }

    fn resolve_jump_input(&self) -> Option<(u64, String)> {
        let text = self.quick_jump_text.trim();

        if let Some(image) = self.project.pe_image() {
            if let Some(raw_rva) = text.strip_prefix("rva:") {
                let rva = parse_number(raw_rva.trim())?;
                return Some((image.rva_to_va(rva), format!("RVA 0x{rva:08X}")));
            }

            if let Some(raw_file_offset) = text.strip_prefix("file:") {
                let file_offset = parse_number(raw_file_offset.trim())?;
                let va = image.file_offset_to_va(file_offset)?;
                return Some((va, format!("FO 0x{file_offset:08X}")));
            }

            let va = parse_number(text)?;
            return Some((va, format!("VA 0x{va:016X}")));
        }

        if let Some(raw) = self.project.raw_image() {
            if let Some(raw_file_offset) = text.strip_prefix("file:") {
                let file_offset = parse_number(raw_file_offset.trim())?;
                let va = raw.file_offset_to_va(file_offset)?;
                return Some((va, format!("FO 0x{file_offset:08X}")));
            }
            if let Some(raw_rva) = text.strip_prefix("rva:") {
                let rva = parse_number(raw_rva.trim())?;
                let va = raw.rva_to_va(rva)?;
                return Some((va, format!("Raw+0x{rva:X}")));
            }
            let va = parse_number(text)?;
            return raw
                .contains_va(va)
                .then_some((va, format!("VA 0x{va:016X}")));
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

    fn run_search(&self) -> Vec<String> {
        let query = self.search_text.trim();
        if query.is_empty() {
            return vec!["请输入搜索内容。".to_owned()];
        }

        let Some(analysis) = &self.analysis else {
            return vec![
                format!("搜索请求：{query}"),
                "尚未打开可分析的 PE 或 Raw Binary 文件。".to_owned(),
            ];
        };

        let query_lower = query.to_lowercase();
        let mut results = Vec::new();
        results.push(format!("搜索请求：{query}"));

        for function in &analysis.functions {
            let name = self
                .project
                .name_for(function.start_va)
                .unwrap_or(&function.name);
            if name.to_lowercase().contains(&query_lower)
                || format!("{:016X}", function.start_va).contains(query)
            {
                results.push(format!("函数 0x{:016X} {}", function.start_va, name));
            }
        }

        for bookmark in self.project.bookmarks() {
            if format!("{:016X}", bookmark.address).contains(query)
                || self
                    .project
                    .address_comment(bookmark.address)
                    .map(|comment| comment.to_lowercase().contains(&query_lower))
                    .unwrap_or(false)
            {
                results.push(format!("书签 0x{:016X}", bookmark.address));
            }
        }

        for string in &analysis.strings {
            if string.value.to_lowercase().contains(&query_lower)
                || format!("{:016X}", string.address).contains(query)
            {
                results.push(format!(
                    "字符串 0x{:016X} [{}] {}",
                    string.address,
                    string.encoding.label(),
                    string.value
                ));
            }
        }

        for import in &analysis.imports {
            let name = import.display_name();
            if name.to_lowercase().contains(&query_lower)
                || format!("{:016X}", import.thunk_va).contains(query)
            {
                results.push(format!("导入 0x{:016X} {}", import.thunk_va, name));
            }
        }

        for export in &analysis.exports {
            if export.name.to_lowercase().contains(&query_lower)
                || format!("{:016X}", export.va).contains(query)
            {
                results.push(format!(
                    "导出 0x{:016X} {} ordinal {}",
                    export.va, export.name, export.ordinal
                ));
            }
        }

        for xref in &analysis.xrefs {
            let from = format!("{:016X}", xref.from_va);
            let to = format!("{:016X}", xref.to_va);
            if from.contains(query) || to.contains(query) || xref.kind.label().contains(query) {
                results.push(format!("交叉引用 {from} -> {to} {}", xref.kind.label()));
            }
        }

        if results.len() == 1 {
            results.push("没有匹配结果。".to_owned());
        }
        results
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
