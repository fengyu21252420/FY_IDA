use std::path::{Path, PathBuf};

pub const APP_NAME: &str = "FY_IDA";

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalysisState {
    NoFile,
    NotAnalyzed,
    PlaceholderReady,
    Error(String),
}

impl AnalysisState {
    pub fn label(&self) -> String {
        match self {
            Self::NoFile => "尚未打开文件".to_owned(),
            Self::NotAnalyzed => "已选择文件 / 暂未分析".to_owned(),
            Self::PlaceholderReady => "占位视图已就绪 / 暂未分析".to_owned(),
            Self::Error(message) => format!("错误：{message}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProjectState {
    selected_file: Option<FileSelection>,
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
        self.analysis_state = AnalysisState::NotAnalyzed;
        self.dirty = true;
        self.jump_to(0x1400_01000, Some("入口占位".to_owned()));
    }

    pub fn set_error(&mut self, message: impl Into<String>) {
        self.analysis_state = AnalysisState::Error(message.into());
    }

    pub fn jump_to(&mut self, address: u64, function: Option<String>) {
        self.current_address = Some(address);
        self.current_rva = address.checked_sub(0x1400_00000);
        self.current_file_offset = self.current_rva.map(|rva| rva.saturating_add(0x400));
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
