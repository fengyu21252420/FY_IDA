use fyida_core::FileSelection;

#[derive(Debug, Clone)]
pub struct DisassemblyRow {
    pub address: u64,
    pub bytes: &'static str,
    pub mnemonic: &'static str,
    pub operands: String,
    pub comment: String,
}

pub fn placeholder_disassembly(selected_file: Option<&FileSelection>) -> Vec<DisassemblyRow> {
    match selected_file {
        Some(file) => vec![
            DisassemblyRow {
                address: 0x1400_01000,
                bytes: "?? ?? ?? ??",
                mnemonic: "db",
                operands: format!("{} 字节", file.size_bytes()),
                comment: "已选择文件，暂未分析 PE / Raw Binary".to_owned(),
            },
            DisassemblyRow {
                address: 0x1400_01004,
                bytes: "?? ??",
                mnemonic: "db",
                operands: file.display_name().to_owned(),
                comment: "等待后续 loader 与 x64 反汇编实现".to_owned(),
            },
            DisassemblyRow {
                address: 0x1400_01006,
                bytes: "??",
                mnemonic: "nop",
                operands: String::new(),
                comment: "占位指令行，用于验证中文 GUI 布局".to_owned(),
            },
        ],
        None => vec![
            DisassemblyRow {
                address: 0x1400_01000,
                bytes: "48 89 5C 24 08",
                mnemonic: "mov",
                operands: "[rsp+8], rbx".to_owned(),
                comment: "示例行：打开文件后显示所选文件状态".to_owned(),
            },
            DisassemblyRow {
                address: 0x1400_01005,
                bytes: "57",
                mnemonic: "push",
                operands: "rdi".to_owned(),
                comment: "尚未进行真实反汇编".to_owned(),
            },
            DisassemblyRow {
                address: 0x1400_01006,
                bytes: "48 83 EC 20",
                mnemonic: "sub",
                operands: "rsp, 20h".to_owned(),
                comment: "占位反汇编视图".to_owned(),
            },
        ],
    }
}

pub fn startup_log_lines() -> Vec<String> {
    vec![
        "FY_IDA GUI 已启动。".to_owned(),
        "当前版本为 v0.1.0-alpha.2：中文 GUI 空壳与文件选择入口。".to_owned(),
        "loader 尚未解析 PE，选择文件后仅记录路径与大小。".to_owned(),
    ]
}

pub fn file_selected_log_lines(file: &FileSelection) -> Vec<String> {
    vec![
        format!("已选择文件：{}", file.path().display()),
        format!("文件大小：{}", file.formatted_size()),
        "分析状态：暂未分析。".to_owned(),
    ]
}
