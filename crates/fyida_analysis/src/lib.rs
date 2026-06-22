use fyida_core::{FileSelection, PeImage};
use fyida_disasm::disassemble_entry_point;

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

pub fn empty_workspace_disassembly() -> Vec<DisassemblyRow> {
    empty_workspace_rows()
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

pub fn startup_log_lines() -> Vec<String> {
    vec![
        "FY_IDA GUI 已启动。".to_owned(),
        "当前版本：v0.3.0-alpha.1 开发中，x64 入口点反汇编已接入 GUI。".to_owned(),
        "可打开 Windows x64 PE 文件并显示入口点附近真实指令。".to_owned(),
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

pub fn file_error_log_lines(file: &FileSelection, message: &str) -> Vec<String> {
    vec![
        format!("打开文件失败：{}", file.path().display()),
        format!("错误：{message}"),
    ]
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
