use fyida_core::{FileSelection, PeImage};

#[derive(Debug, Clone)]
pub struct DisassemblyRow {
    pub address: u64,
    pub bytes: String,
    pub mnemonic: String,
    pub operands: String,
    pub comment: String,
}

pub fn placeholder_disassembly(pe_image: Option<&PeImage>) -> Vec<DisassemblyRow> {
    match pe_image {
        Some(image) => pe_summary_rows(image),
        None => empty_workspace_rows(),
    }
}

pub fn startup_log_lines() -> Vec<String> {
    vec![
        "FY_IDA GUI 已启动。".to_owned(),
        "当前版本：v0.2.0-alpha.1 开发中，PE Loader MVP 已接入 GUI。".to_owned(),
        "可打开 Windows PE 文件并显示 DOS/NT/Header 与 section 基础信息。".to_owned(),
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

fn pe_summary_rows(image: &PeImage) -> Vec<DisassemblyRow> {
    let mut rows = vec![
        DisassemblyRow {
            address: image.entry_point_va(),
            bytes: "--".to_owned(),
            mnemonic: "entry".to_owned(),
            operands: format!("RVA 0x{:08X}", image.entry_point_rva()),
            comment: "PE 入口点；反汇编将在后续版本接入".to_owned(),
        },
        DisassemblyRow {
            address: image.image_base(),
            bytes: "--".to_owned(),
            mnemonic: "imagebase".to_owned(),
            operands: format!("0x{:016X}", image.image_base()),
            comment: format!("{} / {}", image.machine_label(), image.subsystem_label()),
        },
    ];

    rows.extend(image.sections.iter().map(|section| DisassemblyRow {
        address: section.virtual_address_va(image.image_base()),
        bytes: "--".to_owned(),
        mnemonic: "section".to_owned(),
        operands: format!(
            "{} RVA 0x{:08X} FO 0x{:08X}",
            section.name, section.virtual_address, section.pointer_to_raw_data
        ),
        comment: format!(
            "VS 0x{:X} RAW 0x{:X} 权限 {}",
            section.virtual_size,
            section.size_of_raw_data,
            section.permissions()
        ),
    }));

    rows
}

fn empty_workspace_rows() -> Vec<DisassemblyRow> {
    vec![
        DisassemblyRow {
            address: 0x1400_01000,
            bytes: "48 89 5C 24 08".to_owned(),
            mnemonic: "mov".to_owned(),
            operands: "[rsp+8], rbx".to_owned(),
            comment: "示例行：打开 PE 后会显示入口点与 Header 摘要".to_owned(),
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
