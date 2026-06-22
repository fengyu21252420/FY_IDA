use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "fy_ida",
    version,
    about = "FY_IDA 中文逆向分析工作台",
    long_about = "FY_IDA 是面向 Windows x64 PE / Raw Binary 的轻量逆向分析工具。当前 v0.2.0-alpha.1 已提供 PE Header 解析 MVP。"
)]
pub struct Cli {
    #[arg(long, help = "以命令行占位模式运行，不启动 GUI")]
    pub headless: bool,

    #[arg(value_name = "FILE", help = "启动 GUI 时预选的输入文件路径")]
    pub file: Option<PathBuf>,
}

pub fn run_headless(cli: &Cli) -> i32 {
    let Some(file) = &cli.file else {
        println!("FY_IDA headless 模式需要提供输入文件。");
        return 2;
    };

    match fyida_loader::load_pe_file(file) {
        Ok(image) => {
            println!("PE 加载完成：{}", image.file().path().display());
            println!(
                "Machine：{} (0x{:04X})",
                image.machine_label(),
                image.nt_headers.file_header.machine
            );
            println!("ImageBase：0x{:016X}", image.image_base());
            println!(
                "EntryPoint：VA 0x{:016X} / RVA 0x{:08X}",
                image.entry_point_va(),
                image.entry_point_rva()
            );
            println!("Subsystem：{}", image.subsystem_label());
            println!("Sections：{}", image.sections.len());
            for section in &image.sections {
                println!(
                    "  {} RVA 0x{:08X} VA 0x{:016X} FO 0x{:08X} VS 0x{:X} RAW 0x{:X} {}",
                    section.name,
                    section.virtual_address,
                    section.virtual_address_va(image.image_base()),
                    section.pointer_to_raw_data,
                    section.virtual_size,
                    section.size_of_raw_data,
                    section.permissions()
                );
            }
            0
        }
        Err(error) => {
            eprintln!("PE 加载失败：{error}");
            1
        }
    }
}
