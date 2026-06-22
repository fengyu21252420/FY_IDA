use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "fy_ida",
    version,
    about = "FY_IDA 中文逆向分析工作台",
    long_about = "FY_IDA 是面向 Windows x64 PE / Raw Binary 的轻量逆向分析工具。当前 v0.4.0-alpha.1 已提供基础静态分析索引。"
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

    match fyida_loader::load_pe_file_with_bytes(file) {
        Ok(loaded) => {
            let image = loaded.image;
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

            match fyida_disasm::disassemble_entry_point(&image, &loaded.bytes) {
                Ok(instructions) => {
                    println!("入口点反汇编：");
                    for instruction in instructions {
                        let comment = if instruction.invalid {
                            " ; 无效 x64 指令占位"
                        } else {
                            ""
                        };
                        println!(
                            "  {:016X}  {:<24} {:<8} {}{}",
                            instruction.address,
                            instruction.bytes_text(),
                            instruction.mnemonic,
                            instruction.operands,
                            comment
                        );
                    }
                }
                Err(error) => {
                    println!("反汇编提示：{error}");
                }
            }

            let analysis = fyida_analysis::analyze_pe(&image, &loaded.bytes);
            println!("基础静态分析：");
            println!("  Functions：{}", analysis.functions.len());
            for function in &analysis.functions {
                println!(
                    "    {:016X} {:<24} size 0x{:X} insns {} calls {}",
                    function.start_va,
                    function.name,
                    function.size,
                    function.instruction_count,
                    function.call_count
                );
            }
            println!("  Strings：{}", analysis.strings.len());
            for string in analysis.strings.iter().take(32) {
                println!(
                    "    {:016X} [{}] {}",
                    string.address,
                    string.encoding.label(),
                    string.value
                );
            }
            println!("  Imports：{}", analysis.imports.len());
            for import in analysis.imports.iter().take(64) {
                println!("    {:016X} {}", import.thunk_va, import.display_name());
            }
            println!("  Exports：{}", analysis.exports.len());
            for export in analysis.exports.iter().take(64) {
                println!(
                    "    {:016X} ordinal {} {}",
                    export.va, export.ordinal, export.name
                );
            }
            println!("  Relocations：{}", analysis.relocations.len());
            for relocation in analysis.relocations.iter().take(32) {
                println!(
                    "    {:016X} RVA 0x{:08X} {}",
                    relocation.va,
                    relocation.rva,
                    relocation.kind_label()
                );
            }
            println!("  Xrefs：{}", analysis.xrefs.len());
            for xref in analysis.xrefs.iter().take(64) {
                println!(
                    "    {:016X} -> {:016X} {}",
                    xref.from_va,
                    xref.to_va,
                    xref.kind.label()
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
