use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::Parser;
use fyida_core::RawArch;
use fyida_loader::RawLoadOptions;

#[derive(Debug, Parser)]
#[command(
    name = "fy_ida",
    version,
    about = "FY_IDA 中文逆向分析工作台",
    long_about = "FY_IDA 是面向 Windows x64 PE / Raw Binary 的轻量逆向分析工具。当前 v0.9.0-alpha.1 已提供内部类型模型、C Header 导入/导出、类型应用和 PDB 类型快照。"
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

    #[arg(long, value_name = "HEADER", help = "导入 C Header 类型定义")]
    pub type_header: Option<PathBuf>,

    #[arg(long, value_name = "HEADER", help = "导出内置/导入的类型库为 C Header")]
    pub export_types: Option<PathBuf>,

    #[arg(value_name = "FILE", help = "启动 GUI 时预选的输入文件路径")]
    pub file: Option<PathBuf>,
}

pub fn run_headless(cli: &Cli) -> i32 {
    let Some(file) = &cli.file else {
        println!("FY_IDA headless 模式需要提供输入文件。");
        return 2;
    };
    let cli_types = match load_cli_types(cli) {
        Ok(types) => types,
        Err(message) => {
            eprintln!("类型参数错误：{message}");
            return 2;
        }
    };

    if cli.raw {
        let options = match raw_options(cli) {
            Ok(options) => options,
            Err(message) => {
                eprintln!("Raw Binary 参数错误：{message}");
                return 2;
            }
        };

        return match fyida_loader::load_raw_file_with_bytes(file, options) {
            Ok(loaded) => {
                let image = loaded.image;
                println!("Raw Binary 加载完成：{}", image.file().path().display());
                println!("Arch：{}", image.arch.label());
                println!("Base：0x{:016X}", image.base_address);
                println!(
                    "Entry：VA 0x{:016X} / FO 0x{:08X}",
                    image.entry_address,
                    image.entry_offset().unwrap_or(0)
                );
                println!("Size：{}", image.file().formatted_size());

                match fyida_disasm::disassemble_raw_entry_point(&image, &loaded.bytes) {
                    Ok(instructions) => {
                        println!("Raw 入口点反汇编：");
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
                        println!("Raw 反汇编提示：{error}");
                    }
                }

                let analysis = fyida_analysis::analyze_raw(&image, &loaded.bytes);
                print_static_analysis(&analysis);
                print_type_library(&cli_types);
                0
            }
            Err(error) => {
                eprintln!("Raw Binary 加载失败：{error}");
                1
            }
        };
    }

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

            let mut analysis = fyida_analysis::analyze_pe(&image, &loaded.bytes);
            if let Some(pdb_path) = &cli.pdb {
                match fyida_analysis::apply_pdb_file(&image, &mut analysis, pdb_path) {
                    Ok(summary) => {
                        println!(
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
                        );
                    }
                    Err(error) => println!("PDB 加载失败：{error}"),
                }
            }
            print_static_analysis(&analysis);
            print_type_library(&cli_types);
            0
        }
        Err(error) => {
            eprintln!("PE 加载失败：{error}");
            1
        }
    }
}

fn load_cli_types(cli: &Cli) -> Result<Vec<fyida_core::ProjectType>, String> {
    let mut types = fyida_core::builtin_type_library();
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
        println!(
            "C Header 类型已导入：{} / total {}",
            header_path.display(),
            types.len()
        );
    }

    if let Some(export_path) = &cli.export_types {
        let header = fyida_core::export_c_header_types(&types);
        std::fs::write(export_path, header)
            .map_err(|source| format!("无法导出 C Header {}：{source}", export_path.display()))?;
        println!("C Header 类型已导出：{}", export_path.display());
    }

    Ok(types)
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

fn print_static_analysis(analysis: &fyida_analysis::StaticAnalysis) {
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
    println!("  CFGs：{}", analysis.function_cfgs.len());
    for cfg in analysis.function_cfgs.iter().take(16) {
        println!(
            "    {:016X} blocks {} edges {}",
            cfg.function_start,
            cfg.blocks.len(),
            cfg.edges.len()
        );
    }
    println!(
        "  CallGraph：{} nodes / {} edges",
        analysis.call_graph.nodes.len(),
        analysis.call_graph.edges.len()
    );
    for edge in analysis.call_graph.edges.iter().take(64) {
        println!(
            "    {:016X} -> {:016X} callsite {:016X}",
            edge.caller_va, edge.callee_va, edge.callsite_va
        );
    }
    println!("  PDBRecords：{}", analysis.pe_pdb_records.len());
    for record in &analysis.pe_pdb_records {
        println!(
            "    {} age {} guid {} path {}",
            record.format.label(),
            record.age.unwrap_or(0),
            record.guid.as_deref().unwrap_or("-"),
            record.path
        );
    }
    println!("  PDBSymbols：{}", analysis.pdb_symbols.len());
    for symbol in analysis.pdb_symbols.iter().take(64) {
        let address = symbol
            .address
            .map(|address| format!("{address:016X}"))
            .unwrap_or_else(|| "----------------".to_owned());
        println!(
            "    {} {:<18} {}",
            address,
            symbol.kind.label(),
            symbol.display_name()
        );
    }
    println!("  PDBTypes：{}", analysis.pdb_types.len());
    for type_item in analysis.pdb_types.iter().take(64) {
        println!("    [{}] {}", type_item.kind, type_item.name);
    }
}

fn print_type_library(types: &[fyida_core::ProjectType]) {
    println!("  TypeLibrary：{}", types.len());
    for type_item in types.iter().take(64) {
        println!(
            "    [{}] {} - {}",
            type_item.kind,
            type_item.name,
            type_item.display_signature()
        );
    }
}
