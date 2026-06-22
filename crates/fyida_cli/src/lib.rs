use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "fy_ida",
    version,
    about = "FY_IDA 中文逆向分析工作台",
    long_about = "FY_IDA 是面向 Windows x64 PE / Raw Binary 的轻量逆向分析工具。当前 alpha.2 默认启动中文 GUI，headless 分析将在后续版本补齐。"
)]
pub struct Cli {
    #[arg(long, help = "以命令行占位模式运行，不启动 GUI")]
    pub headless: bool,

    #[arg(value_name = "FILE", help = "启动 GUI 时预选的输入文件路径")]
    pub file: Option<PathBuf>,
}

pub fn run_headless(cli: &Cli) -> i32 {
    println!("FY_IDA headless 模式尚未实现。");

    if let Some(file) = &cli.file {
        println!("已接收文件参数：{}", file.display());
    }

    println!("当前版本仅提供 GUI 空壳与文件选择入口。");
    0
}
