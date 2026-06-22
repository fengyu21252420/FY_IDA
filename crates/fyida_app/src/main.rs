use clap::Parser;
use fyida_cli::Cli;

fn main() {
    let cli = Cli::parse();

    if cli.headless {
        std::process::exit(fyida_cli::run_headless(&cli));
    }

    if let Err(error) = fyida_ui::run(cli.gui_file()) {
        eprintln!("FY_IDA GUI 启动失败：{error}");
        std::process::exit(1);
    }
}
