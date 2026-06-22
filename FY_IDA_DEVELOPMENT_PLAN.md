# FY_IDA 开发计划清单

更新时间：2026-06-22

目标：开发一个类似 IDA Professional 9.3 工作流、但大幅裁剪后的轻量逆向分析软件。优先面向 Windows x64 PE 和 Raw Binary 静态分析，最终可以单独一个 exe 运行。该项目不复制 IDA 的代码、图标、私有数据库格式或专有界面细节，只实现自有架构和自有交互。

适用用户：网络安全工程师、恶意样本分析人员、Windows PE 逆向分析人员。

## 1. 产品定位

- 软件类型：Windows 本地 GUI 逆向分析器，附带 headless/batch 命令行模式。
- 主要平台：Windows。
- 主要分析对象：Windows x64 PE、x64 Raw Binary。
- 主要能力：反汇编、静态分析、xref、函数图、类型系统、PDB、Python 自动化、x64 反编译。
- 不做方向：多平台多架构、动态调试器、团队协作、云端元数据、license 管理、native C/C++ 插件 SDK。
- 单 exe 要求：主程序应能单 exe 启动和完成核心功能。Python 插件和外部类型库可以作为可选附加目录存在，但没有它们时核心 exe 仍可运行。

## 2. 已确认功能取舍总览

### 2.1 需要保留

- PE 文件加载。
- Raw Binary / 固件裸文件加载。
- PDB 调试符号加载。
- x64 反汇编。
- 自动识别代码和数据。
- 函数边界识别。
- 跳转表 / switch 识别。
- 交叉引用 Xref。
- 字符串自动提取。
- 导入表 / 导出表解析。
- 重定位信息解析。
- 保存 / 打开分析项目数据库。
- 重命名函数、标签和全局变量。
- 注释功能。
- 书签功能。
- 手动把字节改成代码 / 数据。
- 段 / Section 管理。
- 搜索功能。
- 撤销 / 重做。
- 十六进制视图。
- 线性反汇编视图。
- 函数列表窗口。
- 名称 / 符号列表窗口。
- 字符串列表窗口。
- 导入 / 导出列表窗口。
- 交叉引用列表窗口。
- 函数控制流图 CFG。
- 全局 Xref 图 / 调用图。
- 快速跳转 / Jump Anywhere。
- 多标签页 / 停靠窗口布局。
- 结构体 / union / enum 类型编辑。
- 函数原型编辑。
- 局部类型窗口。
- C Header 导入。
- C Header 导出。
- PDB 类型恢复。
- 类型库。
- x64 伪 C 反编译。
- 批量反编译 / Decompile All。
- 栈变量 / 局部变量识别。
- 类型传播。
- 反编译表达式优化。
- IR / 微码视图。
- 函数签名库。
- 编译器 / 运行库函数识别。
- 符号 Demangle。
- 脚本控制台。
- Python API。
- Python 插件加载系统。
- Headless / Batch 分析命令行。
- API 文档与示例脚本 / 示例插件。

### 2.2 明确不做

- ELF 文件加载。
- Mach-O 文件加载。
- COFF / OBJ / LIB 文件加载。
- DEX / Java / .NET 字节码加载。
- Intel HEX / Motorola S-record 文件加载。
- Windows Crash Dump / Minidump 加载。
- 压缩包 / 归档内文件识别。
- DWARF 调试符号加载。
- x86 32-bit 反汇编。
- ARM 32-bit / Thumb 反汇编。
- ARM64 / AArch64 反汇编。
- MIPS 32/64 反汇编。
- PowerPC 32/64 反汇编。
- RISC-V 32/64 反汇编。
- V850 / RH850 反汇编。
- TriCore 反汇编。
- 其他嵌入式架构反汇编。
- Patch Bytes / 修改字节。
- 暗色主题。
- Objective-C 类型 / 类 / 方法解析。
- Go 语言符号 / 类型恢复。
- 多架构反编译。
- 混淆表达式简化。
- 本地调试器：启动 / 附加进程。
- 断点。
- 单步 / 步过 / 运行到光标。
- 寄存器窗口。
- 内存窗口。
- 栈窗口。
- 调用栈窗口。
- 远程调试。
- 执行 Trace / 记录运行路径。
- 公共函数元数据服务。
- 私有团队元数据服务器。
- C/C++ 插件 SDK。
- 自定义 Loader。
- 自定义 Processor Module。
- 团队协作项目。
- 分析结果同步 / 合并。
- 账号 / 权限 / License 管理。

## 3. 技术路线建议

### 3.1 推荐技术栈

- 主语言：Rust。
- GUI：egui / eframe。
- 反汇编：优先 Zydis 或 iced-x86；也可评估 Capstone。
- PE 解析：object、goblin、pelite、或自研轻量 PE parser。
- PDB 解析：pdb crate，必要时补充 DIA SDK 适配层。
- 项目数据库：SQLite 或自定义二进制数据库。
- 图布局：petgraph + 自研布局，或集成 Graphviz 布局算法。
- C Header 解析：tree-sitter-c、libclang、或 clang-sys。
- Python 嵌入：PyO3 或 rustpython；如果单 exe 优先，先将 Python 插件作为后期可选模块。
- 命令行：clap。
- 日志：tracing。
- 序列化：serde。

### 3.2 建议架构

```text
fy_ida.exe
  app/
    gui shell
    docking layout
    command palette
  core/
    project database
    address model
    symbol model
    type model
    undo/redo command model
  loaders/
    pe loader
    raw binary loader
  analysis/
    recursive descent analyzer
    function discovery
    xref engine
    string scanner
    switch recognizer
    relocation analyzer
    signature matcher
  disasm/
    x64 decoder abstraction
    instruction formatter
  decompiler/
    lifter
    IR
    data flow
    type propagation
    pseudo C printer
  pdb/
    symbol loader
    type loader
  ui_views/
    linear disasm
    hex view
    functions
    names
    strings
    imports exports
    xrefs
    CFG graph
    call graph
    local types
  scripting/
    Python API
    console
    plugin loader
  cli/
    headless analyze
    export json/csv
```

### 3.3 核心设计原则

- 地址统一使用 VA/RVA/File Offset 三元映射，所有视图只消费统一地址模型。
- 项目数据库保存用户分析结果，不直接修改原始二进制。
- 自动分析结果和用户手动修改分层保存，用户修改优先。
- 每个 UI 操作尽量映射成 command，方便撤销/重做和脚本复用。
- 反编译器作为独立内部库，不直接耦合 GUI。
- Headless 模式复用与 GUI 相同的 loader、analysis、database 和 export 层。

## 4. 开发里程碑

### 4.1 Milestone 0：项目骨架

- [ ] 建立 Rust workspace。
- [ ] 建立 GUI app crate。
- [ ] 建立 core crate。
- [ ] 建立 loader crate。
- [ ] 建立 disasm crate。
- [ ] 建立 analysis crate。
- [ ] 建立 cli crate。
- [ ] 建立 sample 测试文件目录。
- [ ] 建立单元测试、集成测试、基础 CI 脚本。
- [ ] 建立 release 打包脚本，目标为单 exe。

验收标准：

- [ ] `fy_ida.exe` 能启动空白 GUI。
- [ ] `fy_ida.exe --help` 能显示命令行帮助。
- [ ] 项目能一键构建 release exe。

### 4.2 Milestone 1：PE/x64 静态分析 MVP

- [ ] 实现 PE 文件打开。
- [ ] 解析 DOS Header、NT Header、Section Table。
- [ ] 解析 ImageBase、EntryPoint、Subsystem、Machine、Characteristics。
- [ ] 建立 VA/RVA/File Offset 映射。
- [ ] 解析 imports。
- [ ] 解析 exports。
- [ ] 解析 relocations。
- [ ] 集成 x64 反汇编后端。
- [ ] 从入口点进行递归下降反汇编。
- [ ] 识别 direct call、direct jmp、conditional branch、ret。
- [ ] 生成初步函数列表。
- [ ] 提取 ASCII 字符串。
- [ ] 提取 UTF-16LE 字符串。
- [ ] 建立代码引用。
- [ ] 建立数据引用。
- [ ] 建立导入 API 引用。

验收标准：

- [ ] 打开一个 x64 PE 后能显示入口点反汇编。
- [ ] 函数列表里至少包含 entry point 和 direct call 目标。
- [ ] 字符串列表可以跳转到字符串地址。
- [ ] 导入表可以列出 DLL 和 API。
- [ ] xref 可以显示某字符串或导入 API 被哪里引用。

### 4.3 Milestone 2：基础 GUI 工作流

- [ ] 实现主窗口。
- [ ] 实现菜单栏。
- [ ] 实现文件打开。
- [ ] 实现最近文件列表。
- [ ] 实现线性反汇编视图。
- [ ] 实现 Hex View。
- [ ] 实现函数列表窗口。
- [ ] 实现名称 / 符号列表窗口。
- [ ] 实现字符串列表窗口。
- [ ] 实现导入 / 导出列表窗口。
- [ ] 实现 Xref 窗口。
- [ ] 实现 section 窗口。
- [ ] 实现地址跳转。
- [ ] 实现函数名跳转。
- [ ] 实现字符串关键词跳转。
- [ ] 实现多标签页。
- [ ] 实现基础停靠布局。

验收标准：

- [ ] 用户能从函数列表跳到反汇编。
- [ ] 用户能从字符串列表跳到数据地址或引用点。
- [ ] 用户能从导入表跳到引用该 API 的代码。
- [ ] 用户能输入地址或名称快速跳转。

### 4.4 Milestone 3：项目数据库与人工分析

- [ ] 设计项目文件格式。
- [ ] 保存原始文件 hash、路径、大小、加载参数。
- [ ] 保存函数列表。
- [ ] 保存符号名称。
- [ ] 保存注释。
- [ ] 保存书签。
- [ ] 保存手动代码/数据定义。
- [ ] 保存类型信息。
- [ ] 保存 UI 布局。
- [ ] 实现打开已有项目。
- [ ] 实现另存为项目。
- [ ] 实现自动分析缓存。
- [ ] 实现重命名函数。
- [ ] 实现重命名标签。
- [ ] 实现重命名全局变量。
- [ ] 实现地址注释。
- [ ] 实现函数注释。
- [ ] 实现书签添加和删除。
- [ ] 实现手动改为代码。
- [ ] 实现手动改为数据。
- [ ] 实现撤销 / 重做命令栈。

验收标准：

- [ ] 重命名和注释保存后重开仍存在。
- [ ] 书签保存后重开仍存在。
- [ ] 用户手动修改优先于自动分析结果。
- [ ] 撤销 / 重做覆盖重命名、注释、书签、代码/数据转换。

### 4.5 Milestone 4：更完整的静态分析

- [ ] 改进函数边界识别。
- [ ] 识别 prologue/epilogue 模式。
- [ ] 识别 tail call。
- [ ] 识别 thunk 函数。
- [ ] 识别 import thunk。
- [ ] 识别 RIP-relative 数据引用。
- [ ] 识别 jump table。
- [ ] 识别 switch case 目标。
- [ ] 识别只读数据中的指针。
- [ ] 建立更完整的 xref 索引。
- [ ] 建立函数调用图。
- [ ] 建立 basic block。
- [ ] 建立函数 CFG。
- [ ] 实现 CFG 图视图。
- [ ] 实现全局调用图视图。
- [ ] 实现搜索地址。
- [ ] 实现搜索字节序列。
- [ ] 实现搜索字符串。
- [ ] 实现搜索函数名。
- [ ] 实现搜索导入 API。
- [ ] 实现搜索注释。

验收标准：

- [ ] switch 样本可以显示多个 case 分支。
- [ ] CFG 能显示 basic block 和跳转边。
- [ ] 调用图能显示 entry point 到若干函数的调用关系。
- [ ] 搜索能跨函数、字符串、导入、注释工作。

### 4.6 Milestone 5：PDB 与符号能力

- [ ] 加载外部 PDB 文件。
- [ ] 自动匹配 PE Debug Directory 中的 PDB 信息。
- [ ] 恢复函数名。
- [ ] 恢复全局变量名。
- [ ] 恢复源码文件路径信息。
- [ ] 恢复函数原型。
- [ ] 恢复 struct。
- [ ] 恢复 union。
- [ ] 恢复 enum。
- [ ] 恢复 class 基本结构。
- [ ] 将 PDB 类型写入项目类型库。
- [ ] 在反汇编视图显示 PDB 名称。
- [ ] 在函数列表显示 PDB 名称。
- [ ] 支持 MSVC 符号 demangle。
- [ ] 支持 C++ 符号 demangle。
- [ ] 评估并支持 Rust 符号 demangle。

验收标准：

- [ ] 带 PDB 的 PE 打开后函数名从 `sub_xxx` 变为真实名称。
- [ ] 类型窗口能看到从 PDB 恢复的结构体和枚举。
- [ ] 反汇编视图中调用目标显示 demangle 后的可读名称。

### 4.7 Milestone 6：类型系统

- [ ] 设计内部类型模型。
- [ ] 支持整数类型。
- [ ] 支持指针类型。
- [ ] 支持数组类型。
- [ ] 支持 struct。
- [ ] 支持 union。
- [ ] 支持 enum。
- [ ] 支持 typedef。
- [ ] 支持函数类型。
- [ ] 支持调用约定。
- [ ] 实现函数原型编辑器。
- [ ] 实现结构体编辑器。
- [ ] 实现 enum 编辑器。
- [ ] 实现局部类型窗口。
- [ ] 实现类型搜索。
- [ ] 实现类型应用到地址。
- [ ] 实现类型应用到函数。
- [ ] 实现 C Header 导入。
- [ ] 实现 C Header 导出。
- [ ] 内置最小 Windows API 类型库。
- [ ] 内置最小 CRT 类型库。
- [ ] 支持外部类型库导入。

验收标准：

- [ ] 用户能创建 `struct CONFIG` 并应用到变量或参数。
- [ ] 函数原型修改后，调用点显示更可读的参数。
- [ ] `.h` 文件导入后能在类型窗口看到类型。
- [ ] 项目类型能导出为 `.h`。

### 4.8 Milestone 7：签名与运行库识别

- [ ] 设计函数签名格式。
- [ ] 设计签名生成工具。
- [ ] 实现签名匹配器。
- [ ] 建立最小 CRT 签名库。
- [ ] 建立常见 MSVC runtime 识别规则。
- [ ] 识别 `__security_check_cookie`。
- [ ] 识别 CRT startup。
- [ ] 识别异常处理相关函数。
- [ ] 识别常见 memcpy/memset/memcmp 模式。
- [ ] 支持用户导入本地签名库。
- [ ] 在函数列表标记库函数。

验收标准：

- [ ] 静态链接 CRT 样本中部分库函数能被命名。
- [ ] 用户可以过滤或折叠库函数，专注业务逻辑。

### 4.9 Milestone 8：Headless 与导出

- [ ] 实现 `fy_ida.exe --headless analyze <file>`。
- [ ] 支持指定 raw binary 参数：base、entry、arch。
- [ ] 支持导出 JSON。
- [ ] 支持导出 CSV。
- [ ] 支持导出函数列表。
- [ ] 支持导出字符串列表。
- [ ] 支持导出 imports。
- [ ] 支持导出 exports。
- [ ] 支持导出 xrefs。
- [ ] 支持运行脚本后导出结果。
- [ ] 支持批量分析目录。
- [ ] 支持超时控制。
- [ ] 支持错误报告。

验收标准：

- [ ] 命令行可以批量分析一批 PE 并输出 JSON 报告。
- [ ] GUI 和 headless 输出的基础分析结果一致。

### 4.10 Milestone 9：Python 自动化与插件

- [ ] 选择嵌入方案：PyO3 或 RustPython。
- [ ] 定义 Python API 对象模型。
- [ ] 暴露项目对象。
- [ ] 暴露函数遍历。
- [ ] 暴露指令遍历。
- [ ] 暴露字符串列表。
- [ ] 暴露 imports / exports。
- [ ] 暴露 xrefs。
- [ ] 暴露名称修改。
- [ ] 暴露注释修改。
- [ ] 暴露书签修改。
- [ ] 暴露类型查询。
- [ ] 暴露命令行参数。
- [ ] 实现脚本控制台。
- [ ] 实现运行脚本文件。
- [ ] 实现插件目录扫描。
- [ ] 实现插件 manifest。
- [ ] 实现插件菜单注册。
- [ ] 实现插件右键菜单注册。
- [ ] 实现插件分析回调。
- [ ] 实现插件错误隔离。
- [ ] 编写 API 文档。
- [ ] 编写示例脚本：列出 imports。
- [ ] 编写示例脚本：查找字符串 xref。
- [ ] 编写示例脚本：批量重命名。
- [ ] 编写示例插件：恶意 API 打分器。

验收标准：

- [ ] 用户可以在控制台运行 Python 脚本查询当前函数。
- [ ] 插件可以在菜单中出现并执行。
- [ ] 插件可以读取 imports、strings、xrefs 并输出结果窗口。

### 4.11 Milestone 10：x64 反编译器一期

备注：这是全项目最大工程量，建议等静态分析和类型系统稳定后再做。

- [ ] 设计 IR。
- [ ] 实现 x64 指令 lifter。
- [ ] 支持寄存器 SSA 或近似 SSA。
- [ ] 支持基本块 IR。
- [ ] 支持控制流结构化输入。
- [ ] 支持栈变量识别。
- [ ] 支持参数位置识别。
- [ ] 支持局部变量命名。
- [ ] 支持常量传播。
- [ ] 支持复制传播。
- [ ] 支持死代码消除。
- [ ] 支持简单表达式合并。
- [ ] 支持 if/else 输出。
- [ ] 支持 while/for 近似输出。
- [ ] 支持 switch 输出。
- [ ] 支持调用表达式输出。
- [ ] 支持类型传播。
- [ ] 支持函数原型影响反编译结果。
- [ ] 支持 PDB 类型影响反编译结果。
- [ ] 实现伪 C 视图。
- [ ] 实现汇编和伪 C 地址同步。
- [ ] 实现批量反编译。
- [ ] 实现伪代码搜索。
- [ ] 实现 IR / 微码视图。

验收标准：

- [ ] 简单 x64 函数能输出可读伪 C。
- [ ] 调用 WinAPI 的函数能显示 API 名称和参数。
- [ ] 带栈变量的函数能显示局部变量。
- [ ] 类型修改后反编译结果会更新。
- [ ] 批量反编译可以缓存结果并支持搜索。

## 5. 功能细化清单

### 5.1 文件加载

- [x] 需要：PE 文件加载。
- [x] 需要：Raw Binary / 固件裸文件加载。
- [x] 需要：PDB 调试符号加载。
- [ ] 不需要：ELF 文件加载。
- [ ] 不需要：Mach-O 文件加载。
- [ ] 不需要：COFF / OBJ / LIB 文件加载。
- [ ] 不需要：DEX / Java / .NET 字节码加载。
- [ ] 不需要：Intel HEX / Motorola S-record 文件加载。
- [ ] 不需要：Windows Crash Dump / Minidump 加载。
- [ ] 不需要：压缩包 / 归档内文件识别。
- [ ] 不需要：DWARF 调试符号加载。

### 5.2 架构和反汇编

- [x] 需要：x64 反汇编。
- [x] 需要：自动识别代码和数据。
- [x] 需要：函数边界识别。
- [x] 需要：跳转表 / switch 识别。
- [x] 需要：交叉引用 Xref。
- [x] 需要：字符串自动提取。
- [x] 需要：导入表 / 导出表解析。
- [x] 需要：重定位信息解析。
- [ ] 不需要：x86 32-bit 反汇编。
- [ ] 不需要：ARM 32-bit / Thumb 反汇编。
- [ ] 不需要：ARM64 / AArch64 反汇编。
- [ ] 不需要：MIPS 32/64 反汇编。
- [ ] 不需要：PowerPC 32/64 反汇编。
- [ ] 不需要：RISC-V 32/64 反汇编。
- [ ] 不需要：V850 / RH850 反汇编。
- [ ] 不需要：TriCore 反汇编。
- [ ] 不需要：其他嵌入式架构反汇编。

### 5.3 项目数据库和人工标注

- [x] 需要：保存 / 打开分析项目数据库。
- [x] 需要：重命名函数、标签和全局变量。
- [x] 需要：注释功能。
- [x] 需要：书签功能。
- [x] 需要：手动把字节改成代码 / 数据。
- [x] 需要：段 / Section 管理。
- [x] 需要：搜索功能。
- [x] 需要：撤销 / 重做。
- [ ] 不需要：Patch Bytes / 修改字节。

### 5.4 UI 视图

- [x] 需要：十六进制视图。
- [x] 需要：线性反汇编视图。
- [x] 需要：函数列表窗口。
- [x] 需要：名称 / 符号列表窗口。
- [x] 需要：字符串列表窗口。
- [x] 需要：导入 / 导出列表窗口。
- [x] 需要：交叉引用列表窗口。
- [x] 需要：函数控制流图 CFG。
- [x] 需要：全局 Xref 图 / 调用图。
- [x] 需要：快速跳转 / Jump Anywhere。
- [x] 需要：多标签页 / 停靠窗口布局。
- [ ] 不需要：暗色主题。

### 5.5 类型系统

- [x] 需要：结构体 / Union / Enum 类型编辑。
- [x] 需要：函数原型编辑。
- [x] 需要：局部类型窗口。
- [x] 需要：C Header 导入。
- [x] 需要：C Header 导出。
- [x] 需要：PDB 类型恢复。
- [x] 需要：类型库。
- [ ] 不需要：Objective-C 类型 / 类 / 方法解析。
- [ ] 不需要：Go 语言符号 / 类型恢复。

### 5.6 反编译

- [x] 需要：x64 伪 C 反编译。
- [x] 需要：批量反编译 / Decompile All。
- [x] 需要：栈变量 / 局部变量识别。
- [x] 需要：类型传播。
- [x] 需要：反编译表达式优化。
- [x] 需要：IR / 微码视图。
- [ ] 不需要：多架构反编译。
- [ ] 不需要：混淆表达式简化。

### 5.7 调试器

- [ ] 不需要：本地调试器：启动 / 附加进程。
- [ ] 不需要：断点。
- [ ] 不需要：单步 / 步过 / 运行到光标。
- [ ] 不需要：寄存器窗口。
- [ ] 不需要：内存窗口。
- [ ] 不需要：栈窗口。
- [ ] 不需要：调用栈窗口。
- [ ] 不需要：远程调试。
- [ ] 不需要：执行 Trace / 记录运行路径。

### 5.8 签名和识别

- [x] 需要：函数签名库。
- [x] 需要：编译器 / 运行库函数识别。
- [x] 需要：符号 Demangle。
- [ ] 不需要：公共函数元数据服务。
- [ ] 不需要：私有团队元数据服务器。

### 5.9 自动化和插件

- [x] 需要：脚本控制台。
- [x] 需要：Python API。
- [x] 需要：Python 插件加载系统。
- [x] 需要：Headless / Batch 分析命令行。
- [x] 需要：API 文档与示例脚本 / 示例插件。
- [ ] 不需要：C/C++ 插件 SDK。
- [ ] 不需要：自定义 Loader。
- [ ] 不需要：自定义 Processor Module。

### 5.10 团队和商业化

- [ ] 不需要：团队协作项目。
- [ ] 不需要：分析结果同步 / 合并。
- [ ] 不需要：账号 / 权限 / License 管理。

## 6. 初始项目目录建议

```text
FY_IDA/
  Cargo.toml
  crates/
    fyida_app/
    fyida_core/
    fyida_loader/
    fyida_pe/
    fyida_raw/
    fyida_disasm/
    fyida_analysis/
    fyida_pdb/
    fyida_types/
    fyida_decompiler/
    fyida_scripting/
    fyida_cli/
  assets/
    fonts/
    icons/
  samples/
    pe/
    raw/
  docs/
    architecture.md
    file_format.md
    python_api.md
    plugin_api.md
    decompiler_ir.md
  plugins/
    examples/
  tests/
    fixtures/
  tools/
    signature_builder/
```

## 7. 项目数据库草案

推荐优先 SQLite，原因是调试方便、迁移方便、适合增量保存。后期如需极致性能，再评估自定义格式。

### 7.1 必要表

- `project_meta`：项目版本、创建时间、原文件 hash、原文件路径。
- `input_files`：输入文件记录。
- `segments`：内存段 / section。
- `functions`：函数地址、大小、名称、flags。
- `basic_blocks`：基本块范围。
- `instructions`：地址、长度、字节、助记符缓存、操作数缓存。
- `names`：用户名称、自动名称、PDB 名称。
- `comments`：地址注释、函数注释。
- `bookmarks`：书签。
- `xrefs`：from、to、类型。
- `strings`：地址、编码、内容。
- `imports`：DLL、API、IAT 地址。
- `exports`：导出名称、ordinal、地址。
- `relocations`：重定位地址和类型。
- `types`：类型定义。
- `function_prototypes`：函数原型。
- `analysis_tasks`：分析任务和状态。
- `decompiler_cache`：伪 C、IR、时间戳、依赖版本。
- `undo_log`：撤销/重做记录。
- `ui_state`：布局和最近打开视图。

### 7.2 数据库迁移

- [ ] 每个 release 增加 schema version。
- [ ] 项目打开时自动迁移旧版本。
- [ ] 迁移失败要备份旧项目，不破坏用户数据。

## 8. 核心 API 草案

### 8.1 Rust 内部接口

```rust
pub trait Loader {
    fn probe(&self, bytes: &[u8]) -> ProbeResult;
    fn load(&self, bytes: &[u8], options: LoadOptions) -> Result<LoadedImage>;
}

pub trait Disassembler {
    fn decode(&self, image: &LoadedImage, va: u64) -> Result<Instruction>;
}

pub trait Analyzer {
    fn analyze(&mut self, project: &mut Project, options: AnalyzeOptions) -> Result<()>;
}
```

### 8.2 Python API 初稿

```python
import fyida

project = fyida.current_project()

for func in project.functions():
    print(hex(func.start), func.name)

for s in project.strings():
    if "http" in s.value.lower():
        for xr in project.xrefs_to(s.address):
            project.set_comment(xr.from_address, "references URL string")
```

### 8.3 插件 manifest 初稿

```toml
name = "malware_triage"
version = "0.1.0"
entry = "plugin.py"

[menus]
tools = ["Run Malware Triage"]
```

## 9. 测试计划

### 9.1 单元测试

- [ ] VA/RVA/File Offset 映射。
- [ ] PE header parser。
- [ ] Import parser。
- [ ] Export parser。
- [ ] Relocation parser。
- [ ] 字符串扫描。
- [ ] x64 指令格式化。
- [ ] xref 生成。
- [ ] project database save/load。
- [ ] undo/redo command。

### 9.2 集成测试

- [ ] 打开最小 x64 console PE。
- [ ] 打开带 imports 的 PE。
- [ ] 打开带 exports 的 DLL。
- [ ] 打开带 relocations 的 PE。
- [ ] 打开带 PDB 的 PE。
- [ ] 打开 raw binary 并指定 base/entry。
- [ ] headless 输出 JSON 并校验字段。

### 9.3 GUI 测试

- [ ] 打开文件。
- [ ] 跳转地址。
- [ ] 函数列表点击跳转。
- [ ] 字符串列表点击跳转。
- [ ] 添加注释。
- [ ] 重命名函数。
- [ ] 保存并重开项目。
- [ ] CFG 视图不为空。
- [ ] 调用图视图不为空。

### 9.4 反编译测试

- [ ] 简单算术函数。
- [ ] if/else。
- [ ] loop。
- [ ] switch。
- [ ] WinAPI 调用。
- [ ] 栈变量。
- [ ] 结构体字段访问。
- [ ] 类型传播。

## 10. 风险和难点

- x64 反编译器难度最高，应放到后期，并先做可解释 IR 和小范围伪 C。
- PDB 类型恢复可能遇到格式差异和复杂 C++ 类型，先支持常见 MSVC 场景。
- C Header 导入如果使用 libclang，单 exe 打包会复杂；如果使用 tree-sitter-c，需要自己处理语义。
- Python 嵌入会影响单 exe 体积和发布方式，应先设计为可选模块。
- 停靠 UI 和大型列表性能需要早期压测，避免打开大 PE 后卡顿。
- 自动代码/数据识别会有误报，需要保留用户手动覆盖机制。
- 函数签名库需要签名生成工具和样本积累，不要依赖云服务。

## 11. 建议优先级

P0 必做：

- PE 加载。
- x64 反汇编。
- 函数识别。
- 字符串。
- imports/exports。
- xrefs。
- 线性反汇编视图。
- 函数列表。
- Hex View。
- 项目保存。
- 重命名和注释。

P1 重要：

- Raw Binary。
- relocations。
- section 管理。
- 搜索。
- 快速跳转。
- 书签。
- 撤销/重做。
- CFG。
- 调用图。
- PDB 符号。
- demangle。

P2 增强：

- PDB 类型。
- 类型系统。
- C Header 导入/导出。
- 类型库。
- 函数签名库。
- 运行库识别。
- Headless。
- Python API。
- Python 插件。

P3 高级：

- x64 反编译。
- 批量反编译。
- IR / 微码视图。
- 类型传播。
- 反编译表达式优化。

## 12. 下一次会话建议起点

如果要从代码开始，建议下一次直接说：

```text
根据 C:\Users\Administrator\Desktop\FY_IDA\FY_IDA_DEVELOPMENT_PLAN.md，先搭 Rust workspace 和 GUI 空壳。
```

如果要先细化架构，建议说：

```text
根据计划文档，先细化 PE loader、地址模型和项目数据库 schema。
```

如果要先做原型验证，建议说：

```text
先做一个最小原型：打开 x64 PE，显示 entry point 附近反汇编和 imports。
```

## 13. 当前决策快照

- 第一版只支持 Windows x64。
- 第一版只支持 PE 和 Raw Binary。
- 不做调试器。
- 不做 patch bytes。
- 不做暗色主题。
- 不做联网元数据。
- 不做团队协作。
- 不做自定义 loader 和自定义 processor。
- 要做 Python API 和本地 Python 插件。
- 要做 headless/batch。
- 要做 PDB 符号和类型。
- 要做类型系统。
- 要做 x64 反编译，但放到高级阶段。

