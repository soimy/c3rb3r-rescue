# 物理机 Linux / DSM：先保住密钥

[English](physical-memory.md) | 简体中文

核对资料日期：2026-10-29；社区更新：2026-10-30。这里区分上游支持、合成测试、隔离 Linux 子进程测试和真正的物理设备验收。**本案实证仍是 PVE RAM；没有在物理 DSM 上验证 AVML 或加载 LiME。**

社区现已有物理 DSM 进程内存恢复成功汇报，包括 [Issue #14](https://github.com/soimy/c3rb3r-rescue/issues/14) 的 DS920+／DSM 7.2.2。这属于汇报者的结果，不是维护者新增的实机测试。仍须区分进程采集、AVML 命令完成和整机覆盖验证，见[社区证据](https://github.com/soimy/c3rb3r-rescue/blob/main/docs/community-findings_CN.md)。

## 先选能立即保全的路径

| 当前条件 | 先做什么 | 得到什么 / 缺什么 |
|---|---|---|
| 已确认加密 PID，所有线程已暂停，能读其 mem | 保存进程映射、exe、身份和 maps；随后补整机采集 | 可直接寻址的用户态内容；缺内核、未映射残留、寄存器 |
| PID 未知或已退出，整机工具已适配 | 尽早采集整机 RAM | 可能保留旧页和内核状态；不保证密钥尚存 |
| 有可信 PVE 等带外主机权限 | 优先使用已经验证的宿主采集能力 | 不必为采集在受灾来宾安装工具 |
| 物理机上用户态读 RAM 被拒绝 | 评估已适配并测试的内核模块 | 模块可崩溃系统；不能临时试错或强制加载 |
| 已关机/重启 | 保留磁盘、已有 dump、swap/休眠等历史材料 | 已不是原现场的 live RAM；重新开机不能重建失去的内存 |

内存优先不意味着放任加密继续跑。先核对恶意进程身份、暂停已明确的进程并检查所有线程，保留电源和受限管理通道。不要等待完整逆向才保存内存。不要 kill、恢复运行、swapoff、drop_caches、升级内核或从 USB 重启来“准备”采集。采集、读盘和页缓存本身也会改变 live 内存；已释放密钥尤其容易被覆盖。

## 最小现场预检

保存 `date -u`、`uname -a`、DSM VERSION/型号/平台、`/proc/meminfo`、`/proc/iomem`、`/proc/mounts`、`/proc/swaps`、`/proc/cmdline`、`/proc/sys/kernel/yama/ptrace_scope` 和可读的 lockdown 状态。缺失/拒绝也记录，不能据文件存在就认定可采集。工具先在干净机器核对版本、来源和 SHA；不在受灾机安装整套编译环境。

目的目录应在已确认挂载、容量足够的独立取证介质。核对路径对应设备及空间，避免挂载失效后写进系统根分区；不要将几 GiB/几十 GiB dump 写入 tmpfs、/dev/shm 或未经核实的 /tmp。保存整机内存还可能需要两份独立副本和格式转换空间；进程采集按可读虚拟映射总量预估，不等于 RSS。低内存设备上的 Python 开销也要计入。

每次采集先以 `mkdir -m 700` 创建全新 case 目录，创建失败就停止；不使用 `-p` 复用旧目录。外部工具未必拒绝覆盖，所有输出必须事先确认不存在，重试换一个新 case。有限时间内先取得易失内容，再在干净主机执行较重的读回、分析和长期封存。

## A. 先保存已暂停进程

Linux 的 `/proc/PID/mem` 可按虚拟地址读取，但受 ptrace 访问检查约束；root、容器中的 root 和拥有 CAP_SYS_PTRACE 并非在所有 Yama/LSM/namespace 策略下等价。拒绝时保存报错，不自动改 sysctl 或绕过策略。[Linux proc 手册](https://man7.org/linux/man-pages/man5/proc_pid_mem.5.html)、[Yama](https://docs.kernel.org/admin-guide/LSM/Yama.html)

下面是需要代入已核实参数的模板，目的父目录已准备好；sudo 密码只在操作者自己的终端输入：

```sh
sudo python3 /opt/ir/capture_process_memory.py inspect --pid TARGET_PID
stat -c '%d' /mnt/ir-evidence/CASE
df -h /mnt/ir-evidence/CASE
sudo python3 /opt/ir/capture_process_memory.py capture \
  --pid TARGET_PID --expected-start-ticks VERIFIED_START_TICKS \
  --expected-exe-sha256 VERIFIED_EXECUTABLE_SHA256 \
  --expected-output-device VERIFIED_DEVICE_NUMBER \
  --output /mnt/ir-evidence/CASE/process-new
```

采集器只读 mem，不附加 debugger，不发送 STOP/CONT/KILL，不改变权限或加载模块。开始和边界处核对 PID start ticks、exe SHA、所有线程 T/无 tracer、maps 和目的设备；先收集私有匿名可写区、其他可写区，再收集剩余可读区。它不保证两次边界检查之间绝无瞬时恢复，其他进程也可能改变共享页；读 mem 可能调入已换出的页。

新目录必须不存在。每个文件保留起止 VA、SHA、读回验证和不可读页表；空洞在文件中为零占位，**不是采到的零内存**。退出 2 表示有缺页或被排除的不可寻址映射，完成的区域仍有价值；没有 capture.json 的中断目录只能按 regions.jsonl / failure.json 解释为部分采集。不会自动删除这些材料或覆盖重试。

[Issue #14 的实际报错](https://github.com/soimy/c3rb3r-rescue/issues/14)暴露了这一兼容性问题：x86-64 的 `[vsyscall]` 可能超出 `pread` 接受的有符号 64 位偏移。采集器在估算空间前排除跨越该上限的整个映射，在 `excluded_unaddressable` 中记录，`inspect` 也会显示；不会把高地址转换成负偏移或静默丢弃。`selected_mappings_complete` 只描述选定映射；只要排除了任意可读映射或存在缺页，`complete` 就为 false。预期内的排除也需要核对收据，不能称为完整 RAM。

进程输出不是 ELF core。转移到干净分析机、核对文件摘要后，可对相同已审阅样本运行：

```sh
python3 recover_process_key.py --capture /analysis/process-copy \
  --profile /analysis/libgld-802ac85d.json --output /analysis/private/new-candidate
```

这是样本专用 VA 路径，只核对结构与候选，不能自动适配新二进制、PIE/ASLR 或不同 crypto 模式。所需字节缺页、摘要或代码签名不符就拒绝。用独立密文副本和历史明文摘要验证候选；不要把成功提取 48 字节写成成功解密。

## B. AVML 整机采集

AVML 尝试受内核控制的内存源；lockdown 可使其不可用，不应为了它重启并关闭保护。固定并核对选用 release：本次查到 v0.21.0 有 acquire 子命令，以及 x86-64、aarch64、armv6b 命名资产；README 的旧架构概述不足以证明某台 ARM DSM 可用。CPU、字节序、内核访问和实际发布资产都需核实，不能把上游发行版测试当成 DSM 验收。[AVML v0.21.0](https://github.com/microsoft/avml/tree/v0.21.0)、[发布资产](https://github.com/microsoft/avml/releases/tag/v0.21.0)

在可信、匹配架构的工具已就绪且目的为全新私有目录时：

```sh
/opt/ir/avml --help
/opt/ir/avml acquire --help
sudo /opt/ir/avml acquire /mnt/ir-evidence/CASE/ram-new.lime
printf 'ACQUIRE_EXIT=%s\n' "$?"
sha256sum /mnt/ir-evidence/CASE/ram-new.lime
```

模板基于该 release 的未压缩 LiME 输出。保留 stderr、来源和退出状态，另在分析机读回校验。没有把命令存在或退出 0 视为覆盖所有 RAM；压缩输出要保留原件，离线转换独立副本。禁止使用自动删除/上传选项处理现场唯一副本。[固定版本说明](https://github.com/microsoft/avml/blob/v0.21.0/README.md)

传回后按[工具使用](https://github.com/soimy/c3rb3r-rescue/blob/main/docs/tool-usage_CN.md)运行离线 `inspect_lime.py`。LiME v1 的头部是 **32 字节**，末地址包含在范围内，长度为 `end - start + 1`，不能按 24 字节头直接拼接。保留文件偏移与物理范围的映射；地址间隙可能是硬件空洞。与保存的 `/proc/iomem` 中可用 System RAM 地址对照，即使结构通过也保留采集超时／报错。[LiME 头部定义](https://github.com/504ensicsLabs/LiME/blob/master/src/lime.h)

## C. LiME 与 DSM 专有内核

LiME 是需加载到内核中的采集模块。优先 format=lime 保留物理地址范围；raw 拼接会丢失位置，padded 会包含地址洞。默认页面超时可能跳过其余范围，成功加载不等于完整采集。[LiME 参数](https://github.com/jtsylve/LiME)

在干净构建机准备匹配目标的架构、内核源码/配置、编译器、符号版本与模块签名条件，再于同配置测试机演练。DSM 型号的平台和厂商内核补丁很重要；只看 uname -r 或 vermagic 相同仍不足以证明安全。启用 CONFIG_MODVERSIONS 时，modules_prepare 不会生成所需的 Module.symvers。没有匹配材料、签名被拒或模块加载被禁时，停止这条路线，保留进程证据；不 insmod --force、不替换内核。[Synology 工具链](https://help.synology.com/developer-guide/compile_applications/download_dsm_tool_chain.html)、[Linux 外部模块](https://www.kernel.org/doc/html/latest/kbuild/modules.html)

以下仅用于已完成兼容性演练、已授权的加载，现场不可用于碰运气：

```sh
modinfo /opt/ir/lime-reviewed.ko
sudo insmod /opt/ir/lime-reviewed.ko "path=/mnt/ir-evidence/CASE/ram-new.lime format=lime"
printf 'ACQUIRE_EXIT=%s\n' "$?"
```

保存模块 SHA、加载前后 dmesg、超时/跳过区间和实际文件摘要；不自动 rmmod 再重试。空间不足需网络采集时，先验证管理隧道与接收端；LiME TCP 默认可绑定全部接口，因此要求适配版本的 localhostonly=1 加受限 SSH 隧道，不在公司网或互联网裸露 RAM 端口。任何断流产物单独保留，禁止把两次 live 流续接成一个“完整 dump”。[LiME 采集说明](https://github.com/jtsylve/LiME/blob/master/docs/README.md)

## 格式、验证与禁用的捷径

| 输入 | 正确解释 |
|---|---|
| 本案 pc.ram | 按已验证的 QEMU low/high RAM 布局换算 GPA |
| LiME | 逐段 header 的物理起止地址；检查范围、长度、缺失/超时，不能去头后直接拼接 |
| padded / physical raw | 以工具的地址规则和来源映射为准；扩展名 raw 不能决定布局 |
| GDB ELF core | 用 PT_LOAD 的进程 VA；有寄存器等 note，仍不是整机 RAM |
| 本仓库 process mappings | 用 capture.json 的 VA 与 holes；不包含寄存器 |

`recover_ram_keys.py` 的 pc.ram profile **不能直接读 LiME、ELF 或物理内存 raw**。整机分析应采用支持其格式的工具，保留 kernel banner、原厂 vmlinux/debug 信息和必要符号；Volatility 的 Linux 符号要求精确匹配，不能用同版本号的通用符号蒙混通过。格式/符号缺失会限制自动分析，但不应延误已经可做的采集。[Volatility 符号说明](https://volatility3.readthedocs.io/en/latest/symbol-tables.html)

完整验收记录工具/系统版本、时间区间、源范围、目标字节、错误/空洞、源与目的摘要。全文 SHA 相同只说明复制一致，不证明采集没有漏 RAM 或密钥一定在内。物理 RAM 也不等于已换出的全部用户页；swap/休眠证据另行保全，不能通过关闭 swap 来“补齐”。

不要直接 dd 一个大尺寸的 /proc/kcore 当裸 RAM；它是 ELF 接口，需由理解布局的工具读取。GDB/gcore 会涉及调试附加与 detach，可能影响暂停状态；默认过滤也会漏映射，不能用 gcore 成功替代覆盖核验。只有先在无害进程上验证保留 T 状态和过滤行为后才考虑备选，采集后绝不自动 CONT。[kcore](https://man7.org/linux/man-pages/man5/proc_kcore.5.html)、[GDB core](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Core-File-Generation.html)

kdump 依赖预留 crash kernel 并在 crash 路径采集；过滤选项还可能排除用户页。不要在当前唯一现场临时触发 panic、重启配置 kdump 或把故障恢复步骤当成非破坏性采集。已配置、已验证的 crash 取证属于另一个明确决策；本指南没有提供触发命令。[Linux kdump](https://docs.kernel.org/admin-guide/kdump/kdump.html)

Windows 物理机可另行评估官方 WinPmem 的匹配签名驱动；本仓库 Linux 采集器不适用，也不应为加载驱动改 test-signing 后重启。macOS/Apple Silicon 不提供通用整机 dump 承诺，应转向实际受支持的专项取证路径；不要临时关闭 SIP 或重启试工具。[WinPmem](https://github.com/Velocidex/WinPmem)

## 进程已经退出时

此节吸收了 [#6 的 OOM／快照报告](https://github.com/soimy/c3rb3r-rescue/issues/6)、[#9 的 RAM／zram 阴性搜索](https://github.com/soimy/c3rb3r-rescue/issues/9)及 [#10 的证据边界](https://github.com/soimy/c3rb3r-rescue/issues/10)，以下为据此给出的处置建议。

OOM 杀进程、正常退出和攻击者清理有不同证据，不能仅凭开机时长或可执行文件已删除就下结论。没有经过验证的“多少小时以内安全”期限。RAM 搜索阴性只覆盖该份采集和搜索方法。保留 `/proc/swaps` 和实际使用量：未使用的磁盘 swap 不能代替正在使用的 zram，原始压缩 zram 也不等于解压后的线性交换页。采集要保留格式，不能用 swapoff 走捷径。

易失证据保全后检查尚存快照和独立原件。Btrfs 应先评估[旧 extent 恢复](btrfs-recovery_CN.md)，再判断是否不可恢复；这些操作的新增文件仍应放到受灾存储池之外。
