# C3RB3R / .L0CK3D 勒索救灾

[English](README.md) | 简体中文

**NAS 文件突然变成 `.L0CK3D`，目录里出现 `read-me3.txt`？先保住现场，仍可能有恢复机会。**

这个仓库帮助你或你的 AI 助手停止损失、保存内存、寻找密钥，再在副本上恢复文件。已有[本案 PVE](docs/incident-report_CN.md)和[社区物理 DSM](https://github.com/soimy/c3rb3r-rescue/issues/14)的成功案例；密钥找不到时，部分 Btrfs 文件还可以尝试从旧数据块恢复。**能恢复多少取决于现场，没有一把适用于所有人的万能密钥。**

> **先别重启、关机、升级、重装，也别 `kill -9` 加密进程。** 进程内存中可能还留着解密所需的密钥。不要删除密文、快照或回收站来腾空间，也不要把恢复文件写回受灾存储池。

## 第一时间做什么

1. **阻止继续加密，保住进程。** 先核实可疑进程身份，再用 `sudo kill -STOP PID` 暂停它，`PID` 换成确认过的进程号。检查所有线程是否为 `T`；`D` 仍是等待 I/O，不能算暂停成功。程序名可以变化，别仅凭名字批量暂停或杀进程。
2. **隔离入口和同步。** 阻断 NAS 对互联网及其他设备的访问，检查 IPv4 和 IPv6；暂停云同步、共享同步，避免损坏传播。远程处置先保留可信控制台或受限 SSH，别把自己锁在外面。
3. **尽快保存内存和程序样本。** 不要等全盘扫描或查明漏洞才采集。目标选容量足够的独立存储；先核对挂载和空间，别把大 dump 写进 `/tmp` 或受灾数据卷。按下面的表选择采集方式。
4. **复制少量密文，先验证恢复。** 尽量找几份电脑、手机、邮件或 Git 克隆中仍完好的同版本原件，用完整 SHA-256 或逐字节比较验证。验证后再扩大范围；原始密文一直保留。
5. **把业务恢复到干净环境。** 数据恢复成功不代表原 NAS 已经安全。业务可用后，再处理重建、凭据更换和入侵入口。

不熟悉 SSH 或进程操作，可以直接把本页交给 AI 或管理员，使用下方的任务说明。不要为了运行工具重启受灾机。

## 你的情况走哪条路

| 当前情况 | 下一步 |
|---|---|
| **PVE 中的 DSM，机器还在运行** | 从可信宿主保存来宾内存，再离线找密钥。见[保全与 PVE 内存](skills/dsm-ransomware-rescue/references/containment-memory.md)。 |
| **物理 DSM，加密进程还在** | 暂停并核对全部线程后，优先保存进程内存，再评估整机 RAM 采集。见[物理机采集步骤](skills/dsm-ransomware-rescue/references/physical-memory_CN.md)。 |
| **进程已消失，机器未重启** | 尽早保存可采集的 RAM 和实际使用的 swap，但不要假定密钥一定残留。同时检查快照、其他副本和下方 Btrfs 路线。 |
| **找不到密钥，数据卷是 Btrfs** | 保存现有快照，评估是否还有引用旧数据块的文件区段。见[Btrfs 无密钥恢复](skills/dsm-ransomware-rescue/references/btrfs-recovery_CN.md)。 |
| **已经关机或重启** | 不能靠重新启动找回之前的进程内存。保留磁盘、已有 dump、快照和其他副本；Btrfs 路线是否可行仍需检查。 |

**“一直没重启”不等于“密钥还在”；“进程退出”也不等于“所有数据都没救”。** 社区既有成功恢复，也有完整搜索未找到密钥的报告，见[案例与验证范围](docs/community-findings_CN.md)。

## 为什么可能恢复

本次分析的程序给每个文件生成加密材料，再用一份**会话密钥**保护它，把保护后的记录写在文件末尾。会话密钥可能仍在加密进程的内存里。拿到匹配的会话密钥，就有机会逐个解开文件，无需取得攻击者的私钥。

```mermaid
flowchart LR
    A[保存内存] --> B[提取本机会话密钥]
    B --> C[解开文件尾记录]
    C --> D[恢复副本并核对完整内容]
```

另一条路与密钥无关：**Btrfs 写时复制可能留下被覆盖前的数据块**。如果文件未加密的部分仍引用这些块，就可能重组原文件。能否使用取决于实际块映射、快照和后续写入；仅有 Btrfs 或 NoCOW 标签不能下结论。参见 [crt106 的原理说明](https://github.com/crt106/c3rb3r-btrfs-recovery/blob/b831f3a0f718677b889f2998ff09a0b925baa56b/skills/c3rb3r-btrfs-recovery/references/principles.md)及[本仓库的验证边界](skills/dsm-ransomware-rescue/references/btrfs-recovery_CN.md)。

## 已有人成功吗

- **本仓库的 PVE 案例：** 从内存取回密钥，约 49 GiB GitLab 周备份与历史摘要完全一致，随后在隔离实例中恢复了 **80 个项目**。
- **[Benjamin-zlt 的物理机案例](https://github.com/Benjamin-zlt/c3rb3r-baremetal-rescue/blob/906e81293153341f162ee1f176722d93ba1d8358/docs/case-report.md)：** 作者报告恢复约 8.45 万个文件，并用已知原件抽样核对。用的是该机器自己的密钥。
- **[Btrfs 社区工具](https://github.com/crt106/c3rb3r-btrfs-recovery)：** 提供没有密钥时从旧数据块恢复的另一条路线。不同报告的验证程度不同，不能把恢复数量当成所有文件逐字节验证过。

本工具针对已分析的样本和格式。[其他受害者的报告](https://github.com/soimy/c3rb3r-rescue/issues/14)已促成物理机采集兼容性修复和会话标记参数化，但仍需先验证少量副本。仓库公开了[本案的一份恢复候选](docs/key-sharing_CN.md)，目前没有证据表明它能解密其他受害者的文件。

## 交给 AI 的任务说明

> 阅读这个仓库的 README 和 skills/dsm-ransomware-rescue/SKILL.md，帮助我处置疑似 C3RB3R / .L0CK3D 勒索事件。先确认机器类型、是否重启、加密进程状态、管理通道及独立目标存储。在现有授权内阻止继续损失，优先保存内存和样本，不杀掉已暂停的进程。先在独立副本上验证密钥及完整文件；找不到密钥时检查快照和 Btrfs 旧数据块恢复条件。不要自动重启、运行恶意样本或写回受灾卷。明确告诉我哪些已验证、哪些只是候选。

补充你的系统版本、物理机或虚拟机、发现时间、是否重启及可用备份。**不要公开密码、内存 dump、密钥或业务文件。**

## 需要动手或深入了解时

| 你想做的事 | 文档 |
|---|---|
| 采集物理机内存、检查 LiME dump | [物理机指南](skills/dsm-ransomware-rescue/references/physical-memory_CN.md) |
| 没有密钥，评估 Btrfs 恢复 | [条件、步骤与验证](skills/dsm-ransomware-rescue/references/btrfs-recovery_CN.md) |
| 安装分析环境、检查文件尾、运行解密 | [工具使用与维护](docs/tool-usage_CN.md) |
| 看社区成功、失败和适用范围 | [社区发现](docs/community-findings_CN.md) |
| 理解密钥能否共用 | [密钥层级与公开候选](docs/key-sharing_CN.md) |
| 研究算法、内存地址及重复加密 | [逆向与解密](skills/dsm-ransomware-rescue/references/reverse-decrypt.md) |
| 盘点文件、恢复 GitLab | [盘点与校验](skills/dsm-ransomware-rescue/references/inventory-verify.md) · [隔离恢复](skills/dsm-ransomware-rescue/references/gitlab-restore.md) |
| 查看本案的取证记录 | [事件报告](docs/incident-report_CN.md) · [攻击路径](docs/attack-path_CN.md) · [证据封存](docs/evidence-seal_CN.md) |
| 查看测试和工具限制 | [工具验证](docs/toolkit-validation_CN.md) · [AI skill](skills/dsm-ransomware-rescue/SKILL.md) |
| 求助或补充脱敏结果 | [Issues](https://github.com/soimy/c3rb3r-rescue/issues) |
