# 封存与保管

[English](evidence-seal.md) | 简体中文

本地仓库 `private/` 为敏感保管区，Git 显式忽略它。GitHub 公开仓库保存方法和脱敏结果；后来另获明确授权的一份恢复候选见[密钥说明](key-sharing_CN.md)，这一例外不包含原始证据。每次发布前都检查 Git 暂存区，而不是只相信 .gitignore。后续物理机路径的合成测试日志放在另一个被忽略的 `local-validation/`，不改动旧检查点。

本轮封存了 352 份既有证据文件、一个 16 GiB RAM 副本和本次对话的完整行前缀。原始样本、解包派生文件、REA snapshot/证据包、反编译 C、日志 tar、盘点 JSONL、密钥候选、已知明密文、解密/恢复收据和历史脚本都在这 352 份文件中。

本轮新增的 RAM 线索、脚本重放、现场只读状态、外部数据索引和校验报告单独保存；原封存目录保持不改动。历史记录中途的“尚未恢复”等描述代表当时状态，不覆盖为最终结论。

| 本地位置 | 内容 |
|---|---|
| private/evidence-20261028 | 原始取证工作目录的独立只读副本及 SEAL 清单 |
| private/ram | 完整 RAM 副本，0400，具有传输与读回校验 |
| private/transcripts | 对话记录的完整 JSONL 行前缀及范围收据 |
| private/replayed-key-recovery | 整理后工具重新提取的敏感候选 |
| private/replayed-plaintext | 五组真实样本重放输出 |
| private/attack-trace-ram | 新发现的注入相关内存原片段与派生文本 |
| private/replayed-attack-fragments | 整理后的片段提取工具重新输出的三个区域及摘要 |
| private/migration-records | 84 份迁移脚本、清单、映射与日志；大型镜像仍留在原位置 |
| private/external-metadata | 从救援 NAS 另行保存的 10 份清单和校验收据 |
| private/receipts | 现场观察、测试、复制及重放收据 |
| private/external-evidence.json | 救援 NAS 大备份和原 PVE RAM 的位置、已有摘要记录及覆盖限制 |

单独记录的初始证据清单 SHA-256：`afb2989243b394ec06c509fd029a0558832a5dc280a452292ae0442d96a357b5`。
RAM SHA-256：`0f72eb4f7c65ed868ceffcf69b06c1b97bcc49b13323b947f08ba09da6d73883`。

可在本地重验：

```sh
python3 skills/dsm-ransomware-rescue/scripts/seal_evidence.py verify private/evidence-20261028
```

数百 GiB 的业务密文、明文和迁移前仓库备份仍在救援 NAS。本机剩余空间不足以再完整复制全部业务材料；不通过硬链接假装独立备份。其完整清单和收据已纳入本地封存，源目录未删除或移动。联网 NAS 不是离线副本，后续仍需独立介质。

发布完成后，本地 `private/ARCHIVE-MANIFEST.json` 汇总私有区普通文件的相对路径、大小和 SHA-256，`private/ARCHIVE-MANIFEST.sha256` 校验该清单自身。两者不纳入自身清单。它记录本次收尾时的检查点；之后新添的材料需另建检查点，不把新增文件静默计入旧封存。原始 352 文件的 SEAL 仍独立保留。

只读权限可减少误操作，不能抵御拥有者重新 chmod、管理员篡改或底层设备损坏。清单摘要为可复核基线，不是数字签名、可信时间戳或链路外证明。没有获取所有数据盘镜像，没有卸载/冻结源文件系统，没有停止 PVE VM；现场隔离和恶意进程暂停状态需要继续维护。

保留私有区时也应限制整机访问和备份权限。不要把 private 目录作为压缩附件上传到 GitHub issue、Release、聊天或云端扫描服务。

## 2026-10-29 攻击路径补充检查点

本轮只读取既有 RAM 与日志，没有改动上述 `private/` 检查点。新增工作材料位于被 Git 忽略的 `local-validation/attack-path-followup-20261029/`，已独立复制到 `local-validation/attack-path-sealed-20261029/`：**373 个文件，58,739,038 字节**，逐文件复制、读回核对后设为文件 0400、目录 0500。

新增 SEAL 清单 SHA-256：`5ec4807850f7df900431f3591bb90278ad8e891e1f9f7205bfa93c464ef85cc7`。

该检查点包含 84 个日志分析输入及来源目录、25 个标记的完整 RAM 命中索引、有界原始片段、LZO 候选输出、残留日志表解析、一次性分析脚本、128 项核对收据及脱敏报告副本。首次重复扫描 RAM 的本地分析进程被中断以减少重复读取，随后单遍扫描完整完成并重新通过原 RAM 摘要；这一过程也留有记录。它不是一次新的现场采集。

```sh
python3 skills/dsm-ransomware-rescue/scripts/seal_evidence.py verify local-validation/attack-path-sealed-20261029
```

新增的完整上下文仍含敏感信息和载荷片段，不进入 Git。这次攻击路径检查点只对外发布 [调查报告](attack-path_CN.md)、[证据索引](attack-path-evidence.json)和方法；本检查点也不能替代原始 RAM、离线介质或可信时间戳。随后单独发布的恢复候选不改变本检查点或旧封存内容。
