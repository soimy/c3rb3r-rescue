# c3rb3r-rescue

一次 DSM / GitLab 勒索事件的取证、内存密钥恢复和副本解密记录。目标是让下一次处置能够复现经过验证的步骤，同时保留失败和证据缺口。

本工具适用于已分析的 `libgld` 样本与文件格式，**不是 C3RB3R 家族的通用解密器**。样本 SHA-256：`802ac85d19dc6db2b1849bb3499877280544d04a0ae94d4c408b6c321669903d`。不包含恶意二进制、真实密钥、业务数据或可运行的入侵载荷。

**首要目标是保住仍在内存中的解密材料。** 在阻止继续加密并保留管理通道后，尽早采集可取得的进程内存和整机 RAM；不要等全盘盘点、漏洞归因或完整反编译做完才 dump。不要为清理恶意程序先 kill、重启、升级系统或启动另一张救援盘。内存采集不能保证一定有可用密钥，但失去这份易失证据后，本案的恢复路径可能不再成立。

本案成功来自 **PVE 来宾 RAM**。新增的[物理机 Linux / DSM 采集指南](skills/dsm-ransomware-rescue/references/physical-memory.md)覆盖进程映射、AVML 和 LiME；物理 DSM 整机采集尚未实机验收，不能把本次 VM 成功外推到所有设备。

## 交给 AI 使用

可把仓库 URL 和下面这段任务说明交给助手；先提供系统/架构、是否仍开机、可用管理通道和现有授权范围，**不要发送密码、真实密钥、完整内存或业务文件**：

> 阅读 README 与 skills/dsm-ransomware-rescue/SKILL.md。以保住易失密钥为优先，确认当前机器是虚拟机还是物理机，区分进程内存和整机 RAM。先调查可用权限、暂停状态、目标存储和采集兼容性，再在现有授权内采取适用的步骤。保留原始文件、独立副本和校验收据；不要执行样本、自动加载不匹配的内核模块或重启受灾机。只对副本尝试解密，分别报告已验证结果、猜测和未覆盖范围。

症状相同不证明样本、会话或密钥相同。当前解密器还检查本案会话尾标记；其他事件须重新验证布局及标记，不能通过删除校验强行运行。参见[密钥复用与分享](docs/key-sharing.md)。

本次结果：16 GiB 内存副本中找到可用的 48 字节主材料；五组已知明密文逐字节一致。10/24 的约 49 GiB 周备份与历史摘要一致，随后在隔离的同版本 GitLab 中恢复出 80 个项目、23 个用户、16 个群组和 9253 个 LFS 对象。仓库、secrets、LFS、附件和 artifacts 检查通过，登录页返回 200。10/22 的另一份周备份存在交错重复加密，仍未完整恢复。新发现的内存日志高可信指向 DSM 登录插件环境注入、与 CVE-2024-10441 一致，尚缺少完整请求和执行链。

## 阅读入口

- [事件过程与证据边界](docs/incident-report.md)
- [攻击路径：日志、RAM 结构与漏洞判断](docs/attack-path.md) · [可复核证据索引](docs/attack-path-evidence.json)
- [封存布局、保管和重验](docs/evidence-seal.md)
- [工具验证记录](docs/toolkit-validation.md)
- [物理机采集与失败分流](skills/dsm-ransomware-rescue/references/physical-memory.md)
- [密钥层级、复用与公开边界](docs/key-sharing.md)
- [可复用 skill](skills/dsm-ransomware-rescue/SKILL.md)：保全、RAM、REA 逆向、盘点、解密、GitLab 验收。

## 本地与 GitHub 的边界

GitHub 仓库公开，保存脱敏记录、skill、源码、合成测试和样本布局参数。每次发布仍检查 Git 暂存区；公开方法不等于公开本次真实密钥。

`private/` 被 Git 忽略，保存本机证据副本、内存 dump、密钥候选、原始日志、对话快照和保管清单。**Git clone 不包含这些材料，也不能重建解密密钥。** 大体积业务密文和恢复备份仍在救援 NAS，位置和既有校验收据由本地索引记录，不复制到 Git 历史。

这是逻辑封存：独立副本、逐文件摘要、落盘重读、只读权限和来源记录。没有做全盘取证镜像，没有将运行中的 DSM 变为不可变磁盘快照，也没有将联网 NAS 称为离线备份。

## 使用

工具目录：`skills/dsm-ransomware-rescue/scripts/`。分析环境 Python 3.11+；实际回归环境为 Python 3.12，NumPy / cryptography 版本见 `requirements.txt`。DSM 元数据盘点和新增进程采集器只需标准库 Python 3.8+；不要为了运行解密器升级受灾系统。

在干净的分析机建立环境：

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
PYTHONPATH=skills/dsm-ransomware-rescue/scripts:scripts .venv/bin/python -m unittest discover -s tests -v
.venv/bin/python skills/dsm-ransomware-rescue/scripts/verify_backup.py --self-test
```

单文件解密，输入必须是独立密文副本，输出必须不存在：

```sh
.venv/bin/python skills/dsm-ransomware-rescue/scripts/decrypt_copy.py \
  --copy-root /analysis/copies \
  --input-copy /analysis/copies/example.tar.L0CK3D \
  --master-file /analysis/private/master.bin \
  --output /analysis/recovered/example.tar \
  --expected-sha256 KNOWN_ORIGINAL_SHA256
```

没有历史摘要时可省略最后一个参数，但成功退出只证明结构检查接受了候选，不证明文件完整。随后完整读取归档、校验 CRC/PACK/LFS，并进行应用层恢复。不要把 `--copy-root` 指向受灾原卷。

```sh
.venv/bin/python skills/dsm-ransomware-rescue/scripts/verify_backup.py /analysis/recovered/example.tar
```

该验证器会输出进度与最终 JSON；已判失败的归档退出非零。JSON 语法、PGDMP 文件头及 PACK 摘要各有明确边界，不能替代应用验收。

skill 可随整个目录复制到个人 skills 目录；其脚本、布局参数和参考文档均包含在目录内。此仓库创建过程没有自动更改用户的全局 skill 或 SSH 配置。

## 发布前

只暂存经过审查的源码和文档，再检查 Git 暂存区：

```sh
python3 scripts/check_publish.py --repo . --master-file /analysis/private/master.bin
git diff --cached --stat
```

检查器拒绝私有目录、二进制、链接、常见凭据和已知主材料的原始/hex/base64 表示。它不是完整 DLP；人工检查仍需确认没有复制真实日志、客户路径、配置值或解密内容。
