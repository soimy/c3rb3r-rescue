# c3rb3r-rescue

一次 DSM / GitLab 勒索事件的取证、内存密钥恢复和副本解密记录。目标是让下一次处置能够复现经过验证的步骤，同时保留失败和证据缺口。

本工具适用于已分析的 `libgld` 样本与文件格式，**不是 C3RB3R 家族的通用解密器**。样本 SHA-256：`802ac85d19dc6db2b1849bb3499877280544d04a0ae94d4c408b6c321669903d`。不包含恶意二进制、真实密钥、业务数据或可运行的入侵载荷。

本次结果：16 GiB 内存副本中找到可用的 48 字节主材料；五组已知明密文逐字节一致。10/24 的约 49 GiB 周备份与历史摘要一致，随后在隔离的同版本 GitLab 中恢复出 80 个项目、23 个用户、16 个群组和 9253 个 LFS 对象。仓库、secrets、LFS、附件和 artifacts 检查通过，登录页返回 200。10/22 的另一份周备份存在交错重复加密，仍未完整恢复。新发现的内存日志高可信指向 DSM 登录插件环境注入、与 CVE-2024-10441 一致，尚缺少完整请求和执行链。

## 阅读入口

- [事件过程与证据边界](docs/incident-report.md)
- [攻击路径调查及 Reddit 新线索](docs/attack-path.md)
- [封存布局、保管和重验](docs/evidence-seal.md)
- [工具验证记录](docs/toolkit-validation.md)
- [可复用 skill](skills/dsm-ransomware-rescue/SKILL.md)：保全、RAM、REA 逆向、盘点、解密、GitLab 验收。

## 本地与 GitHub 的边界

GitHub 保存脱敏记录、skill、源码、合成测试和样本布局参数。仓库默认私有，之后改变可见性前仍需检查内容。

`private/` 被 Git 忽略，保存本机证据副本、内存 dump、密钥候选、原始日志、对话快照和保管清单。**Git clone 不包含这些材料，也不能重建解密密钥。** 大体积业务密文和恢复备份仍在救援 NAS，位置和既有校验收据由本地索引记录，不复制到 Git 历史。

这是逻辑封存：独立副本、逐文件摘要、落盘重读、只读权限和来源记录。没有做全盘取证镜像，没有将运行中的 DSM 变为不可变磁盘快照，也没有将联网 NAS 称为离线备份。

## 使用

工具目录：`skills/dsm-ransomware-rescue/scripts/`。Python 3.11+；实际回归环境为 Python 3.12，NumPy / cryptography 版本见 `requirements.txt`。DSM 元数据盘点脚本仍可用标准库 Python 3.8；不要为了运行解密器升级受灾系统。

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
