# 工具使用与维护

[English](tool-usage.md) | 简体中文

先按[救灾清单](../README_CN.md)保住易失内存，不要从给受灾 NAS 安装分析环境开始。除物理机采集指南明确说明的步骤外，下列命令均在干净分析机上对独立副本执行。

## 准备分析环境

工具位于 `skills/dsm-ransomware-rescue/scripts/`。保持此目录完整：`decrypt_copy.py` 和 `inspect_footer.py` 共用 `file_layout.py`。分析环境要求 Python 3.11+ 和以下依赖；元数据盘点、进程采集、尾部／LiME 检查器只需 Python 3.8+ 标准库。不要为了满足分析依赖升级受灾 DSM。

在仓库根目录执行：

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
PYTHONPATH=skills/dsm-ransomware-rescue/scripts:scripts .venv/bin/python -m unittest discover -s tests -v
.venv/bin/python skills/dsm-ransomware-rescue/scripts/verify_backup.py --self-test
```

已分析程序的 SHA-256 为 `802ac85d19dc6db2b1849bb3499877280544d04a0ae94d4c408b6c321669903d`。同后缀或同名不能证明兼容；保存程序但不要运行。进程／QEMU 采集和提取密钥请按 [skill 对应路线](../skills/dsm-ransomware-rescue/SKILL.md)操作；地址配置不会自动适配其他二进制或 RAM 格式。

## 先检查密文尾部

```sh
python3 skills/dsm-ransomware-rescue/scripts/inspect_footer.py \
  --input-copy /analysis/copies/example.tar.L0CK3D
```

只读取一份普通副本最后的 588 字节，输出标记、模式、分段参数、原始大小和预期加密范围，不输出内容、路径或包裹后的密钥记录。追加／截断和不支持的模式会拒绝。它不认证密钥、不证明加密完成，也不预测 Btrfs 能否恢复。不同会话分别分组；四字节标记相同不能证明密钥相同。

## 用已验证的候选解密副本

准备独立密文副本、私有的 48 字节 `IV16 + AES-key32` 文件，以及独立存储上尚不存在的输出位置。标记替换为自己案例审阅过的值，不要仅为消除报错而改值。

```sh
.venv/bin/python skills/dsm-ransomware-rescue/scripts/decrypt_copy.py \
  --copy-root /analysis/copies \
  --input-copy /analysis/copies/example.tar.L0CK3D \
  --master-file /analysis/private/master.bin \
  --expected-marker REVIEWED_8_HEX_DIGITS \
  --output /analysis/recovered/example.tar \
  --expected-sha256 KNOWN_ORIGINAL_SHA256
```

`--expected-marker` 只接受 8 位十六进制；省略时保持原来的 `ce35a593` 检查。收据同时记录预期与实际标记。选择会话不会关闭尺寸／模式、AES 记录、不覆盖和完整摘要验证。[密钥说明](key-sharing_CN.md)单独介绍了可选公开候选；其他受害者通常需要自己的内存材料。

没有历史摘要时省略 `--expected-sha256`，结果只能叫候选。错误 IV 也可能通过重复 nonce 检查而产生损坏内容。扩大范围前验证多个完整文件和模式。工具拒绝符号链接、硬链接输入、已有输出以及明确副本根目录之外的输入；不能把根目录指向受灾原卷。失败会移除本次新建输出，保留原件和已有文件。

```sh
.venv/bin/python skills/dsm-ransomware-rescue/scripts/verify_backup.py /analysis/recovered/example.tar
```

完整归档检查比文件头检查更强，但不能替代历史摘要或应用验收。JSON 语法、PGDMP 文件头和 PACK/LFS 检查各有不同范围。重复／中断加密及尾部之后追加日志需要单独分析，不要通过裁剪字节或删除校验强行成功。

## 检查保存的 LiME dump

```sh
python3 skills/dsm-ransomware-rescue/scripts/inspect_lime.py \
  --input-copy /analysis/copies/ram.lime \
  --iomem-copy /analysis/copies/iomem.txt \
  --sha256
```

使用同一机器采集前后保存的 `/proc/iomem`；没有时省略 `--iomem-copy`，覆盖范围为 `null`，不表示通过。RAM 地址全被遮蔽或为空会拒绝。未压缩 LiME v1 的头部为 32 字节，物理末地址包含在范围内；检查器接受一致的大／小端，拒绝截断、重叠、不支持的头部和尾部垃圾。地址间隙可能是 MMIO／PCI hole，不一定是缺 RAM；对照会列出缺少的 System RAM 范围和多出的范围。

退出 1 表示检查失败；退出 2 表示结构有效但与提供的 RAM 范围不符；退出 0 只表示请求的检查通过。它不能识别结构正常的补零页面，不能证明原子采集或密钥存在。`--sha256` 增加完整文件读取，不带时只检查头部／范围。工具不转换格式，LiME 不能直接交给 QEMU 专用提取器。见[物理机指南](../skills/dsm-ransomware-rescue/references/physical-memory_CN.md)。

## 保全与公开分开处理

公开仓库包含审阅后的源码、脱敏记录、合成测试、布局参数和一份单独授权的候选。克隆仓库**不会**取得私有 RAM、其他密钥、日志、凭据或业务文件。本地 `private/` 和 `local-validation/` 被忽略，但 Git 忽略不是访问控制。证据应放受保护存储，记录来源／副本摘要与保管过程，见[证据封存](evidence-seal_CN.md)。

整个 skill 目录可复制到个人技能位置；本仓库不会自动安装它，或更改 SSH、防火墙、服务和全局设置。

公开前只暂存审阅过的源码和文档：

```sh
python3 scripts/check_publish.py --repo . --master-file /analysis/private/master.bin
git diff --cached --stat
```

检查器扫描 Git 暂存区，拒绝私有路径、二进制、链接、常见凭据和未授权的已知密钥表示。唯一公开密钥例外绑定精确路径与文件摘要；这一份候选的授权不能延伸到其他密钥或 dump。还需人工检查文件名、日志、个人路径及恢复内容，这不是完整 DLP 系统。
