# 攻击路径：新证据与置信度

更新：2026-10-29。结论基于已保全的本次内存和日志；外部帖子只用于提出检索方向。没有重放漏洞请求，没有访问样本下载服务器，没有执行解码内容。

## 新发现

初始的 88 份已保存日志检索没有找到 `PLUGIN_VALUE_END`、`LD_PRELOAD`、`LD_DEBUG_OUTPUT` 注入内容。不能由此排除这些行为。随后对先前采集的 RAM 搜索，区分了普通库中的常量字符串和携带真实参数的日志残留。

RAM 文件中 `0x2932af000` 开始的 16384 字节区域包含 DSM 登录处理错误消息、注入的账号值、`.SDATA.journald` 形式字段和 `synoscgi.service` 标记。附近 `_SOURCE_REALTIME_TIMESTAMP` 为 `1793147969312774`，换算北京时间 **2026-10-28 08:39:29.312774**。这表示内存残留中的来源时间字段，尚未从完整 journal 文件独立验证其边界。

注入记录出现 plugin delimiter、`LD_PRELOAD`、`LD_DEBUG=libs`，以及 `LD_DEBUG_OUTPUT=/etc/cron.d/synotgkk`。另一段 `0x2d3210000` 开始的区域含展开后的插件参数和失败结果；其中部分字节损坏，不能当作完整 HTTP 请求。

编码字段仅作为数据解码；得到的命令引用下载地址 `hxxp://104[.]253[.]175[.]125/xdy5[.]sh` 并将下载内容交给 shell。这里仅保存去武器化 IOC，不提供可运行的请求或 cron 载荷。解码文本 SHA-256 为 `d912350a99fe2005dcf992cfdba2a4980fe7f30d865abe18fe50e492a2fb9a54`。

| 时间（+08:00） | 本次证据 | 能说明的范围 |
|---|---|---|
| 08:39:29.312774 | RAM 中 DSM 登录处理、plugin delimiter 与环境变量注入残留 | 真实输入/处理线索；不是仅库常量 |
| 08:40:07 | rm.log.1.xz 第 6762 行，root 删除四个 synotgkk.PID cron 文件 | 与注入的同名输出路径和 PID 后缀机制相符 |
| 约 08:46:47 | libgld 进程启动记录与文件变化 | 加密执行时间线 |
| 08:47:23 | rm.log.1.xz 第 6763 行，root 删除 /bin/l0ck.enc | 后续标记/清理线索 |

重复 RAM 命中可能是同一消息的多个缓冲副本，不能计为多次攻击。一般的 LD_PRELOAD 或 delimiter 常量不计为命中利用。较常见标记的扫描设置了每项 100 条上限并明确报告截断；上述较少见的注入标记未截断。

## 与漏洞资料的对应

当前读取的受灾机 `/etc/VERSION` 与 `/etc.defaults/VERSION` 都标记 DSM 7.2、build 64561、smallfix 0。官方公告将 DSM 7.2 分支修复版本列为 7.2-64570-4；现场版本标记低于该值。版本文件不是二进制补丁鉴定，单凭版本仍不能证明利用。[Synology SA-24:20](https://www.synology.com/en-global/security/advisory/Synology_SA_24_20)

Rapid7 的原始研究描述了 DSM 登录流程中的 delimiter/environment 注入，以及通过动态链接器输出形成带 PID 后缀的 cron 文件的技术链。本次输入结构、相同 cron 路径、时间关系和版本标记共同支持这一方向。[Rapid7 whitepaper](https://www.rapid7.com/cdn/assets/bltad0709de42b54e82/689604359f008cdd02f69917/disguise-delimit-whitepaper.pdf)

**评估：高可信指向 DSM 登录插件环境注入，与 CVE-2024-10441 利用链一致。** 相比“GitLab 新 RCE”的猜测，已有更直接的本机证据。尚未获得原 HTTP POST、完整 cron 文件、完整进程父子链或厂商确认，故不写成已经完成端到端证明。

## Reddit 线索如何使用

用户提供的[帖子](https://www.reddit.com/r/synology/comments/1xhqgov/well_it_finally_happened_my_first_real_ransomware/)描述了相同的文件后缀、赎金说明、`libgld -n 308`、标记文件及 cron 清理模式，并讨论了上述 DSM 漏洞。该信息促使本次重新检查 RAM。帖主的下载地址与本次解码地址不同；其事后下载样本也不能替代本机保全样本。没有依据这些相似点确认同一操作者。

## 可复核位置与证据限制

- 原 RAM SHA-256：`0f72eb4f7c65ed868ceffcf69b06c1b97bcc49b13323b947f08ba09da6d73883`。
- 登录消息区域：文件偏移 `0x2932af000`，16384 字节，SHA-256 `5d5157e9b2050739a18e3a1639d6323401c37edc379c5f248bd1fdba48b34582`。
- 插件参数区域：文件偏移 `0x2d3210000`，16384 字节，SHA-256 `c9d413fc0e19de5cc9dcdc9a56314b0084b826f4d3d33f3bb4cb9d59a92b1168`。
- 额外残留区域：`0x3748da000`，16384 字节；仅作辅助，不作为独立攻击事件。
- 原片段、完整上下文与解码文本在本地 `private/attack-trace-ram/`，不上传。

内存是在事故处置期间 live 采集，可能包含过期、重复或损坏的数据，未完成所有相关对象的进程归属重建。该区域中的消息时间与独立 rm 日志相关联，但不是完整日志认证。后续可在离线副本上继续寻找原 cron 内容、journal 结构和进程创建记录；不需要向受灾设备发送验证性攻击。
