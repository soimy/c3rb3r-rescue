# GitLab 隔离恢复

先确定真正运行过的版本和 CE/EE 类型：容器镜像标签、image config 摘要、包内 VERSION、备份元数据交叉核对。旧目录名和“曾升级到某版本”的记忆不能替代现场证据。本案实际恢复版本为 CE 19.5.1。

按[官方恢复要求](https://docs.gitlab.com/administration/backup_restore/restore_gitlab/)准备相同版本/类型、独立空目标和匹配 secrets。旧 gitlab.rb 是可执行 Ruby，不直接加载来自受灾机的版本；重新写最小配置，单独保全原配置供人工比较。

## DSM 宿主检查

Docker 常在 `/var/packages/ContainerManager/target/usr/bin/docker`。SSH 用户属于 administrators 不代表能读 Docker socket 或免密 sudo；密码只在操作者自己的终端输入，不写脚本或聊天。读版本、Docker RootDir、存储驱动、现有容器、Compose 版本、内存和磁盘余量。

检查 Docker 实际返回的 `CPUSet`、`CpuCfsQuota`、`MemoryLimit`、`SwapLimit`。本案 DSM 缺少 CFS quota，使用 `cpus` 创建失败，改为经核实可用的 cpuset。不要用字段名 `Cpuset` 误读 `CPUSet`，也不要为了容器修改整个宿主的 cgroup。

单独建立 root 专用运行目录，核对 Synology ACL 继承；chmod 本身不一定消除原共享 ACL。不改 NAS 其他容器、系统 swap 或原救援共享权限。准备足够展开空间；压缩包本体、工作副本、数据库与 LFS 展开都要计算。

## 空实例与导入

镜像固定 tag + digest，重新检查真实运行版本。使用 `network_mode: none`、无发布端口、无 privileged、无 Docker socket、明确的独立可写 config/log/data；源备份只读挂载。Sidekiq、邮件、Runner 等外部副作用关闭，restart=no。silent mode 是额外保护，不能代替断网。

先验证空实例数据库为零项目/群组和登录页响应。不要假设 curl 在 `/usr/bin/curl`；本案镜像把内置 curl 放进 PATH，调用 `curl` 并记录命令退出码、stderr 和 HTTP 状态。404/502、命令不存在和连接失败分别处理，不静默无限等待。

复制备份为新工作文件，避免硬链接；复制源与目的完整 SHA 均匹配后才导入。写一次性开始标记，重入时拒绝自动覆盖。停止 Puma，确认 Sidekiq 关闭，然后仅在这个新实例执行标准 backup restore。结束后保存真实退出码、阶段日志、项目/群组/用户/LFS 计数，与备份 SQL 的独立计数比较。

依次检查 `gitlab:doctor:secrets`、`gitlab:git:fsck`、`gitlab:lfs:check`、`gitlab:uploads:check`、`gitlab:artifacts:check`。检查 stdout 中失败记录，不能只看 rake 返回 0。启动 Puma，等登录页 200，再记录当前隔离状态。

## 验收边界

本案数据库出现 7 条扩展/public schema 的 ownership/SET ROLE 提示，关键计数和后续检查通过。保留原错误，定位到实际 DDL；没有为了消除提示给应用账户超级权限。独立 ci 备份缺失提示也保留；它并不自动证明 CI 业务已恢复或数据缺失，需要检查源布局和运行时连接。

核心检查成功后，再建立仅本人可访问的入口并测试真实登录、clone、LFS checkout、附件及需要的包。不要假设 SSH AllowTcpForwarding 可用：本案普通用户转发被禁，streamlocal 实测也失败。不能把容器内部 localhost URL 直接发给用户当浏览器入口。

Sidekiq 关闭、无 Runner、无公网入口时，CI 和后台功能没有验收。新的每日数据库不能直接覆盖较旧周备份，否则可能产生不存在的仓库/LFS引用。保留云端和开发机新增提交，逐项目比较后再合并。

恢复失败时只停止这个新实例并保留目录/日志，不清理原件、不使用全局 prune，也不重复执行会覆盖已导入数据的程序。上线是后续阶段，需要重新核实安全版本、凭据和生产资源。
