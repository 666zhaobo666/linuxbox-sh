# LinuxBox 全功能 Linux 管理脚本

一款面向运维和开发者的 Linux 一键管理脚本。覆盖系统管理、网络与安全、建站与容器、性能测试与加速、应用市场、开发环境、反向代理等 15 大模块，支持 Ubuntu / Debian / CentOS / Arch / Fedora 等主流发行版。

## 安装方法

### 一键安装（推荐）
```bash
bash <(curl -sL https://raw.githubusercontent.com/666zhaobo666/linuxbox-sh/main/install.sh)
```

### 国内加速
```bash
bash <(curl -sL https://proxy.cccg.top/raw.githubusercontent.com/666zhaobo666/linuxbox-sh/main/install.sh)
```

> 脚本会自动把入口、lib/、modules/ 全量下载到 `/usr/local/bin/linuxbox/`，创建 `j` 快捷命令，安装完输入 `j` 即可启动。

## 使用方法

终端输入 `j` 启动脚本，主菜单按编号选择功能。

常用快捷命令：

```bash
j help              # 查看命令行帮助
j update            # 更新脚本 (单进度条全量下载, 失败自动回滚)
j install nano wget # 安装软件包
j service restart docker  # 重启服务
j docker            # Docker 管理菜单
j web               # LDNMP 建站菜单
j caddy             # Caddy 反代管理菜单
j firewall          # 防火墙管理菜单
j ssl example.com   # 申请/管理证书
j swap 2048         # 设置 2048M 虚拟内存
j time Asia/Shanghai # 设置时区
j open-port 80 443  # 开放端口
j close-port 8080   # 关闭端口
```

## 框架配置

默认配置文件位于 `~/.linuxbox/config`：

- `SCRIPT_BRANCH`：脚本更新分支，默认 `main`。
- `key`：快捷命令，默认 `j`。

版本号唯一来源在 `LinuxBox.sh` 顶部 `version="x.y.z"`，升版本只需改这一处（主菜单显示 + 远程 update 比对 + 更新后校验都读这一行）。

## 功能介绍

### 一、系统信息查询

- 一键显示主机名、系统版本、CPU 架构与型号、内存、硬盘、网络、地理位置、运营商、DNS、系统时间、运行时长等详细信息。
- 自动识别公网/本地 IP 与 IPv6 地址。

### 二、系统工具合集

- 脚本快捷键、用户与密码管理、SSH 端口与登录策略、DNS 优化、IPv4/IPv6 优先级切换、端口占用、虚拟内存调整、主机名修改、系统时区切换、系统更新源切换、定时任务管理、文件管理器、系统语言切换、系统回收站、SSH 远程连接、硬盘分区管理、命令行历史与收藏夹、命令行美化。

### 三、系统清理

- 一键清理包管理器缓存、孤立依赖、系统日志、临时文件。
- 覆盖 `apt / dnf / yum / apk / pacman / zypper / opkg / pkg` 八种主流包管理器。
- 自动 rotate 与 vacuum `journalctl` 日志（`vacuum-time=1s` + `vacuum-size=500M`）。
- 集成 `fix_dpkg` 工具，apt 卡死时自动解锁 `/var/lib/dpkg/lock*` 并恢复 `dpkg --configure -a`。

### 四、基础工具

- 一屏展示 21 个常用工具的安装状态（curl / wget / sudo / socat / htop / iftop / unzip / tar / tmux / ffmpeg / btop / ranger / ncdu / fzf / vim / nano / git / cmatrix / sl / bastet / nsnake / ninvaders）。
- 支持单装、单卸、一键全装（`31`）、一键全装（不含屏保和游戏，`32`）、一键全卸（`33`）、按名装卸（`41` / `42`）。
- 屏保与小游戏：黑客帝国（cmatrix）、跑火车（sl）、俄罗斯方块（bastet）、贪吃蛇（nsnake）、太空入侵者（ninvaders）。
- 集成 opencode AI 编程助手一键安装。

### 五、测试工具合集

- IP 与解锁检测：ChatGPT 解锁检测、流媒体解锁、IP 质量体检。
- 网络测速：besttrace 三网回程、mtr_trace 回程线路、Superspeed 三网测速、nxtrace 快速/指定 IP 回程、ludashi2020、i-abc、NetQuality。
- 硬件性能：yabs、cpu-gb5、bench、spiritysdx 怪测评。
- 一键调用，自动安装依赖，结果清晰展示。

### 六、Docker 容器管理

- 一键安装/卸载/更新 Docker，支持官方源与国内镜像源切换。
- 容器/镜像/网络/卷全生命周期管理，IPv6 支持开关，daemon.json 可视化编辑。
- 一键清理停止的容器、未使用的镜像、网络、卷，释放系统空间。

### 七、LDNMP 建站管理

- 一键部署 LNMP/LDNMP 环境（Docker 版），支持多版本。
- 站点与数据库增删、SSL 证书自动申请与续签、phpMyAdmin 升级、CF 缓存清理。
- Nginx WAF 开关、WordPress 调试/URL/内存一键修复、Nginx 压缩（gzip/zstd/br）配置。

### 八、Caddy 反向代理管理 ⭐

- **一键安装 Caddy**：官方源（Cloudsmith），自动添加 apt 源 + GPG key；安装时自动跳过 `/etc/caddy/Caddyfile` 的 dpkg 冲突（用 `--force-confold` 保留用户现有配置）。
- **仪表盘**：6 列实时展示所有反代（域名 / 反代目标 / 类型 / SSL 状态 / 备注 / 网站目录），类型自动识别（反向代理 / 静态网站 / PHP 站点 / 负载均衡 / 重定向 / 综合配置）。
- **基础功能**：
  - 添加反向代理（域名 + 目标 + 备注）
  - 删除主机配置（二次确认）
  - 修改主机备注
- **高级配置模式**（每项前先选域名，指令安全追加到 vhost 块内 `{}` 中）：
  1. 静态文件托管（`root *` + `file_server`）
  2. 基础密码保护（`basicauth`，密码经 `caddy hash-password` bcrypt 处理）
  3. 重定向 / URL 重写（`redir` / `rewrite`）
  4. 负载均衡 + 健康检查（`reverse_proxy A B { lb_policy round_robin; health_uri /health }`，自动替换原 `reverse_proxy` 行）
  5. HTTP 请求头管理（`header`）
  6. IP 黑名单 / 访问限制（`@blocked` + `abort`）
  7. PHP FastCGI（`php_fastcgi unix:///run/php/...`）
- **安全机制**：每次修改 vhost 前自动 `cp` 备份 → 写入新指令 → `caddy validate --config /etc/caddy/Caddyfile` 校验 → 校验成功才 `systemctl reload caddy` 并删备份；**校验失败自动从备份回滚**，并打印 caddy 错误信息。
- **文件布局**：
  - 主配置 `/etc/caddy/Caddyfile`（脚本自动管理 `import /etc/caddy/vhosts/*.conf`）
  - 每个域名一个独立 vhost 文件 `/etc/caddy/vhosts/<domain>.conf`
  - 备注以 `# remark: xxx` 注释形式存于 vhost 块内（`caddy validate` 自动忽略）
- **SSL 状态**：检测 Caddy 默认证书目录（Let's Encrypt / ZeroSSL），实时显示 [已签发] / [待签发/无]。
- **未安装友好**：首次进入自动检测，已安装直接进主面板，未安装给"安装 / 退出"二选一。
- **卸载询问**：卸载前明确询问是否保留 `/etc/caddy`（配置）和 `/var/lib/caddy`（证书），按用户选择决定是否 `rm -rf`。
- **运行状态**：仪表盘底部显示服务状态（运行中/未运行/未安装）+ Caddy 进程实际 RSS 物理内存。

### 九、防火墙配置

- 一键安装/卸载 firewalld 与 iptables，自动识别当前防火墙类型。
- 端口开放/关闭、IP 白/黑名单、国家 IP 规则（ipset+ipdeny）、DDOS 防御、PING 管理。
- 规则自动保存与恢复，支持重启后生效。

### 十、BBR 加速管理

- 一键开启 BBR / BBR Plus / BBR2 / 锐速 / Lotserver，自动检测内核版本。
- 内核不满足时自动安装适配内核。
- 状态检测与 sysctl 自动优化。

### 十一、WARP 管理

- Cloudflare WARP 客户端一键安装/卸载/状态查看。
- 支持 WARP 模式切换、WARP+ 接入、Teams 团队配置。
- 集成 Cloudflare 官方源与多发行版包管理（apt/yum）。

### 十二、应用市场

- 主流运维/建站面板一键管理：1Panel、宝塔、aaPanel 等。
- Docker 应用市场：常用应用安装、统计、访问地址检测、端口管理。
- crontab 自动检测、iptables 规则持久化、应用 ID 与目录管理。

### 十三、服务器集群管理

- 通过 SSH 远程批量管理多台服务器。
- 服务器列表可视化，命令一键下发到全部节点。
- 配置文件格式：`名称|IP|端口|用户名|密码`，权限可控。

### 十四、游戏服务器管理

- Minecraft 基岩版/Java 版一键开服，集成服务端核心下载与管理。
- 幻兽帕鲁（Palworld）专用开服脚本，支持备份与日志管理。
- 适合多人联机服务器快速部署。

### 十五、Dev 环境管理

- Python 多版本管理（pyenv）：安装、切换、卸载，自动配置环境变量。
- 数据库 Docker 化部署：MySQL、PostgreSQL 多版本可选，密码与数据目录可自定义。
- 编译依赖自动检测与安装。

## 主要特点

- **一键化操作**：所有功能均可通过菜单或命令行一键完成，运维效率大幅提升。
- **模块化架构**：入口脚本 + `lib/` 公共库 + `modules/` 功能模块，加新功能只动一处。
  ```
  LinuxBox.sh        # 入口 + 主菜单
  lib/               # 公共库 (常量 / 配置 / 工具 / 系统 / 网络 / 服务 / 安装 / 升级 / 命令分发 / 中文文案)
  modules/           # 功能模块 (15 个, 每个文件对应主菜单一项)
  ```
- **Caddy 反代深度集成**：仪表盘 + 基础 + 7 项高级配置 + 安全回滚 + 自动 SSL，一站式管理。
- **多发行版兼容**：支持 Ubuntu、Debian、CentOS、Arch、Fedora 等，主流架构（x86_64 / aarch64）开箱即用。
- **安全机制完善**：集成防火墙、DDOS 防护、WAF、回收站、误操作确认、配置回滚等多重安全措施。
- **智能检测**：自动检测依赖、磁盘空间、root 权限、系统类型，缺啥装啥、给提示不裸跑。
- **单一版本源**：版本号唯一在 `LinuxBox.sh` 顶部 `version="x.y.z"` 一行，升版本只动一处。
- **统一 UI 风格**：所有模块用同一套 `cyan/green/red/yellow/pink` 颜色变量和分隔线，无 emoji 装饰菜单项。

## 项目参考

- https://github.com/kejilion/sh
- https://github.com/xykt/IPQuality
- https://github.com/yuju520/YujuToolBox
- https://github.com/zhucaidan/BestTrace-Linux
- https://github.com/zhucaidan/mtr_trace
- https://github.com/evolutionboy/superspeed
