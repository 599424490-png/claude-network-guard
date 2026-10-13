# Claude Network Guard

A Windows launcher and firewall guard for Claude Desktop with Clash Verge / Mihomo. It checks the proxy before launch, blocks non-loopback connections for covered Claude executables, and closes Claude when protection fails.

用于 Windows 的 Claude 桌面端网络保护器。适合希望 Claude 始终通过本机 Clash 代理联网、避免误关代理或切换路由模式后程序继续运行的用户。

## 它有什么作用

- **启动前检查**：确认系统代理、本地代理端口、实时 Mihomo 全局模式、TUN 自动路由、手动选择的代理链和出口 IP。三个独立 IP 查询服务中至少两个结果一致才启动。
- **限制直接联网**：Windows 防火墙拦截已覆盖 Claude 程序对非回环 IPv4/IPv6 地址的入站和出站连接，保留与本机代理的回环通信。
- **运行中保护**：持续检查本地代理、路由模式、节点和防火墙。保护失效或检测到出口变化时，强制关闭 Claude 及其子进程。
- **减少误退出**：单轮 IP 查询失败先进行独立 HTTPS 复核；Google、Cloudflare、Apple 中任一测试网站可通过代理正常访问，就继续运行。连续两轮全部失败才按上游不可用处理。
- **保护器崩溃也关闭 Claude**：使用 Windows Job 的 `KILL_ON_JOB_CLOSE`。Claude 以挂起状态创建，绑定 Job 后才执行程序。

项目不修改或重置 Claude 账号，也不提供账号封禁规避功能。它限制网络路径，不能保证匿名或防止账号封禁。它是独立社区工具，与 Anthropic、Clash 或 Microsoft 没有隶属关系。

## 支持环境

- Windows 10/11，推荐 64 位 Python 3.11 或更新版本，安装时包含 `py` 启动器。
- Claude Desktop 安装在 `%LOCALAPPDATA%\AnthropicClaude`，且存在 `app-*\claude.exe`。其他安装布局目前不支持直接启动。
- Clash Verge Rev / Mihomo，启用系统代理、**global 全局模式、TUN 和 auto-route**。
- 当前版本固定使用 `http://127.0.0.1:7897`；配置中的其他代理地址会被拒绝。
- `GLOBAL` 策略链必须使用手动选择的 Selector 和真实节点；DIRECT、自动切换组及负载均衡不放行。
- 安装防火墙规则需要管理员权限；运行保护器不需要管理员权限。

## 安装与启动

将仓库放在固定、可信的目录中。创建快捷方式后移动目录，需要重新执行安装步骤。

在该目录打开 PowerShell：

```powershell
py -3 -m pip install -r requirements.txt
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup.ps1
```

`setup.ps1` 会复制示例配置、从 C# 源码编译防火墙测试程序、请求 UAC 管理员授权并安装规则，最后创建桌面上的 **Claude (Network Guard)** 快捷方式。现有同名受保护快捷方式会更新；其他 Claude 快捷方式不自动替换。

安装会开启 Domain、Private、Public 三种 Windows 防火墙配置，并为发现的 Claude 可执行文件添加拦截规则。原开关状态保存在本机 `firewall-original-profiles.json`。安装过程中使用独立测试程序验证回环代理可达、外部 IPv4 被访问拒绝；不会主动停掉代理进行测试。

先在 Clash Verge 中选择代理节点并启用上述设置，再彻底退出已有 Claude，包括托盘实例。以后通过 **Claude (Network Guard)** 启动。启动失败时会显示中文原因；保护失败时先关闭程序，再提示原因。

配置文件 `guard-config.json` 支持 `%LOCALAPPDATA%`、`%APPDATA%` 等环境变量。默认不固定国家或 IP；`allowed_exit_ips` 为空时接受启动时选中代理的当前出口，并在运行中检查是否变化。

```json
"allowed_exit_ips": ["你确认可信的公网 IPv4"]
```

这是填写格式示意；请替换成真实地址再使用。程序不会为对比而请求你的直连公网 IP。更换节点或出口会触发退出，请关闭 Claude、调整 Clash 后重新启动。

## 检查和撤销

```powershell
# 完整启动条件检查，不启动 Claude
py -3 .\claude-guard.pyw --check

# Claude 已运行时，只检查网络和防火墙，不关闭程序
py -3 .\claude-guard.pyw --check-network
```

检查命令的 JSON 输出包含当前代理出口 IP 和所选策略链；提交故障报告前请自行删去这些字段。日志仅保存事件、检测域名、耗时和异常类别，不保存账号、凭据或出口 IP。

撤销时先关闭 Claude 和保护器，再在管理员 PowerShell 运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\restore-firewall.ps1
```

它删除安装清单中的规则并恢复安装前的防火墙开关。之后可手动删除 **Claude (Network Guard)** 快捷方式。保留本机备份文件，直到确认不需要恢复。

## 检测延迟与保护范围

本地端口和系统代理约每 0.25 秒检查一次；Clash 路由与防火墙约每秒核验。IP 检测每轮最多 8 秒，完成后等待 5 秒。上游复核每轮最多 5 秒，两轮间隔 1 秒，因此远端故障通常在约 25 秒内处理；系统繁忙时可能更久。复核过程中防火墙继续限制已覆盖程序的直连。

HTTPS 复核证明代理仍能承载请求；IP 查询恢复前无法重新确认公网出口。多个检测网站持续不可达也可能造成保守强退，不能当作节点实际掉线的绝对证据。强退可能丢失未保存内容。

防火墙覆盖以下目录下发现的 `.exe`：

```text
%LOCALAPPDATA%\AnthropicClaude
%APPDATA%\Claude\claude-code
%USERPROFILE%\.local\share\claude
```

规则按程序路径匹配。Claude 更新产生新程序时，保护器会拒绝启动，请重新运行安装脚本。直接打开 Claude、协议链接和其他启动入口可能绕过后台监控；已经覆盖的程序仍受防火墙规则约束。

外部 MCP 工具、自行安装的 Python/Node、Cowork 虚拟机、其他代发流量的 Windows 服务未建立完整隔离。程序可以读取本机网卡信息；这里的规则不能阻止所有间接泄漏方式。管理员关闭防火墙或修改规则会使隔离失效，保护器发现后会强退，仍存在检查延迟。

IPv6 无路由时测试报告会明确标为 `socket-error-10051`，而非“实测被防火墙拦截”；此时 IPv6 地址范围依靠规则核验确认。项目不保证覆盖所有 Windows 网络栈和第三方安全软件组合。

## 开发和验证

```powershell
py -3 -m unittest discover -s tests -v
powershell -NoProfile -ExecutionPolicy Bypass -File .\build-probe.ps1
```

测试使用模拟网络及独立测试进程，不会关闭用户的 Claude，不需要停掉真实代理。覆盖启动拒绝条件、Job 绑定时序、监控异常关闭、出口查询复核、直连回退拒绝和命名管道分段响应读取。CI 在 Windows 上运行测试和脚本语法检查。

本地安装配置、日志、防火墙备份、快捷方式及编译生成的程序由 `.gitignore` 排除。请勿把代理密钥、账号令牌或个人运行记录提交到仓库。

采用 MIT 许可证，见 [LICENSE](LICENSE)。

## 实现参考

- [Electron 代理启动参数](https://www.electronjs.org/docs/latest/api/command-line-switches)
- [Mihomo 配置与代理 API](https://wiki.metacubex.one/en/api/)
- [Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
