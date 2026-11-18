# Linux / OpenRC 订阅客户端

客户端与 composer 分工：composer 生成节点、路由和原生管理 API 服务；`sing-box-client` 获取、校验、暂存及应用订阅。本机文件仅保留可选日志设置，客户端不是常驻进程，定时获取由 Cronie 执行。

## 配置目录

```text
/etc/sing-box/
    10-local.json
    20-subscription.json
/etc/sing-box-client/
    client.json
    subscription-token
/var/lib/sing-box-client/
```

sing-box 使用 `-D /var/lib/sing-box -C /etc/sing-box` 启动。Linux / macOS 订阅默认由 composer 生成一个原生 API 服务，Android 默认不生成；设备配置可覆盖平台默认值。正常配置由空或仅含日志设置的本机文件与包含一个 API 的订阅组成；客户端也兼容本机保留一个旧 API、订阅不含 API 的布局。最终配置对必须恰有一个 API，服务 tag 不得重复，本机文件只允许 `services` 和 `log` 字段，且不允许其他类型的本机服务。本机文件必须存在且为普通文件，可以使用 `{}`，见 [本机配置示例](../deploy/linux/local.example.json)。

运行目录中的其他 `.json` 文件同样会被加载，因此候选版本和备份必须位于状态目录。客户端拒绝未受管理的额外 JSON 文件，避免校验输入与运行输入不同。

含密钥的配置、订阅与凭据使用 `0600`，客户端配置目录及状态目录使用 `0700`，由 root 管理。API 密钥和订阅令牌分别管理，不写入命令行或日志。

客户端字段见 [配置示例](../deploy/linux/client.example.json)。订阅 URL 不包含用户名和令牌：用户名使用 `username`，令牌从 `token_file` 指定的文件读取。composer 管理的 API secret 应在后续订阅生成中保持稳定，并与连接 API 的客户端一致；重新 fetch 不应随机更换密钥。旧本机 API 的密钥不会自动复制到订阅，迁移前应在 composer 中配置好预期密钥。

健康探测必须使用具体主机地址，端口必须与 API 的 `listen_port` 一致。客户端会在应用前校验地址兼容性：`::` 通配监听可接受 IPv4/IPv6，`0.0.0.0` 只接受 IPv4，具体监听地址必须匹配探测目标。不能将 `0.0.0.0` 或 `::` 用作探测目标。

## 操作

```sh
sudo /usr/local/bin/sing-box-client fetch --config /etc/sing-box-client/client.json
sudo /usr/local/bin/sing-box-client status --config /etc/sing-box-client/client.json
sudo /usr/local/bin/sing-box-client apply --config /etc/sing-box-client/client.json
sudo /usr/local/bin/sing-box-client rollback --config /etc/sing-box-client/client.json
```

`fetch` 只下载、原生检查并暂存，不重载。当订阅包含一个 API，而本机仍保留一个旧 API 时，客户端会生成只移除旧 API、保留日志的临时本机文件，在配置目录之外与候选订阅一起交给 sing-box 校验，线上两个文件均不改变。它不会手写合并原生配置。

`apply` 重新读取本机配置并执行相同投影与校验，确认备份能够组成有效恢复配置对后，先保存原始本机文件的精确字节、上一份订阅及其存在状态，再持久化事务记录，最后写入新的本机文件与订阅。配置无有效变化时跳过重启。JSON 对象键顺序和空白不影响比较，数组顺序会影响比较。

应用使用 OpenRC restart，会中断旧实例的连接。状态目录中的私有 `backup-*` 目录内，`previous-local.json` 和 `previous.json` 组成配套恢复点；状态文件通过 `backup_generation` 引用已发布的目录，并记录配对标记及内容校验值。新恢复点先在独立目录写入并校验，再原子发布状态，不覆盖仍被旧状态引用的文件。旧备份目录暂时保留，尚未自动清理。启动或健康检查失败时会恢复两个输入，即使应用后手动修改过本机文件，也会恢复备份的精确原文。首次从旧 API 本机配置应用失败时，恢复原本机文件并删除新订阅；不会留下旧订阅加已剥离 API 的本机文件。

中途退出后，使用 `status` 查看状态并显式执行 `rollback`；事务未恢复前不能继续 fetch/apply。恢复会先验证完整备份对，再修改线上输入；备份丢失、损坏或原生校验失败会拒绝恢复并保留事务状态。旧版本没有配对标记的恢复状态只使用当前本机文件与旧订阅进行校验，不会假定存在本机备份，也不会自动剥离 API。磁盘上的配置不直接视为已成功运行。

健康检查覆盖 OpenRC 服务状态及管理监听端口的短期稳定性，不保证外部网站连通性或节点可用性，也不代替 API 鉴权验收。

## OpenRC

沿用系统提供的 `/etc/init.d/sing-box`；通过 `/etc/conf.d/sing-box` 固定配置目录和工作目录：

```sh
SINGBOX_CONFIG="/etc/sing-box"
SINGBOX_WORKDIR="/var/lib/sing-box"
```

首次接入时，先私有备份原配置，将其中的旧 API 配置保留为 `10-local.json`，并移走原来的 `config.json`，防止重复加载。首次应用需要一个有效恢复点：若订阅尚不存在，应保留原本机 API，客户端会在应用包含 API 的新订阅时自动迁移；已有包含 API 的订阅时，本机文件可以为空或仅含日志。首次订阅若启用 TUN，会改变主机路由；应保留独立恢复入口，在确认候选配置通过检查后单独应用。

## Cronie

将 `deploy/linux/cron/sing-box-client.example` 安装为 `/etc/cron.d/sing-box-client`，所有者 root、权限 `0644`。按本机 OpenRC 服务名称启用 Cronie：

```sh
sudo rc-update add cronie default
sudo rc-service cronie start
```

默认每天 00:17、08:17、16:17 触发获取，并加入最多 5 分钟随机延迟；时间以客户端本机时区为准，不自动应用。客户端错误写入标准错误与 syslog，状态文件保存最近操作结果；定时任务关闭邮件发送。

## 构建与验证

```sh
nix-shell -p go --run 'go test ./internal/clientupdate ./cmd/sing-box-client'
SUBCOMPOSE_SING_BOX=/absolute/path/to/sing-box nix-shell -p go --run 'go test ./internal/clientupdate -run TestNativeAPIMigrationPairValidation -v'
nix-shell -p go --run 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /tmp/sing-box-client ./cmd/sing-box-client'
```

部署后检查 `fetch` 不改变 sing-box PID；第一次应用后检查管理 API、代理入口和网络；重复应用相同配置不应改变 PID。客户端与目标服务必须使用同一个 sing-box 二进制及工作目录进行原生校验。
