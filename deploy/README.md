# 部署模板

准备专用的 `subcompose` 用户和组，把编译产物放到 `/usr/local/bin/subcompose`，服务配置放到 `/etc/subcompose/config.json`。这些模板不会自动创建用户、修改系统或部署。

服务配置中的 `snapshot_dir` 应改成 `/var/lib/subcompose`，`check_binary` 指向已部署的 sing-box 1.14.4 CLI；不要使用 Nix 环境里恰好存在的其他版本。来源文件使用 `/etc/subcompose` 下的绝对路径。状态目录包含凭据，不放到公开静态目录。

将设备令牌和订阅链接放到权限受限的 `/etc/subcompose/environment`，使用服务配置中的 `env:` 引用。Caddy 模板需要替换实际域名并确保 DNS 已指向服务器。Basic / Bearer 鉴权由应用完成，反向代理应保留 Authorization 请求头。

```text
SUBCOMPOSE_MACOS_TOKEN=replace-with-random-token
SUBCOMPOSE_ANDROID_TOKEN=replace-with-another-random-token
AIRPORT_SUBSCRIPTION_URL=https://provider.example/subscription
```

模板默认只开放 HTTPS 反向代理，服务本身监听 loopback。若只从 LAN 或 Tailscale 分发，调整监听地址和访问路径，并保留首次导入的恢复方案。首次部署先调用鉴权状态接口和强制刷新接口；`healthz` 只证明进程可响应。
