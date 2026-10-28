# Subscription Composer

为官方 SFM / SFA 生成完整 sing-box 远程配置的个人订阅服务。目标配置格式为 sing-box **1.14**；开发验证使用 **1.14.4**。服务使用 Go，除 YAML 解析库外不依赖第三方运行框架。

## 已实现

- 多来源 HTTP(S) / 本地文件订阅，支持原生 sing-box 节点、常见分享链接及 SS / VMess Clash YAML。
- ikuuu 网页 App Token 授权、设备绑定、自动刷新及官方节点 API；[授权使用说明](docs/ikuuu-auth.md)。
- 节点按国家分组；每个国家都有手动选择器和 URLTest，另有 `main`、`regional`、全局 `auto`。
- 每次请求订阅都会尝试检查上游；默认 2 秒防抖，同一时刻的刷新请求共用一次任务。
- 上游 ETag / Last-Modified 条件请求；304 代表本次已经检查过上游，没有内容变化。
- 来源分别回退上次成功数据；没有任何成功数据的来源失败时，不发布缺失来源的新配置。
- 所有设备配置构建及校验成功后原子发布；失败继续提供上一次成功快照。
- 原生 sing-box 用户规则、设备基础配置、每设备独立鉴权、检查状态接口。
- 远程规则集由服务端检查并内联到分发配置；客户端启动不依赖 GitHub 下载。

不包含地区解锁检测、候选池管理网页、服务端测速或配置自动推送。ikuuu API 域名变化暂时通过来源配置处理，不自动运行官方 GrowthBook / 应用侧 HTTPDNS 逻辑。节点入口 DNS 独立处理：导入官方配置中的定向解析策略，由客户端实时查询服务商 DNS。

## 本地启动

所有开发工具在 Nix 环境中临时提供，不安装到系统。`~/flake/develop` 当前没有 Go，因此以下使用 `nix-shell`。

```bash
nix-shell -p go --run 'go test ./...'
nix-shell -p go --run 'go build -o ./bin/subcompose ./cmd/subcompose'
```

先复制 [examples/config.json](examples/config.json) 为自己的配置，并按实际情况修改。示例的 `examples/nodes.json` 使用保留文档地址，**只能验证配置合成，不能连接外网**。

- 把 `sources` 改成真实订阅；相对文件路径以服务配置文件目录为根。
- `snapshot_dir` 指定可写的专用目录；其中包含节点凭据，权限保持 0700 / 0600。
- 设置 `check_binary` 为 sing-box 1.14.4 CLI 的绝对路径或 PATH 中的名称。SFM.app 本身不是这个 CLI。
- 示例含 Tailscale endpoint；如 Mac 已运行独立 Tailscale，首次验证先移除这个 endpoint 及对应 DNS / 路由项，避免两套实例冲突。
- 修改示例中的 `campus.example.edu`、校园网 DNS 和特定内网 CIDR。
- Android 与 macOS 使用独立 Remote Profile 和本地状态。

```bash
export SUBCOMPOSE_MACOS_TOKEN="$(openssl rand -hex 32)"
export SUBCOMPOSE_ANDROID_TOKEN="$(openssl rand -hex 32)"
./bin/subcompose -config ./examples/config.json -check
./bin/subcompose -config ./examples/config.json
```

生产环境把令牌保存到权限受限的环境文件，重启服务时沿用。令牌至少 24 字节，各设备必须不同。`env:VARIABLE_NAME` 可用于设备令牌、来源 URL 和来源请求头值；未设置的环境变量会导致启动失败。

## 分发接口

| 路径 | 方法 | 用途 |
| --- | --- | --- |
| `/profiles/macos.json` | GET | 检查上游并返回 macOS 配置 |
| `/profiles/android.json` | GET | 检查上游并返回 Android 配置 |
| `/profiles/{device}/refresh` | POST | 忽略防抖窗口，强制检查上游，返回状态 |
| `/profiles/{device}/status` | GET | 只读状态，不触发更新 |
| `/healthz` | GET | 无鉴权存活检查，不代表已有可用配置 |

除 healthz 外，使用 HTTP Basic（用户名为设备 ID，密码为设备令牌），也支持 `Authorization: Bearer`。**不接受 query token**，避免令牌进入常规 URL 日志。可以在配置 URL 上加 `?refresh=force` 明确绕过防抖；仍然需要鉴权。强制刷新会与已经进行中的刷新共用结果，不会同时重复抓取。

```bash
curl --fail --user "macos:$SUBCOMPOSE_MACOS_TOKEN" \
  http://127.0.0.1:8080/profiles/macos.json -o /tmp/macos.json
curl --fail --user "macos:$SUBCOMPOSE_MACOS_TOKEN" \
  -X POST http://127.0.0.1:8080/profiles/macos/refresh
curl --fail --user "macos:$SUBCOMPOSE_MACOS_TOKEN" \
  http://127.0.0.1:8080/profiles/macos/status
```

响应使用 `Cache-Control: no-store`。`X-Upstream-Checked-At`、`X-Config-Published-At`、`X-Config-Revision`、`X-Config-Stale` 区分“刚检查但没有变化”和“失败回退旧配置”。来源失败但仍能使用该来源缓存时，GET 返回可运行的配置并标记 stale；首次没有可发布配置时返回 503。强制刷新状态接口只在无法完成配置发布时返回 502，部分来源使用缓存需检查 `sources[].stale`。

## 在 SFM / SFA 中使用

创建 **Remote Profile**，填入带 URL userinfo 的配置地址。已核对 SFM 当前界面：没有单独的 Basic 用户名 / 密码字段，用户名与密码放在 URL 中；用户名为设备 ID，密码为对应令牌。随机令牌使用十六进制可避免 URL 转义问题。公网部署使用 HTTPS；URL 含令牌，不要分享或记录完整地址。

```text
http://macos:DEVICE_TOKEN@127.0.0.1:8080/profiles/macos.json
https://macos:DEVICE_TOKEN@subscriptions.example.com/profiles/macos.json
```

尚未实际操作 SFM GUI 完成导入；后端 Basic 鉴权与分发接口已通过 HTTP 验证。

官方导入 Scheme：

```text
sing-box://import-remote-profile?url=URL_ENCODED_PROFILE_URL#URL_ENCODED_NAME
```

该链接用于导入地址；不要假定它同时携带或设置了客户端的鉴权字段。

合成器为所有设备自动添加两个仅监听本机的 HTTP / SOCKS 混合入口：`127.0.0.1:7890` 使用正常分流规则；`127.0.0.1:7891` 优先路由到 `direct`，覆盖基础规则与用户规则。没有 `direct` 出站时自动补充。设备基础配置不得占用这两个端口或 `mixed-rules` / `mixed-direct` 标签；`direct` 标签必须对应原生 direct 出站。7891 指定连接出口，DNS 仍遵循原生解析配置。更新 Remote Profile 并重新加载客户端配置后生效。

```bash
curl --proxy http://127.0.0.1:7890 https://example.com
curl --proxy http://127.0.0.1:7891 https://example.com
```

Dashboard / Groups 中按 `main`、`regional`、其余组的顺序展示；可展开国家组，选择自动组或具体节点。`main` 默认选 `auto`；`regional` 默认选 `main`。国家组被两个入口共享，因此切换同一个国家组会同时影响引用它的入口。

合成器启用客户端缓存并为每台设备提供稳定 `cache_id`。更新同一个 Remote Profile；不要每次重新导入新 profile，也不要清理客户端工作目录。这样才能保留选择和 Tailscale 登录状态。国家变化不改变节点 tag；同一来源内的原始节点名称改变会产生新 tag，当前不做模糊身份合并。

URLTest 只代表访问测试 URL 的连通性；历史成功不保证当前可用，也不代表 Gemini 接受该出口。手动切换选择器配置为中断相关旧连接；自动测速组不因选优主动切断已有连接。`interrupt_exist_connections` 只控制运行中组内出口切换，不保证整份配置重载保留连接。SFM 更新当前已连接的 Remote Profile 时，内容相同不触发重载，内容变化会请求重载 service；节点列表更新不能视为无断线热更新。

## 配置结构

服务只拥有来源、分组和更新配置。`devices[].base`、`policy.rules`、`policy.rule_sets` 使用原生 sing-box JSON，不另设计路由语言。

```json
{
  "sources": [
    {
      "id": "airport",
      "url": "env:AIRPORT_SUBSCRIPTION_URL",
      "format": "auto"
    }
  ],
  "policy": {
    "country_overrides": {"airport/My Node": "JP"},
    "rules": [
      {
        "domain_suffix": ["example.com"],
        "action": "route",
        "outbound": "regional"
      }
    ]
  }
}
```

以上只是片段，完整字段见示例。服务配置顶层拒绝未知字段；原生 JSON 的具体字段由匹配版本的 `sing-box check` 校验。

合并顺序：

1. 自动生成的 `mixed-direct` 入口直连规则。
2. `base.route.rules`：Tailscale、DNS 接管、内网等基础规则。
3. `policy.rules`：原生手动例外。
4. `direct_domains`、`direct_cidrs`、`regional_domains`：少量便利配置。
5. `direct_rule_sets`。
6. 最终出口固定为 `main`。

基础规则优先于手动例外；如果需要某条例外覆盖内网规则，把相应原生规则放进 `base.route.rules` 的正确位置。域名输入和 DNS 分流需要同时考虑：例如新增校园网直连域名，也应将其加入校园 DNS 规则。客户端仅有域名目的地时，IP 分类可能需要显式的原生 `resolve` 动作；不要假定它与 Xray 的 `DomainStrategy` 完全等价。

来源提取节点，不继承机场的通用 route / dns。Clash 配置中的 `x-client-custom.nameserver-policy` 是一个受限例外：只为匹配节点服务器域名附加独立的原生 `domain_resolver`，不改变设备的网站 DNS 规则。支持精确域名、`+.example.com`（含根域名）和 `*.example.com`（仅子域名），更具体的匹配优先；IP 节点和未匹配节点沿用设备设置。支持 UDP / TCP / TLS / HTTPS 解析入口；有 TCP 时优先使用上游提供的首个 TCP 入口，否则使用列表中的首个入口。这是为受限网络下专用 DoH 可能被重置连接而采用的确定性选择，不移植 Mihomo 的多入口自适应选择及备用入口调度。解析器地址随来源更新，入口 IP 由客户端动态解析，不写死到节点中。解析器自身的域名通过设备 `route.default_domain_resolver` 直接解析；该 bootstrap 必须无代理依赖、无解析环路，设备未指定时生成一个 local bootstrap。

`type` 缺省时是普通订阅；`type: ikuuu` 的 `url` 表示 API base URL，授权单独保存在 `snapshot_dir/auth`。Clash 输入当前支持 SS / VMess，不是完整 Clash 配置执行器。节点名称在一个来源内必须唯一；遇到空订阅、未知协议、无效的定向 DNS 策略或无法保真的分享参数会拒绝该来源新数据并回退缓存，避免静默更改连接语义。原生节点中的来源内部 detour / resolver 拓扑暂不导入。

国家来自节点名称中的地区标识或显式覆盖，不查询入口 IP 地理位置。`country_overrides` 优先匹配 `sourceID/name`，再匹配 `name`；未知国家归入 `OTHER`。

## 快照和刷新

快照文件保存来源内容、规则集原始数据及解码缓存、HTTP validators、检查时间和全部设备配置。发布通过一个临时文件加原子 rename 完成，不会混合不同代的设备配置。来源配置指纹改变后，不复用旧来源响应缓存。保留一个已发布快照，不做无限历史归档。

服务启动读取快照但不主动抓取；首次请求会检查上游。后台刷新独立于请求取消运行，受 `refresh_timeout` 限制。构建或外部校验失败时，新来源响应缓存不会单独提交；下一次刷新会重新获取，磁盘快照始终是一代完整的已发布数据。授权记录独立提交：ikuuu Token 轮换成功后立即保存，即使后续构建失败也保留新 Token。备份与迁移需要同时保存快照和 `auth` 目录。

`check_binary` 留空时只有结构与引用检查，**生产环境应启用原生校验**。校验器错误输出可能包含配置凭据，因此状态接口只返回安全错误；需要详细诊断时，在受控环境对自己生成的配置运行 CLI。配置检查不会验证网络可达性、Tailscale 登录或网站地区解锁。

远程 rule-set 由服务端下载，二进制 `.srs` 使用 `check_binary` 指定的 sing-box 解码，再转换为原生 `inline` 条目。客户端收到完整规则，不会再按远程 URL 下载。示例为静态规则集设置原生 `update_interval: "24h"`，在周期内复用已验证缓存，并保留真实的上次检查时间；机场节点来源仍在每次订阅刷新时检查上游。省略 update_interval 则每次刷新也检查该规则集。服务端遵循自己的 HTTP_PROXY / HTTPS_PROXY 环境；规则里的客户端 `download_detour` 不用于服务端抓取。非空原生 `http_client` 暂不支持，以免误用客户端拨号设置。规则集失败时可回退同一配置指纹的缓存；首次没有缓存时阻止发布。状态接口以 `ruleset:<tag>` 展示检查和 stale 状态。离线启动、校园网 DNS、订阅更新及 Android 网络切换仍需在真实客户端验收。

## 部署

推荐单进程运行于 VPS，监听 `127.0.0.1:8080`，由反向代理提供 HTTPS。状态目录放在持久卷；来源 URL 和令牌由运行环境提供。Go 二进制与 sing-box CLI 均需存在，且目标配置格式保持一致。

```bash
nix-shell -p go --run 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o ./bin/subcompose-linux-amd64 ./cmd/subcompose'
```

systemd 和 Caddy 示例位于 [deploy](deploy/)。它们是部署模板，本项目没有向任何服务器发布或修改系统服务。

仅内网 / Tailscale 可达的分发地址需要单独准备首次导入和恢复路径：客户端丢失 Tailscale 登录状态后，不能依赖同一条 tailnet 连接才能下载配置。

## 验证

```bash
nix-shell -p go --run 'go test -race ./... && go vet ./...'
```

覆盖解析稳定性、原生规则引用、合并顺序、并发刷新、条件请求、强制刷新、防抖、来源失败回退、原子发布和 HTTP 鉴权。静态 `sing-box check` 不会初始化所有 DNS 拨号器，因此另有一个不创建 TUN、不登录 Tailscale 的 DNS 启动测试：

```bash
SUBCOMPOSE_SING_BOX=/absolute/path/to/sing-box nix-shell -p go --run 'go test ./internal/compose -run TestNativeExampleDNSStartup -v'
SUBCOMPOSE_SING_BOX=/absolute/path/to/sing-box SUBCOMPOSE_NETWORK_TEST=1 nix-shell -p go --run 'go test ./internal/compose -run TestNativeExampleRuleSetDownloads -v'
```

直连 DNS 服务器省略 `detour`；指向没有额外拨号选项的空 `direct` outbound 会在启动时失败。SFM / SFA 的 GUI 导入、选择持久化、Tailscale 身份和实际校园网分流另需真机验证。
