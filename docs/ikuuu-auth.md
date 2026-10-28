# ikuuu App Token 来源

合成器通过官方网页登录获得 App Token，随后独立获取节点。密码由官网网页处理；服务不保存账号密码，不依赖官方应用常驻。普通 URL / 文件订阅仍然兼容。

## 已验证协议

- 登录入口：`/auth/login?redirect=%2Fapi%2Fv2%2Fweb-auth%2Fcall-client`。
- 回调：`ikuuu:///login?token=...`；token 参数是 Base64 JSON，包含 app_token、expires_at、token_type、is_active 等元数据。
- 回调中的 token_type 为 `app`，代表凭据用途；HTTP 请求仍使用 `Authorization: Bearer`。
- GET `/client-auth/token-info` 验证凭据。
- POST `/client-auth/refresh-app-token` 需要 JSON `device_id`、`device_name`，返回新的凭据。
- **刷新立即使旧 Token 失效**；新 Token 必须先持久化，再生成配置。
- GET `/nodes/profile` 返回 `data.profile`，目前是 Clash YAML。当前适配器提取其中 SS / VMess 节点，以及仅用于节点服务器域名的 `x-client-custom.nameserver-policy`；网站路由、DNS 和分组仍由合成器维护。

官方配置可能为节点域名下发服务商专用 DNS。合成器根据精确域名或后缀匹配，将策略中的解析入口转换为原生 sing-box DNS server，并仅在匹配节点上设置 `domain_resolver`。上游提供 TCP 入口时优先选择首个 TCP 入口，否则使用列表中的首个入口，以适应专用 DoH 在受限网络下被重置连接的情况。解析入口的域名使用设备的直连 bootstrap，节点入口 IP 仍由客户端实时查询；不依赖官方应用运行，也不发送 App Token 给 DNS 服务。当前不移植官方对多个 DNS 入口的自适应选择；每条策略只使用一个入口，不在运行时自动切换备用入口。策略随节点来源一起缓存、更新和回退，无需迁移现有快照；旧授权失效时，仍可从快照中的上次成功响应构建带 DNS 的配置。

已通过真实授权验证以上请求与响应；这是一套 App Token 登录流程，不按标准 OAuth2 Authorization Code / PKCE 接口实现。

## 配置来源

在服务配置中指定来源类型和 API 地址：

```json
{
  "sources": [
    {
      "id": "ikuuu",
      "type": "ikuuu",
      "url": "https://authcode.iku-client-comm-1.win/api/v2",
      "format": "clash"
    }
  ]
}
```

这是完整服务配置中的片段。API 地址来自官方客户端的站点配置，可能随上游变更；当前不自动执行 GrowthBook 远程配置。修改 API 地址后需要验证并重新导入相应授权，不能把 Token 自动转发到未知站点。

同一个来源 ID 对应一个授权文件；保留 ID 可保留节点标签前缀。App Token 与 SFM 订阅 URL 中的设备令牌相互独立。

## 在 macOS 完成首次授权

```bash
./scripts/build-ikuuu-login.sh
./bin/subcompose -config ./config.json -ikuuu-login ikuuu
```

原生 WebKit 窗口打开官网。成功回调后，CLI 验证 Token，绑定固定设备身份，刷新并保存授权。工具不会更改系统 URL scheme 注册，不打印回调内容。关闭窗口会取消登录。

辅助程序默认位于 subcompose 同目录，可以用 `-login-helper` 指定。官网登录页地址可用 `-ikuuu-login-url` 覆盖。服务部署在 Linux VPS 时不需要运行 WebKit；在 Mac 上捕获回调，再通过安全通道交给服务端导入。

## 导入已有回调 / Session

也可以单独捕获回调：

```bash
./bin/ikuuu-login \
  --url 'https://ikuuu.top/auth/login?redirect=%2Fapi%2Fv2%2Fweb-auth%2Fcall-client' \
  --output './state/auth-bootstrap/callback.txt'
./bin/subcompose -config ./config.json \
  -ikuuu-import ikuuu -auth-file ./state/auth-bootstrap/callback.txt
```

文件必须不存在才可被辅助工具创建；导入时要求是权限受限的普通文件。`-auth-file -` 从标准输入读取，适用于 SSH 传输。导入会刷新并轮换凭据，旧回调里的 Token 此后不能重复导入。

```bash
./bin/subcompose -config ./config.json -ikuuu-status ikuuu
./bin/subcompose -config ./config.json -check
```

状态命令只显示来源、到期时间和设备绑定状态，不输出 Token。它反映本地保存的授权信息，不代替一次真实 API 校验。

## 状态和故障恢复

授权记录位于 `snapshot_dir/auth/<source-id>.json`，目录 0700、文件 0600。文件独立于配置快照原子保存；账号操作使用跨进程文件锁。成功刷新后，即使节点解析、规则集处理或配置检查失败，新凭据也不会被旧快照覆盖。

日常请求直接获取节点，在接近过期时刷新 Token。刷新 POST 遇到不确定的网络失败不会盲目重试，因为服务器可能已经轮换凭据。凭据失效时，来源状态会提示重新登录；若有上次成功的节点快照，继续提供旧配置。

备份和迁移时要同时保留授权目录与服务快照。不要把同一账号授权文件复制到两台同时自动刷新的独立服务：文件锁无法跨机器协调 Token 轮换。

## 测试

```bash
nix-shell -p go --run 'go test -race ./... && go vet ./...'
```

测试覆盖回调解析、HTTP 请求格式、Token 轮换后持久化、失败回退、跨进程锁、Clash 节点转换及凭据不出现在错误消息中。QR 会话创建 / 轮询作为独立协议模块保留，网页登录是当前主要授权入口。
