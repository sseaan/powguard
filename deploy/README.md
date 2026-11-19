# powguard 生产部署（Rocky Linux 10 · systemd + Caddy）

面向单实例部署：一个静态二进制 + SQLite 文件 + systemd + 反向代理。
无 Docker / Node / Redis。目标机器示例：Aliyun 深圳，`cap.example.com`。

> 单实例语义（PLAN.md §6.1）：challenge 与通行 token 保存在进程内存，
> **重启会让未完成的挑战失效**（访客重解一次即可）。不要同时运行两个实例共用同一数据库。

---

## 0. 前置检查

```bash
uname -m                 # 期望 x86_64
cat /etc/os-release      # Rocky Linux 10
sudo dnf install -y caddy sqlite curl openssl  # Caddy 亦可由官方仓库安装
```

## 1. 构建产物（本地或 CI）

```bash
make linux               # dist/powguard-linux-amd64 + sha256
make test race           # 发布门槛：单测 + 数据竞争
```

产物为 `CGO_ENABLED=0` 静态二进制，可直接拷贝到服务器。

## 2. 创建用户与目录

```bash
sudo useradd --system --home-dir /var/lib/powguard --shell /sbin/nologin powguard
sudo install -d -o powguard -g powguard -m 0700 /var/lib/powguard
sudo install -d -o root  -g powguard -m 0750 /etc/powguard
sudo install -m 0755 dist/powguard-linux-amd64 /usr/local/bin/powguard
sudo install -m 0755 dist/capsolve-linux-amd64 /usr/local/bin/capsolve   # 可选：验收工具
```

## 3. 生成密钥并写配置

```bash
# master key：加密站点 secret 与 format-2 签名密钥。丢失 = 密文永久不可恢复
openssl rand -hex 32

# admin key：管理面板登录
openssl rand -base64 24
```

```bash
sudo install -m 0600 -o root -g root deploy/powguard.env.example /etc/powguard/powguard.env
sudoedit /etc/powguard/powguard.env     # 填入上面两个密钥，设置 POWGUARD_PUBLIC_URL
```

关键项：

| 变量 | 说明 |
|---|---|
| `POWGUARD_ADDR` | 必须 `127.0.0.1:3000`（只监听回环） |
| `POWGUARD_PUBLIC_URL` | `https://cap.example.com` → 管理 cookie 自动 Secure |
| `POWGUARD_TRUST_PROXY` | `127.0.0.1/8,::1/128` → 才读取 `X-Forwarded-For` |
| `POWGUARD_MASTER_KEY` | 32 字节；**独立备份** |
| `POWGUARD_ADMIN_KEY` | 高熵随机值；登录管理面板 |

> 直连部署（无反向代理）时把 `POWGUARD_TRUST_PROXY` 留空，否则攻击者可伪造 IP 绕过限流。

## 4. systemd

```bash
sudo install -m 0644 deploy/powguard.service /etc/systemd/system/powguard.service
sudo systemctl daemon-reload
sudo systemctl enable --now powguard
sudo systemctl status powguard --no-pager
curl -fsS http://127.0.0.1:3000/healthz    # {"status":"ok"}
```

首次启动若库中无站点，会用 `POWGUARD_SITE_SLUG` / `POWGUARD_SITE_SECRET` 引导首个站点
（未设置密钥则生成临时值并打 WARN —— **生产务必先创建站点再用管理面板确认**）。

## 5. Caddy 反向代理

```bash
sudo install -m 0644 deploy/Caddyfile /etc/caddy/Caddyfile   # 先改域名
sudo systemctl reload caddy
curl -I https://cap.example.com/healthz
```

要点（已在示例中处理）：

- `X-Forwarded-For` 由 Caddy 重写，客户端伪造值被丢弃；
- `/admin/api/events/stream` 关闭缓冲（`flush_interval -1`），否则 SSE 不实时；
- 仅 443 对外，应用端口不暴露。

防火墙 / 安全组：

```bash
sudo firewall-cmd --permanent --add-service=http --add-service=https
sudo firewall-cmd --reload
# Aliyun 安全组：只放行 80/443
```

## 6. 验收（M5 出口条件）

### 6.1 公开 API 冒烟（无需浏览器）

```bash
# 从管理面板取得站点 secret 后：
capsolve -endpoint https://cap.example.com/twikoo/ -secret '<site secret>'
# 期望输出：OK: challenge → solve → redeem → siteverify → replay-rejected
```

### 6.2 浏览器验证

打开 `https://cap.example.com/`（演示页），点击控件 →
应显示「验证成功」并给出 `twikoo:<id>:<secret>` 形式的 token。
同源加载 `/static/vendor/cap_wasm_bg.wasm`（Network 面板确认无 jsDelivr 请求）。

### 6.3 Twikoo 2.0.17 外接模式

Twikoo 管理面板 → 配置：

```text
CAPTCHA_PROVIDER  = Cap
CAP_API_ENDPOINT  = https://cap.example.com/twikoo/
CAP_SECRET_KEY    = <管理面板「密钥」页获取>
```

在**无痕窗口**提交一条评论，验证：

| 检查 | 期望 |
|---|---|
| 正常填写并完成验证 | 评论成功发布 |
| 不完成验证直接提交 | 被 Twikoo 拒绝（提示验证码错误） |
| 重放同一 token（DevTools 重发） | `404 {"success":false,"error":"Token not found"}` |
| 错误 secret 调 siteverify | `403 Invalid site key or secret` |
| 站点 A 的 token 提交到站点 B | `404 Invalid site key or secret` |

### 6.4 管理面板

`https://cap.example.com/admin` →
登录 → 概览有数据 → 站点列表 → 集成页片段可直接复制 →
密钥页 reveal（需再次输入 admin key）→ 事件页「实时推送」出现 `已连接`。

## 7. 备份与恢复

**数据库与 master key 必须成对备份**（分开存放，同时丢失任一份都可能不可恢复）。

```bash
# 每日备份（可加 systemd timer / cron）
sudo BACKUP_DIR=/var/backups/powguard /path/to/deploy/backup.sh
# 备份里含 sha256 校验；KEEP_DAYS=14 默认保留两周
```

恢复演练（建议上线前在测试机完整走一遍）：

```bash
sudo MASTER_KEY='<master key>' ./deploy/restore.sh /var/backups/powguard/powguard-YYYYmmdd-HHMMSS.sqlite3
```

脚本会：停服 → 校验 sha256 → 现有库改名 `.pre-restore` → 清理 `-wal/-shm` →
放置备份 → `powguard verify-keys` 校验密文可解 → 启动 → `/healthz` 检查。

手工等价命令：

```bash
systemctl stop powguard
cp /var/lib/powguard/powguard.sqlite3 /var/lib/powguard/powguard.sqlite3.bak
rm -f /var/lib/powguard/powguard.sqlite3-wal /var/lib/powguard/powguard.sqlite3-shm
install -m 0600 -o powguard -g powguard <备份文件> /var/lib/powguard/powguard.sqlite3
powguard verify-keys --db /var/lib/powguard/powguard.sqlite3 --master-key "$POWGUARD_MASTER_KEY"
systemctl start powguard
```

## 8. 升级与回滚

```bash
# 1) 构建新版本并保留旧二进制
sudo cp /usr/local/bin/powguard /usr/local/bin/powguard.prev
sudo install -m 0755 dist/powguard-linux-amd64 /usr/local/bin/powguard

# 2) 先备份（升级可能包含 schema 迁移）
sudo BACKUP_DIR=/var/backups/powguard ./deploy/backup.sh

# 3) 停服 → 启动（迁移在启动时自动执行，幂等）
sudo systemctl stop powguard && sudo systemctl start powguard
sudo systemctl status powguard --no-pager
curl -fsS http://127.0.0.1:3000/healthz

# 4) 回滚：恢复旧二进制 + 旧备份
sudo systemctl stop powguard
sudo cp /usr/local/bin/powguard.prev /usr/local/bin/powguard
sudo MASTER_KEY="$POWGUARD_MASTER_KEY" ./deploy/restore.sh /var/backups/powguard/<升级前备份>
```

> 迁移只增不减（当前为 `0001`、`0002`）；回滚到旧二进制时若库已被新版本迁移，
> 必须同时恢复对应备份，不能只回滚二进制。

## 8.1 从旧名字（capgo）迁移的注意事项

本项目原名 `capgo`，更名为 `powguard`。由于加密 AAD 前缀也随之改为
`powguard:secret`，**旧库中的密文无法再用新版本解密**。若你在此之前已有
开发环境的数据库，请二选一：

- 旧库无重要数据：删掉 `capgo.sqlite3` 重新 bootstrap；
- 需要保留站点：先备份，用旧版本二进制的 `reveal` 导出各站点 secret，
  再用新版本重建站点并重新填入 secret（事件历史如需保留，可另存旧库备查）。

部署检查：

```bash
/usr/local/bin/powguard verify-keys --db /var/lib/powguard/powguard.sqlite3 \
  --master-key "$POWGUARD_MASTER_KEY"
```

## 9. master key 轮换

```bash
sudo systemctl stop powguard
NEW=$(openssl rand -hex 32)
sudo /usr/local/bin/powguard keyrotate \
  --db /var/lib/powguard/powguard.sqlite3 \
  --old-key "$POWGUARD_MASTER_KEY" --new-key "$NEW"
# 更新 /etc/powguard/powguard.env 中的 POWGUARD_MASTER_KEY=$NEW，然后：
sudo systemctl start powguard
sudo /usr/local/bin/powguard verify-keys --db /var/lib/powguard/powguard.sqlite3 --master-key "$NEW"
```

轮换在单事务内完成，任一条失败整体回滚（不会半新半旧）。轮换后**立即重新备份**。

## 10. 日常运维

```bash
# 日志（JSON 行）
journalctl -u powguard -f --output cat | jq -c 'select(.msg=="http" or .level=="ERROR")'

# 审计事件（管理面板或 API）
curl -s -b cookie 'https://cap.example.com/admin/api/events?limit=50' | jq

# 站点密钥校验（换机/恢复后必做）
powguard verify-keys --db /var/lib/powguard/powguard.sqlite3 --master-key "$POWGUARD_MASTER_KEY"
```

### 排障对照

| 现象 | 原因 | 处理 |
|---|---|---|
| 启动即退出，日志 `库中已有加密密钥但未提供 POWGUARD_MASTER_KEY` | 缺 key | 从备份恢复 `POWGUARD_MASTER_KEY` |
| 管理面板 reveal 报 `master key 不匹配` | key 与库不配套 | 用正确的 key 重启或恢复备份 |
| 所有访客共用一个限流桶 | 未设 `POWGUARD_TRUST_PROXY` | 配置可信反代网段并重启 |
| 事件页一直「连接中断」 | 反代缓冲 SSE | Caddy 加 `flush_interval -1` |
| 大陆访问 widget 卡住 | 走了 jsDelivr | 集成页使用同源 `CAP_WASM_URL` 片段 |
| cookie 无法保存 | HTTPS 但 `POWGUARD_PUBLIC_URL` 为 http | 改成 `https://…` |

## 11. 发布门槛（PLAN.md §9）

升级前必须全部通过，否则不得发布：

```bash
make check          # fmt + vet + go test -race
make oracle         # 官方包双向互操作（需 node + tools/oracle）
# 浏览器：widget 0.1.63 在 format-1 / format-2 站点各完成一次验证
# Twikoo：2.0.17 无痕窗口真实评论提交
```
