# WorkBuddy 每日签到插件（workbuddy-checkin）

一个标准 C-ABI 动态库插件，自动在每日 **00:10 ~ 03:10** 的时间窗口内，对
`data/auth_files/` 下所有 **codebuddy-cn** 登录凭证文件执行 WorkBuddy「每日签到」，
并让每个凭证随机延时最多 **180 分钟**，避免所有账号在同一时刻集中签到。

## 原理

- 插件在 `plugin.register` / `plugin.reconfigure` 时读取配置，若 `enabled: true`
  则启动一个后台调度 goroutine。
- 调度器在每日窗口开始时一次性读取匹配凭证，并为每个账号独立随机分配窗口内的一个时间点；
  一个账号的 HTTP 请求耗时不会把其他账号顺延到窗口外。
- 签到过程通过宿主回调完成，不依赖外部网络库：
  - `host.auth.list` / `host.auth.get`：读取物理凭证 JSON（含 `access_token` / `base_url`）。
  - `host.http.do`：由宿主代为发起签到 HTTP 请求（自动走代理与请求日志）。
  - `host.log`：把每次签到结果写入宿主日志。
- 利用凭证 `access_token`（JWT）的 `sub` 字段作为 `X-User-Id`。
- 每个凭证先查询 `checkin-activity-status`，已签到则跳过；否则调用 `daily-checkin`。

## 接口（与 docs/scripts/workbuddy_checkin.py 一致）

```
查询状态: POST {endpoint}/v2/billing/meter/checkin-activity-status
执行签到: POST {endpoint}/v2/billing/meter/daily-checkin
```

鉴权头：`Authorization: Bearer <access_token>`、`X-User-Id: <uid>`，
以及按需的 `X-Enterprise-Id` / `X-Tenant-Id` / `X-Domain`。

## 配置项（config.yaml → plugins.configs.workbuddy-checkin）

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `window_start_min` | int | `10` | 签到窗口起点（当天分钟数，00:10）。 |
| `window_end_min` | int | `190` | 签到窗口终点（当天分钟数，03:10）。 |
| `max_jitter_min` | int | `180` | 兼容旧配置，当前版本由完整签到窗口为每个账号分配随机时间，此字段不再控制账号间串行等待。 |
| `endpoint` | string | `https://copilot.tencent.com` | 签到基地址；凭证 `base_url` 可覆盖。 |
| `prefix` | string | `codebuddy-cn` | 仅处理文件名以此前缀开头的 `.json` 凭证。 |
| `user_agent` | string | `WorkBuddy/5.3.14` | 请求 User-Agent。 |
| `run_immediately` | bool | `false` | 启用后插件加载即立刻触发一次（绕过时间窗）。 |

## 手动触发 / 状态查看

插件声明了 Management API，在管理界面暴露菜单资源 **「WorkBuddy 签到」**：

- `?action=run`：立即在后台触发一次全量签到（手动触发不等待每日随机窗口）。
- `?action=config`：查看当前配置。
- 不带参数：查看下次运行时间、窗口、next_run_at 等调度状态。

## 构建

```bash
cd data/plugins/workbuddy-checkin/go
go build -buildmode=c-shared -o ../workbuddy-checkin.so .
rm -f ../workbuddy-checkin.h
```

产物 `workbuddy-checkin.so` 复制到 `data/plugins/`（与 `config.yaml` 中 `plugins.dir` 对应）
后会被宿主自动发现并加载。
