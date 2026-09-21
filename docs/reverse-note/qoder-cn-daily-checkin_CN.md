# Qoder CN 每日 Credits 领取接口：逆向过程与复用指南

## 1. 目的与结果

从桌面客户端「每天领 100 Credits」弹窗出发，定位活动查询、领取接口与鉴权方式，并形成可复用脚本。

已确认的调用链：

```text
Qoder CN desktop 0.2.5
  → 主进程 Campaign service
  → GET https://openapi.qoder.com.cn/sash/api/v1/me/campaigns
  → campaignUrl 指向远程活动页
  → 页面 JS 的领取按钮
  → POST /sash/api/v1/me/campaigns/{campaignId}/claim
  → 查询活动状态和 usage 验证结果
```

本次此前的实测已提交一次真实领取：活动从 `CLAIMABLE` 变为 `CLAIMED`，用量接口新增 `addOnQuota.total=100, used=0, remaining=100`，`isQuotaExceeded` 从 `true` 变为 `false`。本次归档没有再次提交领取。

脚本：[`../scripts/qoder_cn_checkin.py`](../scripts/qoder_cn_checkin.py)。命令形式与 WorkBuddy 脚本一致：默认 `checkin` 会提交领取，`status` 只查询。

## 2. 输入、环境与证据位置

| 项目 | 位置/版本 |
|---|---|
| 原始安装包 | `/run/media/van/Alaska1/a/QoderCN/qoder-desktop-deb/Qoder-CN-linux-amd64.deb` |
| 逆向产物根目录 | `/run/media/van/Alaska1/a/QoderCN/rev/` |
| deb 解包 | `rev/deb/opt/Qoder CN/` |
| ASAR | `rev/deb/opt/Qoder CN/resources/app.asar` |
| 主进程 bundle | `rev/app/out/main/index.js` |
| 渲染进程 bundle | `rev/app/out/renderer/assets/index-BPZZyWKH.js` |
| 桌面 package 版本 | `0.2.5`，来源 `rev/app/package.json` |
| 下载的活动页代码 | `rev/growth-page/activity-iframe.js`、`.css` |
| 活动页 CDN 版本 | `0.0.704`（不是桌面客户端版本） |

外置盘路径属于本机环境，不是脚本运行依赖。无需安装或启动桌面应用即可运行签到脚本。凭证由用户通过 `--auth` 提供，文档和脚本均不嵌入真实 token、账户信息或机器指纹。

## 3. 可复现的静态分析过程

### 3.1 解包前先检查已有产物

本次曾重复解包，之后确认新旧主进程文件一致，删除了新增重复目录。后续 Agent 应先检查 `rev/deb/` 和 `rev/app/`，避免重复生成数百 MB 数据。

全新分析时可运行：

```bash
ROOT=/run/media/van/Alaska1/a/QoderCN
mkdir -p "$ROOT/rev/deb" "$ROOT/rev/app"
sha256sum "$ROOT/qoder-desktop-deb/Qoder-CN-linux-amd64.deb"
dpkg-deb -x "$ROOT/qoder-desktop-deb/Qoder-CN-linux-amd64.deb" "$ROOT/rev/deb"
node docs/reverse-toolkit/extract-asar.mjs \
  "$ROOT/rev/deb/opt/Qoder CN/resources/app.asar" "$ROOT/rev/app"
```

解包工具对 `app.asar.unpacked` 的处理可能不同；本任务只需要已打包的主进程/渲染进程 JS。不要通过管道最后一个命令的退出码判断解包成功，必须核对目标文件。

### 3.2 从 UI 文案定位业务，不要把所有 checkin 命中都当签到

截图中的关键文案：

- 每天领 100 Credits
- 每日 10:00（UTC+8）刷新，领取后 30 天有效
- 领取

初始搜索 `checkin` 命中很多第三方库、语法高亮和运行时的 `checking`。有效线索来自渲染进程的 `ariaLabelCampaignClaimable`，随后沿 `campaign` 搜索主进程，找到：

```js
const fbt = "/sash/api/v1/me/campaigns";
const Bbt = "client_launch_26";
const rl = Object.freeze({ clientType: 10, businessProduct: "app", sessionType: "app" });
```

`client_launch_26` 用于 **limited-number** 编号查询，不是每日 Credits 活动的固定 ID。不能拿它代替每日响应中的 `campaignId`。

推荐搜索方式：先 `rg -l -F` 定位文件，再用 Python/Node 的 `indexOf`/`find` 输出有界上下文。不要对十几 MB 单行压缩 bundle 使用 `grep -E '.{0,2000}keyword.{0,2000}'`，可能极慢且输出失控。也不要把整条压缩行直接输出。

```bash
rg -l -F 'ariaLabelCampaignClaimable' "$ROOT/rev/app/out"
rg -l -F '/sash/api/v1/me/campaigns' "$ROOT/rev/app/out"
```

### 3.3 主进程：活动发现与 webview 鉴权

主进程压缩名称在当前版本中为 `B4`（Campaign service）、`cbt`（native campaign request service）、`gbt`（headers helper）。名称会随构建变化，应依赖字符串和行为定位，而非固定符号名。

关键行为：

1. `getStatus()` 从 auth service 获取 access token。
2. `Mbt()` 返回环境覆盖 `QODER_OPENAPI_BASE_URL` 或产品配置 `openApiBaseUrl`；CN 生产配置为 `https://openapi.qoder.com.cn`。
3. GET `/sash/api/v1/me/campaigns`，读取 `showCampaign`、`claimable`、`campaignUrl`。
4. `openSurface()` 打开活动页，并注册该 webContents 的允许 origin。
5. native 请求拦截器给该活动页发起的、符合 origin/resourceType 条件的请求注入认证头。

`gbt()` 删除页面自带的 Authorization 与 Cosy-*，再写入：

```text
Authorization: Bearer <access token>
Cosy-ClientType: 10
Cosy-Version: <clientVersion>
Cosy-MachineOS: <if available>
Cosy-MachineHostname: <if available>
Cosy-MachineId: <if available>
Cosy-MachineToken: <if available>
Cosy-MachineCode: <if available>
Cosy-MachineType: <if available>
```

注意：`Cosy-Business-Product: app` 是本次成功请求中额外携带的头，**不是上述 gbt() 注入清单的一部分**。当前脚本保留已测成功的头组合；不要将其表述为逐字节复刻客户端。

### 3.4 领取实现不在 deb 中，而在远程页面

真实活动查询响应包含：

```json
{
  "showCampaign": true,
  "claimable": true,
  "campaignUrl": "https://openapi.qoder.com.cn/growth-page/activity-iframe"
}
```

获取该 HTML 后找到：

```text
https://g.alicdn.com/qbase/qoder/0.0.704/growth-page/activity-iframe/activity-iframe.js
https://g.alicdn.com/qbase/qoder/0.0.704/growth-page/activity-iframe/activity-iframe.css
```

只向 OpenAPI 发凭证，不要把 Authorization 带到 CDN 下载请求。未来 CDN 版本可能变化，应从最新 HTML 重新发现脚本 URL。

活动页的关键还原片段：

```js
const xe = "/sash/api/v1/me/campaigns";
qe(clientType, `${xe}/${encodeURIComponent(campaignId)}/claim`, {
  method: "POST",
  keepalive: true
});

// Direct fetch transport:
fetch(path, { ...init, credentials: "omit" });

// UI accepts either a direct result or a data envelope:
const result = response.data ?? response;
if (result.status !== "CLAIMED") throw new Error("unexpected claim result");
```

这是 **无 body 的 POST**。原先验证脚本发送 `{}` 也成功，但不是页面的原始请求形态。项目归档脚本改为无 body POST。

页面还会对 `VIEW_DETAILS` 条目调用同一个接口来标记状态。签到脚本只处理 `CLAIM_BENEFIT`，不自动标记广告/详情活动。

## 4. API 规格

### 查询

```http
GET /sash/api/v1/me/campaigns HTTP/1.1
Host: openapi.qoder.com.cn
Authorization: Bearer <access_token>
Cosy-ClientType: 10
Cosy-Business-Product: app
Cosy-Version: 0.2.5
Accept: application/json
```

`machine_id` 存在时脚本还带 `Cosy-MachineId`。已在不携带 MachineToken/Code/Type 的组合下查询、领取成功，因此这些机器指纹头在本次环境并非必要条件。

活动字段示例（省略身份信息及展示文案）：

```json
{
  "campaigns": [{
    "campaignId": "<server-generated UUID>",
    "campaignKey": "<activity key>",
    "actionType": "CLAIM_BENEFIT",
    "claimStatus": "CLAIMABLE",
    "startAt": 1789783200,
    "endAt": 1789869540,
    "benefit": {
      "kind": "CREDITS",
      "amount": 100,
      "modelScope": { "modelSeries": { "key": "ALL_MODELS" } },
      "validity": { "mode": "RELATIVE_DAYS", "days": 30 }
    }
  }]
}
```

每次运行重新查询列表，使用 `campaignId`（不是 `campaignKey`）。不要固定活动 UUID、日期或金额。当前脚本会领取**所有**可领取的 `CLAIM_BENEFIT` 条目，不限于 100 Credits 活动。

### 领取

```http
POST /sash/api/v1/me/campaigns/{URL-encoded campaignId}/claim HTTP/1.1
Host: openapi.qoder.com.cn
Authorization: Bearer <access_token>
Cosy-ClientType: 10
```

沿用查询请求头，body 为空。客户端成功判定：HTTP 成功且 JSON 的 `status` 或 `data.status` 等于 `CLAIMED`。

### 复查到账

```http
GET https://openapi.qoder.com.cn/sash/api/v2/me/usage
```

检查 `qoderUsage.addOnQuota`；本次记录为 total 100、used 0、remaining 100。`credits-summary` 和 `credits-heatmap` 属用量统计，不能用其仍然为 0 来判断奖励没到账。

## 5. 证据边界与之前结论的纠正

| 结论 | 证据状态 |
|---|---|
| Bearer token + 当前请求头组合可查询并领取 | 实测成功 |
| 不需要 CLI 的 WASM 请求签名 | 本次请求未使用 WASM 且成功 |
| 无效 token 被拒 | 观察到 401 `TOKEN_INVALID` |
| 随机不存在的活动 ID | 观察到 404 `CAMPAIGN_NOT_FOUND` |
| 领取后状态和余额更新 | 实测 `CLAIMED`、新增 100 add-on credits |
| ClientType 10 可用 | 源码与实测均支持 |
| ClientType 5 一定被拒绝 | **未验证，之前的断言不成立** |
| 所列请求头每一个都必需 | **未逐项删减验证** |
| 重复 POST 绝对幂等、不重复发放 | **没有对同一真实活动重复 POST，不作此保证** |
| 脚本重复运行会跳过已领取活动 | 查询状态后本地过滤；已测状态，不等于服务端幂等证明 |
| 所有旧 `/api/v2/*` 都不可达 | 不成立；先前已观察到其中部分用户/配额接口返回 200 |
| 免费账号领不到模型列表是套餐门控 | 未证明；不能由 401/503 推断 |

日期注意：旧会话中服务端时间、活动日期和本地归档日期存在差异。这里保留接口观察值，不把本机日期当作服务端日期；自动化应依据服务端状态。

## 6. 脚本使用与行为

Python 3，仅使用标准库（urllib、json、argparse），无需 pip 安装依赖。凭证结构：

```json
{ "access_token": "<secret>", "machine_id": "<optional>" }
```

```bash
# Query only; no mutation.
python3 docs/scripts/qoder_cn_checkin.py status --auth-file /absolute/path/to/credential.json

# Default action: query and claim.
python3 docs/scripts/qoder_cn_checkin.py --auth-file /absolute/path/to/credential.json

# Batch claims, sequentially; use a prefix in mixed-provider directories.
python3 docs/scripts/qoder_cn_checkin.py --auth-dir data/auth_files --prefix qoder-cn-

# Batch status, machine-readable output.
python3 docs/scripts/qoder_cn_checkin.py status --auth-dir data/auth_files --prefix qoder-cn- --json

# Manual token (prefer files to avoid shell history exposure).
python3 docs/scripts/qoder_cn_checkin.py status --token "$TOKEN" --machine-id "$MACHINE_ID"

# Offline regression tests.
python3 -m unittest discover -s docs/scripts -p 'test_qoder_cn_checkin.py'
```

- **默认行为已调整为签到**，只查询必须指定 `status`。`--auth` 是 `--auth-file` 的兼容别名，`--claim` 保留为旧版签到别名，但不能与 `status` 同用。
- `--auth-file`、`--auth-dir`、`--token` 互斥；未指定时读取 `QODER_CN_AUTH_FILE` 环境变量。不猜测桌面端加密凭证路径。
- `--auth-dir` 非递归扫描排序后的 `.json` 文件，`--prefix` 按文件名前缀筛选。单文件错误不阻断其他文件；有任意失败整体返回 1。显式标记为其他 provider 的凭证不会发送到 Qoder。
- JSON 输出为 `accounts` 数组和 `summary`（total/succeeded/failed）。status 查询成功或无可领取活动也计为 succeeded，不表示本次实际领取成功。
- 不照搬 WorkBuddy 专用的 `uid`、企业头、staging 或任意 endpoint，也不新增请求超时（遵循项目网络超时约束）。
- 固定 CN OpenAPI host，不使用凭证文件里的模型 `base_url`，不提供任意 host 覆盖以避免误发 token。
- 拒绝 HTTP 重定向；不输出 token、原始响应 body 或原始网络异常。
- 不自动刷新 token、不重试 POST、不安装定时任务；401 后应通过现有登录/刷新机制更新凭证。
- 查询返回格式异常会报错，而不是静默当作“没有活动”。
- 同一返回列表内按 ID 去重；HTTP 失败或领取响应不符合预期，退出码为 1；无可领取活动时退出码为 0。
- JSON 输出中的 campaigns 是**提交前快照**，claimed 数组是提交结果；需要最新状态请重新只读查询。
- 网络断开时请求可能已在服务端执行。先重新查询状态，不要盲目重发。
- 活动文案规定每天 10:00（UTC+8）刷新、领取后 30 天有效。若自行定时执行，应明确机器时区，避免把本地 10:00 当作北京时间。

## 7. 后续 Agent 排障顺序

1. 运行只读查询，确认凭证和活动状态。
2. 查询失败时记录 HTTP 状态，不输出原始身份/凭证数据。
3. 若接口/格式变化，重新检查桌面主进程中 `/sash/api/v1/me/campaigns`。
4. 从响应 `campaignUrl` 获取当前活动 HTML，再定位新 CDN JS；不要长期固定 `0.0.704`。
5. 对照领取按钮调用、native 请求注入逻辑，确认方法、ID 来源、头、body 和响应判定。
6. 将静态推断、只读验证和真实状态变更分别记录。分析接口不等于获准自动领取；真正提交前确认任务范围。
7. 将新证据与脚本测试一起更新，避免把猜测写成确定事实。

本笔记只涉及 Credits 领取，不证明 Qoder CN 模型推理链路、模型列表签名或 provider endpoint 已经正确。
