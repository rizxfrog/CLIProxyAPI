#!/usr/bin/env python3
"""
TRAE SOLO CN 每日签到脚本

调用 TRAE SOLO CN（TraeWork 桌面端）的「每日签到领积分」后端接口。

接口（从 TraeWork_CN-Setup-x64.exe 逆向提取，位置为 main.js 字节偏移）:
  - 查询状态:  POST {ug_host}/trae/api/v2/ug/checkin_credits/status   (@1696710)
  - 执行签到:  POST {ug_host}/trae/api/v2/ug/checkin_credits/claim    (@1696742)
  - 积分余额:  POST {ug_host}/trae/api/v2/pay/ide_user_ent_usage      (@1708850)

  请求核心 eb() 位于 @1695333，响应字段 enable / checked_in / credits。
  ug_host 来自 product.json 的 bootConfig.ug.trae.normal = https://api.trae.cn

鉴权（bb() @1694752 + cb() @1695022 + fb() @1696860）:
  - Authorization: Cloud-IDE-JWT <accessToken>
  - x-device-id / x-device-brand / x-device-type: 设备身份头
  - x-os-version / x-app-version: 客户端运行环境头
  - x-rust-request-timeout: Electron TTNet 底层自动添加的超时头

注意：CLIProxyAPI OAuth 会为每次登录生成并保存独立的 device_id/machine_id。
默认应使用凭证文件中与该次 OAuth 登录配套的 ID，不要跨账号混用。只有当 OAuth
登录明确使用了外部 Trae 客户端身份时，才应从 renderer.log 提取 guaranteedDeviceId
并通过 --device-id 覆盖。status 接口较宽松，不能用来证明任意 ID 都可用于 claim。

登录态来源（自动读取，也可手动传入）:
  CLIProxyAPI 凭证目录:  ~/.cli-proxy-api/auths/trae-<uid>.json
  支持两种格式:
    1. 嵌套（CLIProxyAPI Trae 落盘格式）:
       { auth: {accessToken, refreshToken, machineId, deviceId, osVersion},
         account: {uid, nickname} }
    2. 扁平 / CLI 凭证:
       { accessToken, uid, machineId, deviceId, ... } 或
       { access_token, base_url, ... }（uid 从 JWT 的 sub/payload 解出）

  也可用 TRAE_AUTH_FILE 环境变量指定单个文件。

用法:
  uv run trae_checkin.py                                  # 查询状态 + 签到
  uv run trae_checkin.py status                           # 仅查询状态
  uv run trae_checkin.py --token <TOKEN>                  # 手动指定 token
  uv run trae_checkin.py --auth-file <FILE>               # 对单个凭证文件签到
  # 仅当 OAuth 登录使用了外部 Trae 客户端身份时，覆盖凭证中的设备参数：
  uv run trae_checkin.py --auth-file <FILE> \\
    --device-id 4456774404944876 --device-type windows \\
    --os-version "Windows 11 Home" --app-version 0.1.62
  uv run trae_checkin.py --auth-dir ~/.cli-proxy-api/auths          # 批量签到
  uv run trae_checkin.py --auth-dir ~/.cli-proxy-api/auths --prefix trae  # 只处理 trae*.json
  uv run trae_checkin.py --usage                          # 附带查询积分余额
  uv run trae_checkin.py --retry 3 --retry-delay 30       # 遇排队错误自动重试

业务错误码（实测）:
  code 0                      签到成功
  9074 「当前参与用户太多，请稍后再试」
       可能是服务端活动排队，也可能是 OAuth 设备上下文不一致。
       默认应复用该凭证文件保存的 device_id/machine_id，不要跨账号混用。
       status 接口较宽松，不能据此判断 claim 的设备上下文是否有效。
  9090 「活动暂不可用」  activity/action 通道返回，说明该奖励不走此通道。
  1001 / 2001 / 9095     今日已签到，脚本视为成功（幂等）。
                           9095 实测文案：当前设备今日已经签到，请明日再来哦～
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# 尽量零依赖：优先用 requests，否则退回标准库 urllib
try:
    import requests  # type: ignore
except ImportError:
    requests = None

# ---------------------------------------------------------------- 配置
DEFAULT_UG_HOST = "https://api.trae.cn"

EP_STATUS = "/trae/api/v2/ug/checkin_credits/status"
EP_CLAIM = "/trae/api/v2/ug/checkin_credits/claim"
EP_USAGE = "/trae/api/v2/pay/ide_user_ent_usage"

# 业务错误码语义（实测）
#   9074: "当前参与用户太多，请稍后再试"
#         It may indicate activity queueing or an OAuth device-context mismatch.
#         Reuse the identity stored with the credential by default; only
#         override it when the OAuth login used an external Trae client ID.
#   9090: "活动暂不可用"（activity/action 通道返回）
#         该 activity_id 不走通用活动通道，或参数不匹配。
RETRYABLE_CODES = frozenset({9074})
# 「已签到」类：视作成功（幂等）。9095 是当前接口实测返回码。
ALREADY_CODES = frozenset({1001, 2001, 9095})

# CLIProxyAPI 默认 auth 目录
AUTH_REL_PATH = (".cli-proxy-api", "auths")

# 设备身份头默认值。真实客户端取自机器信息，签到接口不强制校验，
# 保持跨次运行稳定即可。
DEFAULT_MACHINE_ID = "0123456789abcdef0123456789abcdef"
DEFAULT_DEVICE_ID = "0123456789abcdef0123456789abcdef"
DEFAULT_DEVICE_BRAND = "83DG"
DEFAULT_DEVICE_TYPE = "windows"
DEFAULT_OS_VERSION = "Windows 11 Home"
DEFAULT_APP_VERSION = "0.1.62"


def _decode_jwt_uid(token: str) -> str | None:
    """从 JWT payload 解出 uid（依次尝试 uid/user_id/sub）。失败返回 None。"""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        pad = "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
        for key in ("uid", "user_id", "userId", "sub"):
            if payload.get(key):
                return str(payload[key])
        return None
    except Exception:
        return None


def _auth_candidates() -> list[Path]:
    """按平台返回可能的 TRAE 凭证文件位置。"""
    env_override = os.environ.get("TRAE_AUTH_FILE")
    if env_override:
        return [Path(env_override)]

    home = Path.home()
    auth_dir = home.joinpath(*AUTH_REL_PATH)
    out: list[Path] = []
    if auth_dir.is_dir():
        out.extend(sorted(auth_dir.glob("trae-*.json")))
        if not out:
            out.extend(sorted(auth_dir.glob("*.json")))
    return out


def load_session(auth_file: Path | None) -> dict:
    """读取登录态，返回含 token/uid/device_* 的 dict。

    支持格式：
      1. 嵌套（CLIProxyAPI Trae）: {auth: {accessToken, ...}, account: {uid, ...}}
      2. 扁平: {accessToken, uid, machineId, deviceId, ...}
      3. CLI 凭证: {access_token, base_url, ...}（uid 从 JWT 解出）
    """
    path = auth_file or next((p for p in _auth_candidates() if p.is_file()), None)
    if path is None:
        raise SystemExit(
            "未找到 TRAE 登录态文件。请先完成 Trae 登录（生成 auths/trae-<uid>.json），"
            "或通过 --auth-file / --token 指定。也可用 TRAE_AUTH_FILE 环境变量指定。"
        )
    data = json.loads(path.read_text(encoding="utf-8"))

    # 格式 3：CLI 凭证（access_token / base_url）
    if "access_token" in data:
        token = data.get("access_token")
        uid = data.get("uid") or _decode_jwt_uid(token or "")
        if not token:
            raise SystemExit(f"凭证文件 {path} 中 access_token 无效。")
        print(f"[i] 登录态来源: {path} (CLI 凭证)")
        return {
            "token": token,
            "uid": str(uid or ""),
            "device_id": data.get("deviceId") or data.get("device_id") or DEFAULT_DEVICE_ID,
            "device_brand": data.get("deviceBrand") or DEFAULT_DEVICE_BRAND,
            "device_type": data.get("deviceType") or DEFAULT_DEVICE_TYPE,
            "os_version": data.get("osVersion") or DEFAULT_OS_VERSION,
            "app_version": data.get("appVersion") or DEFAULT_APP_VERSION,
            "ug_host": (data.get("base_url") or "").rstrip("/") or None,
            "_path": str(path),
        }

    # 格式 1：嵌套（auth / account）
    auth = data.get("auth") if isinstance(data.get("auth"), dict) else None
    account = data.get("account") if isinstance(data.get("account"), dict) else {}
    if auth is not None:
        src = auth
        uid = (account or {}).get("uid") or auth.get("uid")
        kind = "嵌套 (CLIProxyAPI Trae)"
    else:
        # 格式 2：扁平
        src = data
        uid = data.get("uid")
        kind = "扁平"

    token = src.get("accessToken") or src.get("token")
    if not token:
        raise SystemExit(f"凭证文件 {path} 中缺少 accessToken。")
    if not uid:
        uid = _decode_jwt_uid(token)

    print(f"[i] 登录态来源: {path} ({kind})")
    return {
        "token": token,
        "uid": str(uid or ""),
        "device_id": src.get("deviceId") or src.get("device_id") or DEFAULT_DEVICE_ID,
        "device_brand": src.get("deviceBrand") or DEFAULT_DEVICE_BRAND,
        "device_type": src.get("deviceType") or DEFAULT_DEVICE_TYPE,
        "os_version": src.get("osVersion") or DEFAULT_OS_VERSION,
        "app_version": src.get("appVersion") or DEFAULT_APP_VERSION,
        "ug_host": src.get("ugHost") or src.get("apiHost") or None,
        "_path": str(path),
    }


# ---------------------------------------------------------------- HTTP
def _http_json(url: str, headers: dict, body: dict, timeout: int) -> dict:
    if requests is not None:
        r = requests.post(url, headers=headers, json=body, timeout=timeout)
        status = r.status_code
        try:
            payload = r.json()
        except Exception:
            payload = {"raw": r.text}
    else:
        import urllib.error
        import urllib.request

        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={**headers, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            status = e.code
            try:
                payload = json.loads(e.read().decode("utf-8"))
            except Exception:
                payload = {"raw": e.read().decode("utf-8", "replace")}
    return {"status": status, "payload": payload}


def build_headers(session: dict) -> dict:
    """还原 main.js 的 bb() + cb() + fb() 与 TTNet 公共头。"""
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        # cb() → mixAuthorization()
        "Authorization": f"Cloud-IDE-JWT {session['token']}",
        # fb(): 设备身份头
        "x-device-id": str(session.get("device_id") or DEFAULT_DEVICE_ID),
        "x-device-brand": str(session.get("device_brand") or DEFAULT_DEVICE_BRAND),
        "x-device-type": str(session.get("device_type") or DEFAULT_DEVICE_TYPE),
        # Electron TTNet iCubeBaseTTNetService.c() 自动添加
        "x-rust-request-timeout": str(session.get("request_timeout_ms") or 30000),
    }
    if session.get("os_version"):
        headers["x-os-version"] = str(session["os_version"])
    if session.get("app_version"):
        headers["x-app-version"] = str(session["app_version"])
    return headers


# ---------------------------------------------------------------- 业务
def checkin_status(ug_host: str, session: dict, timeout: int) -> dict:
    """POST /trae/api/v2/ug/checkin_credits/status"""
    return _http_json(ug_host.rstrip("/") + EP_STATUS, build_headers(session), {}, timeout)


def claim_checkin(ug_host: str, session: dict, timeout: int) -> dict:
    """POST /trae/api/v2/ug/checkin_credits/claim"""
    return _http_json(ug_host.rstrip("/") + EP_CLAIM, build_headers(session), {}, timeout)


def fetch_usage(ug_host: str, session: dict, timeout: int) -> dict:
    """POST /trae/api/v2/pay/ide_user_ent_usage — 积分余额。

    请求体 {require_usage: true, req_source: 2}（req_source 2 = solo-lite 客户端）。
    """
    return _http_json(
        ug_host.rstrip("/") + EP_USAGE,
        build_headers(session),
        {"require_usage": True, "req_source": 2},
        timeout,
    )


def _pretty(data: dict) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2))


def _biz_code(payload) -> int | None:
    """取出业务错误码，非数字返回 None。"""
    return payload.get("code") if isinstance(payload, dict) and isinstance(payload.get("code"), int) else None


def ccode_msg(code: int | None) -> str:
    """把已知业务错误码翻译成人话；未知码原样返回。"""
    return {
        9074: "服务端活动排队中（当前参与用户太多，请稍后再试）",
        9090: "活动暂不可用（该 activity_id 不走此通道）",
        9095: "当前设备今日已经签到",
        1001: "今日已签到",
        2001: "今日已签到",
    }.get(code, f"业务错误码 {code}")


def _has_today_checkin_pack(payload: dict, uid: str) -> bool:
    """Return whether entitlement usage contains today's Beijing checkin pack."""
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    packs = data.get("user_entitlement_pack_list") if isinstance(data, dict) else None
    if not isinstance(packs, list):
        return False
    day = datetime.now(timezone(timedelta(hours=8))).strftime("%Y%m%d")
    expected = f"checkin_{day}_{uid}" if uid else f"checkin_{day}_"
    for pack in packs:
        if not isinstance(pack, dict):
            continue
        base = pack.get("entitlement_base_info")
        if not isinstance(base, dict):
            continue
        entitlement_id = str(base.get("entitlement_id") or "")
        if entitlement_id == expected or (not uid and entitlement_id.startswith(expected)):
            return True
    return False


def _verify_checkin(ug_host: str, session: dict, timeout: int) -> bool:
    """Verify a claim via refreshed status or today's entitlement pack."""
    status_result = checkin_status(ug_host, session, timeout)
    status_payload = status_result.get("payload") if isinstance(status_result.get("payload"), dict) else {}
    status_data = status_payload.get("data") if isinstance(status_payload.get("data"), dict) else status_payload
    if status_result.get("status") == 200 and status_data.get("checked_in") is True:
        return True

    usage_result = fetch_usage(ug_host, session, timeout)
    usage_payload = usage_result.get("payload") if isinstance(usage_result.get("payload"), dict) else {}
    return usage_result.get("status") == 200 and _has_today_checkin_pack(usage_payload, str(session.get("uid") or ""))


def _run_one(args: argparse.Namespace, session: dict, ug_host: str) -> int:
    """对单个登录态执行 status/checkin。"""
    print(f"[i] ug host: {ug_host}")
    if session.get("uid"):
        print(f"[i] uid: {session['uid']}")

    if args.action == "status":
        r = checkin_status(ug_host, session, args.timeout)
        _pretty(r)
        return 0 if r["status"] == 200 else 1

    # checkin: 先查状态再签到
    print("[i] 查询签到状态...")
    st = checkin_status(ug_host, session, args.timeout)
    payload = st.get("payload") if isinstance(st.get("payload"), dict) else {}
    _pretty(payload)

    if st["status"] != 200:
        print(f"\n[✗] 查询失败，HTTP {st['status']}")
        return 1

    code = _biz_code(payload)
    if code is not None and code != 0:
        print(f"\n[✗] 查询失败，业务错误码 {code}: {payload.get('message', '')}")
        return 1

    # 响应可能是 {code, data:{...}} 或直接 {code, enable, checked_in, credits}
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload

    enable = data.get("enable")
    checked_in = data.get("checked_in")
    # 真实响应还含 did_checked_in（累计是否签到过）与 extra_credits（额外积分）
    did_checked_in = data.get("did_checked_in")
    credits = data.get("credits")
    extra_credits = data.get("extra_credits")

    if not isinstance(enable, bool):
        print("\n[✗] 响应缺少 enable 字段；该账号可能不是 TRAE CN 账号（需 providerCode=cn 且 scope=marscode）")
        return 1

    print(f"[i] 签到功能开启: {enable}")
    if credits is not None:
        print(f"[i] 今日可领积分: {credits}")
    if extra_credits is not None:
        print(f"[i] 额外积分: {extra_credits}")
    if isinstance(did_checked_in, bool):
        print(f"[i] 扩展字段 did_checked_in: {did_checked_in}（原客户端不用于状态判断）")

    if not enable:
        print("\n[i] 该账号未开启签到功能，无需处理。")
        return 0

    # The official Trae client maps only checked_in to its checkedIn state.
    # did_checked_in is an extra server field and is not used by the UI.
    already_checked_in = checked_in is True
    if already_checked_in:
        print("\n[✓] 今日已签到，无需重复。")
        if args.usage:
            _print_usage(ug_host, session, args.timeout)
        return 0

    if args.dry_run:
        print("\n[i] --dry-run：跳过签到。")
        return 0

    print("\n[i] 执行签到...")
    attempts = max(1, getattr(args, "retry", 1))
    delay = max(0, getattr(args, "retry_delay", 5))
    ccode: int | None = None
    cpayload: dict = {}

    for attempt in range(1, attempts + 1):
        cl = claim_checkin(ug_host, session, args.timeout)
        cpayload = cl.get("payload") if isinstance(cl.get("payload"), dict) else {}
        if attempt == 1 or getattr(args, "verbose", False):
            _pretty(cpayload)

        if cl["status"] != 200:
            print(f"\n[✗] 签到失败，HTTP {cl['status']}")
            return 1

        ccode = _biz_code(cpayload)

        if ccode in (None, 0):
            print("\n[i] claim 已受理，正在验证签到状态...")
            if not _verify_checkin(ug_host, session, args.timeout):
                print(
                    "[!] claim 返回 code 0，但 status 和今日签到权益包均未确认到账。\n"
                    "    本次只能判定为请求已受理，不能判定签到成功。"
                )
                return 2
            print("[✓] 签到成功，服务端状态/权益包已确认。")
            granted = cpayload.get("credits")
            if granted is None and isinstance(cpayload.get("data"), dict):
                granted = cpayload["data"].get("credits")
            if granted is not None:
                print(f"[✓] 获得积分: {granted}")
            if args.usage:
                _print_usage(ug_host, session, args.timeout)
            return 0

        if ccode in ALREADY_CODES:
            print(f"\n[✓] 已签到（业务错误码 {ccode}: {cpayload.get('message', '')}）")
            if args.usage:
                _print_usage(ug_host, session, args.timeout)
            return 0

        if ccode in RETRYABLE_CODES and attempt < attempts:
            print(f"[!] 第 {attempt}/{attempts} 次: {ccode_msg(ccode)}；{delay}s 后重试...")
            time.sleep(delay)
            continue

        break

    if ccode in RETRYABLE_CODES:
        print(
            f"\n[!] 签到未成功：{ccode_msg(ccode)}\n"
            "[i] 说明：9074 可能是服务端活动排队，也可能是 OAuth 设备上下文不一致。\n"
            "    默认请使用该凭证文件自身保存的 device_id/machine_id，不要跨账号混用。\n"
            "    只有登录时明确复用了外部 Trae 客户端身份，才使用 --device-id 覆盖。\n"
            "    status 接口较宽松；若配套设备身份下仍返回 9074，再稍后重试。"
        )
        return 2

    print(f"\n[✗] 签到失败，业务错误码 {ccode}: {cpayload.get('message', '')}")
    return 1


def _print_usage(ug_host: str, session: dict, timeout: int) -> None:
    print("\n[i] 查询积分余额...")
    ur = fetch_usage(ug_host, session, timeout)
    upayload = ur.get("payload") if isinstance(ur.get("payload"), dict) else {}
    if ur["status"] == 200 and _biz_code(upayload) in (None, 0):
        data = upayload.get("data") if isinstance(upayload.get("data"), dict) else upayload
        printed = False
        for key in ("total_credits", "used_credits", "remain_credits", "credits"):
            if key in data:
                print(f"[i] {key}: {data[key]}")
                printed = True
        if not printed:
            print(json.dumps(data, ensure_ascii=False)[:400])
    else:
        print(f"[✗] 积分查询失败: HTTP {ur['status']} code={_biz_code(upayload)}")


def _apply_cli_overrides(args: argparse.Namespace, session: dict) -> dict:
    """Apply runtime client identity overrides to any credential source."""
    if args.device_id:
        session["device_id"] = args.device_id
    if args.device_brand:
        session["device_brand"] = args.device_brand
    if args.device_type:
        session["device_type"] = args.device_type
    if args.os_version:
        session["os_version"] = args.os_version
    if args.app_version:
        session["app_version"] = args.app_version
    return session


def _auth_dir_files(auth_dir: Path, prefix: str | None = None) -> list[Path]:
    """返回目录下所有 .json 凭证文件（排序后），可按文件名前缀过滤。"""
    if not auth_dir.is_dir():
        raise SystemExit(f"--auth-dir 指定的目录不存在或不是目录: {auth_dir}")
    files = sorted(auth_dir.glob("*.json"))
    if prefix:
        files = [f for f in files if f.name.startswith(prefix)]
    if not files:
        suffix = f"（前缀 {prefix!r}）" if prefix else ""
        raise SystemExit(f"--auth-dir 指定的目录下没有匹配的 .json 文件{suffix}: {auth_dir}")
    return files


def main() -> int:
    ap = argparse.ArgumentParser(description="TRAE SOLO CN 每日签到")
    ap.add_argument("action", nargs="?", default="checkin", choices=["status", "checkin"])
    ap.add_argument("--ug-host", default=os.environ.get("TRAE_UG_HOST", DEFAULT_UG_HOST))
    ap.add_argument("--auth-file", type=Path, default=None, help="手动指定凭证文件路径")
    ap.add_argument(
        "--auth-dir",
        type=Path,
        default=None,
        help="指定 auth 目录，对其下所有 .json 文件依次执行签到",
    )
    ap.add_argument(
        "--prefix",
        default=None,
        help="配合 --auth-dir 使用，只处理文件名以该前缀开头的 .json 文件",
    )
    ap.add_argument("--token", default=None, help="手动指定 accessToken（Cloud-IDE-JWT）")
    ap.add_argument("--uid", default=None)
    ap.add_argument("--device-id", default=None)
    ap.add_argument("--device-brand", default=None, help="x-device-brand")
    ap.add_argument("--device-type", default=None, help="x-device-type，例如 windows")
    ap.add_argument("--os-version", default=None, help="x-os-version，例如 Windows 11 Home")
    ap.add_argument("--app-version", default=None, help="x-app-version，例如 0.1.62")
    ap.add_argument("--usage", action="store_true", help="附带查询积分余额")
    ap.add_argument("--dry-run", action="store_true", help="只查询状态，不执行签到")
    ap.add_argument(
        "--retry",
        type=int,
        default=1,
        help="遇到可重试错误（如 9074 排队）时的尝试次数（默认 1，即不重试）",
    )
    ap.add_argument("--retry-delay", type=int, default=5, help="重试间隔秒数（默认 5）")
    ap.add_argument("--verbose", action="store_true", help="打印每次重试的原始响应")
    ap.add_argument("--timeout", type=int, default=15)
    args = ap.parse_args()

    if args.prefix and not args.auth_dir:
        raise SystemExit("--prefix 需要配合 --auth-dir 使用")

    ug_host = args.ug_host.rstrip("/")

    # 手动 token 模式
    if args.token:
        session = {
            "token": args.token,
            "uid": args.uid or _decode_jwt_uid(args.token) or "",
            "device_id": args.device_id or DEFAULT_DEVICE_ID,
            "device_brand": args.device_brand or DEFAULT_DEVICE_BRAND,
            "device_type": args.device_type or DEFAULT_DEVICE_TYPE,
            "os_version": args.os_version or DEFAULT_OS_VERSION,
            "app_version": args.app_version or DEFAULT_APP_VERSION,
        }
        return _run_one(args, session, ug_host)

    # 批量目录模式
    if args.auth_dir:
        failures = 0
        for path in _auth_dir_files(args.auth_dir, args.prefix):
            print("\n" + "=" * 60)
            print(f"[i] 处理凭证文件: {path}")
            print("=" * 60)
            try:
                session = load_session(path)
            except SystemExit as e:
                print(f"[✗] 跳过 {path}: {e}")
                failures += 1
                continue
            _apply_cli_overrides(args, session)
            host = ug_host
            # 凭证文件里若带 ug_host/apiHost，优先使用（未显式传 --ug-host 时）
            if session.get("ug_host") and args.ug_host == DEFAULT_UG_HOST:
                host = str(session["ug_host"]).rstrip("/")
            failures += _run_one(args, session, host)
        return failures

    session = load_session(args.auth_file)
    _apply_cli_overrides(args, session)
    if session.get("ug_host") and args.ug_host == DEFAULT_UG_HOST:
        ug_host = str(session["ug_host"]).rstrip("/")
    return _run_one(args, session, ug_host)


if __name__ == "__main__":
    raise SystemExit(main())
