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
  uv run trae_checkin.py --auth-dir ~/.cli-proxy-api/auths          # 批量签到
  uv run trae_checkin.py --auth-dir ~/.cli-proxy-api/auths --prefix trae  # 只处理 trae*.json
  uv run trae_checkin.py --usage                          # 附带查询积分余额
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
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

# CLIProxyAPI 默认 auth 目录
AUTH_REL_PATH = (".cli-proxy-api", "auths")

# 设备身份头默认值。真实客户端取自机器信息，签到接口不强制校验，
# 保持跨次运行稳定即可。
DEFAULT_MACHINE_ID = "0123456789abcdef0123456789abcdef"
DEFAULT_DEVICE_ID = "0123456789abcdef0123456789abcdef"
DEFAULT_DEVICE_BRAND = "83DG"
DEFAULT_DEVICE_TYPE = "Windows 11 Pro"


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
            "device_type": data.get("osVersion") or DEFAULT_DEVICE_TYPE,
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
        "device_type": src.get("osVersion") or DEFAULT_DEVICE_TYPE,
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
    """还原 main.js 的 bb() + cb() + fb()。"""
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
        # cb() → mixAuthorization()
        "Authorization": f"Cloud-IDE-JWT {session['token']}",
        # fb(): 设备身份头
        "x-device-id": str(session.get("device_id") or DEFAULT_DEVICE_ID),
        "x-device-brand": str(session.get("device_brand") or DEFAULT_DEVICE_BRAND),
        "x-device-type": str(session.get("device_type") or DEFAULT_DEVICE_TYPE),
    }


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
    credits = data.get("credits")

    if not isinstance(enable, bool):
        print("\n[✗] 响应缺少 enable 字段；该账号可能不是 TRAE CN 账号（需 providerCode=cn 且 scope=marscode）")
        return 1

    print(f"[i] 签到功能开启: {enable}")
    if credits is not None:
        print(f"[i] 今日积分: {credits}")

    if not enable:
        print("\n[i] 该账号未开启签到功能，无需处理。")
        return 0

    if checked_in:
        print("\n[✓] 今日已签到，无需重复。")
        if args.usage:
            _print_usage(ug_host, session, args.timeout)
        return 0

    if args.dry_run:
        print("\n[i] --dry-run：跳过签到。")
        return 0

    print("\n[i] 执行签到...")
    cl = claim_checkin(ug_host, session, args.timeout)
    cpayload = cl.get("payload") if isinstance(cl.get("payload"), dict) else {}
    _pretty(cpayload)

    if cl["status"] == 200:
        ccode = _biz_code(cpayload)
        if ccode in (None, 0):
            print("\n[✓] 签到成功！")
            granted = cpayload.get("credits") if isinstance(cpayload, dict) else None
            if granted is None and isinstance(cpayload.get("data"), dict):
                granted = cpayload["data"].get("credits")
            if granted is not None:
                print(f"[✓] 获得积分: {granted}")
            if args.usage:
                _print_usage(ug_host, session, args.timeout)
            return 0
        if ccode in (1001, 2001):  # 常见「已签到」类错误码
            print(f"\n[✓] 已签到（业务错误码 {ccode}: {cpayload.get('message', '')}）")
            if args.usage:
                _print_usage(ug_host, session, args.timeout)
            return 0
        print(f"\n[✗] 签到失败，业务错误码 {ccode}: {cpayload.get('message', '')}")
        return 1

    print(f"\n[✗] 签到失败，HTTP {cl['status']}")
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
    ap.add_argument("--device-brand", default=DEFAULT_DEVICE_BRAND)
    ap.add_argument("--device-type", default=DEFAULT_DEVICE_TYPE)
    ap.add_argument("--usage", action="store_true", help="附带查询积分余额")
    ap.add_argument("--dry-run", action="store_true", help="只查询状态，不执行签到")
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
            "device_brand": args.device_brand,
            "device_type": args.device_type,
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
            host = ug_host
            # 凭证文件里若带 ug_host/apiHost，优先使用（未显式传 --ug-host 时）
            if session.get("ug_host") and args.ug_host == DEFAULT_UG_HOST:
                host = str(session["ug_host"]).rstrip("/")
            failures += _run_one(args, session, host)
        return failures

    session = load_session(args.auth_file)
    if session.get("ug_host") and args.ug_host == DEFAULT_UG_HOST:
        ug_host = str(session["ug_host"]).rstrip("/")
    return _run_one(args, session, ug_host)


if __name__ == "__main__":
    raise SystemExit(main())
