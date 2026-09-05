#!/usr/bin/env python3
"""
WorkBuddy 每日签到脚本

调用腾讯 WorkBuddy/CodeBuddy 桌面端的「每日签到」(Buddy 加油站) 后端接口。

接口（从 app.asar 逆向提取）:
  - 查询状态:  POST {endpoint}/v2/billing/meter/checkin-activity-status
  - 执行签到:  POST {endpoint}/v2/billing/meter/daily-checkin

鉴权:
  - Authorization: Bearer <accessToken>
  - X-User-Id: <uid>
  - X-Enterprise-Id / X-Tenant-Id: 企业账号时存在
  - X-Domain: 域账号时存在

登录态来源（自动读取，也可手动传入）:
  Windows:  %LOCALAPPDATA%\\CodeBuddyExtension\\Data\\Public\\auth\\<id>.info
  macOS:    ~/Library/Application Support/CodeBuddyExtension/Data/Public/auth/<id>.info
  Linux:    ~/.local/share/CodeBuddyExtension/Data/Public/auth/<id>.info

用法:
  uv run workbuddy_checkin.py                     # 查询状态 + 签到
  uv run workbuddy_checkin.py status              # 仅查询状态
  uv run workbuddy_checkin.py --token <TOKEN> --uid <UID>   # 手动指定
  uv run workbuddy_checkin.py --auth-dir <DIR>    # 对目录下所有 .json 凭证文件签到
  uv run workbuddy_checkin.py --auth-dir <DIR> --prefix codebuddy  # 只处理 codebuddy*.json
  uv run workbuddy_checkin.py --auth-file <AUTH_FILE> # 对单个文件执行签到
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
DEFAULT_ENDPOINT = "https://copilot.tencent.com"
STAGING_ENDPOINT = "https://staging.codebuddy.cn"

AUTH_ID = "auth"  # authenticationId，可用 authentication.id 覆盖
AUTH_REL_PATH = ("CodeBuddyExtension", "Data", "Public", "auth")

# 可能的登录态文件路径（按平台）
def _auth_candidates() -> list[Path]:
    home = Path.home()
    env_override = os.environ.get("WORKBUDDY_AUTH_FILE") or os.environ.get("CODEBUDDY_AUTH_FILE")
    if env_override:
        return [Path(env_override)]

    bases = []
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            bases.append(Path(local))
        bases.append(home / "AppData" / "Local")
    elif sys.platform == "darwin":
        bases.append(home / "Library" / "Application Support")
    else:
        bases.append(home / ".local" / "share")
        bases.append(home / ".config")

    out = []
    for base in bases:
        d = base.joinpath(*AUTH_REL_PATH)
        out.append(d / f"{AUTH_ID}.info")
        # 也尝试目录下任意 .info 文件
        out.extend(sorted(d.glob("*.info")) if d.exists() else [])
    return out


# ---------------------------------------------------------------- 登录态
def _decode_jwt_sub(token: str) -> str | None:
    """从 JWT 的 payload 解出 sub（作为用户 uid）。失败返回 None。"""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        pad = "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
        return payload.get("sub")
    except Exception:
        return None


def load_session(auth_file: Path | None) -> dict:
    """读取登录态，返回含 token/uid/enterpriseId/domain/endpoint 的 dict。

    支持两种格式：
      1. 桌面端 auth.info：{ auth: { accessToken, domain }, account: { uid, enterpriseId } }
      2. CLI 凭证（codebuddy-cn 等）：{ access_token, base_url, refresh_token, ... }
         此时 uid 从 JWT 的 sub 自动解出，endpoint 取自 base_url。
    """
    path = auth_file or next((p for p in _auth_candidates() if p.is_file()), None)
    if path is None:
        raise SystemExit(
            "未找到登录态文件。请先用 WorkBuddy 登录，或通过 "
            "--auth-file / --token+--uid 指定。"
        )
    data = json.loads(path.read_text(encoding="utf-8"))

    # 格式 2：CLI 凭证
    if "access_token" in data:
        token = data.get("access_token")
        uid = _decode_jwt_sub(token)
        if not token or not uid:
            raise SystemExit(f"凭证文件 {path} 中 access_token 无效或无法解出 uid。")
        endpoint = (data.get("base_url") or "").rstrip("/")
        # base_url 常带 /v2，去掉它以配合脚本内部的 /v2 拼接
        if endpoint.endswith("/v2"):
            endpoint = endpoint[: -len("/v2")]
        print(f"[i] 登录态来源: {path} (CLI 凭证 type={data.get('type')})")
        return {
            "token": token,
            "uid": uid,
            "enterpriseId": data.get("enterprise_id") or data.get("enterpriseId"),
            "domain": data.get("domain"),
            "endpoint": endpoint or None,
            "_path": str(path),
        }

    # 格式 1：桌面端 auth.info
    auth = data.get("auth", {}) or {}
    account = data.get("account", {}) or {}
    token = auth.get("accessToken")
    uid = account.get("uid")
    if not token or not uid:
        raise SystemExit(f"登录态文件 {path} 中缺少 accessToken/uid。")
    print(f"[i] 登录态来源: {path} (桌面端 auth.info)")
    return {
        "token": token,
        "uid": uid,
        "enterpriseId": account.get("enterpriseId"),
        "domain": auth.get("domain"),
        "endpoint": None,
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


def build_headers(session: dict, ua_version: str = "5.3.14") -> dict:
    h = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {session['token']}",
        "X-User-Id": str(session["uid"]),
        "User-Agent": f"WorkBuddy/{ua_version}",
    }
    if session.get("enterpriseId"):
        h["X-Enterprise-Id"] = str(session["enterpriseId"])
        h["X-Tenant-Id"] = str(session["enterpriseId"])
    if session.get("domain"):
        h["X-Domain"] = str(session["domain"])
    return h


# ---------------------------------------------------------------- 业务
def checkin_status(endpoint: str, session: dict, timeout: int) -> dict:
    url = f"{endpoint}/v2/billing/meter/checkin-activity-status"
    return _http_json(url, build_headers(session), {}, timeout)


def claim_daily_checkin(endpoint: str, session: dict, timeout: int) -> dict:
    url = f"{endpoint}/v2/billing/meter/daily-checkin"
    return _http_json(url, build_headers(session), {}, timeout)


def _pretty(data: dict) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2))


def _run_one(args: argparse.Namespace, session: dict, endpoint: str) -> int:
    """对单个登录态执行 status/checkin。"""
    print(f"[i] endpoint: {endpoint}")

    if args.action == "status":
        r = checkin_status(endpoint, session, args.timeout)
        _pretty(r)
        return 0 if r["status"] == 200 else 1

    # checkin: 先查状态再签到
    print("[i] 查询签到状态...")
    st = checkin_status(endpoint, session, args.timeout)
    _pretty(st)
    data = st.get("payload", {}).get("data") if isinstance(st.get("payload"), dict) else None
    already = (
        data.get("today_checked_in")
        if isinstance(data, dict)
        else False
    )
    if already:
        print("\n[✓] 今日已签到，无需重复。")
        return 0

    print("\n[i] 执行签到...")
    cl = claim_daily_checkin(endpoint, session, args.timeout)
    _pretty(cl)
    if cl["status"] == 200:
        payload = cl.get("payload", {})
        code = payload.get("code") if isinstance(payload, dict) else None
        if code == 0:
            print("\n[✓] 签到成功！")
            return 0
    print("\n[✗] 签到未成功（见上方响应）。")
    return 1


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
    ap = argparse.ArgumentParser(description="WorkBuddy 每日签到")
    ap.add_argument("action", nargs="?", default="checkin", choices=["status", "checkin"])
    ap.add_argument("--endpoint", default=os.environ.get("WORKBUDDY_ENDPOINT", DEFAULT_ENDPOINT))
    ap.add_argument("--staging", action="store_true", help="使用 staging 环境")
    ap.add_argument("--auth-file", type=Path, default=None, help="手动指定登录态文件路径")
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
    ap.add_argument("--token", default=None)
    ap.add_argument("--uid", default=None)
    ap.add_argument("--enterprise-id", default=None)
    ap.add_argument("--domain", default=None)
    ap.add_argument("--timeout", type=int, default=15)
    args = ap.parse_args()

    if args.staging:
        args.endpoint = STAGING_ENDPOINT
    endpoint = args.endpoint.rstrip("/")

    if args.prefix and not args.auth_dir:
        raise SystemExit("--prefix 需要配合 --auth-dir 使用")

    if args.token and args.uid:
        session = {
            "token": args.token,
            "uid": args.uid,
            "enterpriseId": args.enterprise_id,
            "domain": args.domain,
            "endpoint": None,
        }
        return _run_one(args, session, endpoint)

    if args.auth_dir:
        total = 0
        for path in _auth_dir_files(args.auth_dir, args.prefix):
            print("\n" + "=" * 60)
            print(f"[i] 处理凭证文件: {path}")
            print("=" * 60)
            try:
                session = load_session(path)
            except SystemExit as e:
                print(f"[✗] 跳过 {path}: {e}")
                total += 1
                continue
            file_endpoint = endpoint
            # 凭证文件里若带 endpoint/base_url，优先使用（未显式传 --endpoint 时）
            if session.get("endpoint") and args.endpoint == DEFAULT_ENDPOINT:
                file_endpoint = session["endpoint"].rstrip("/")
            total += _run_one(args, session, file_endpoint)
        return total

    session = load_session(args.auth_file)

    # 凭证文件里若带 endpoint/base_url，优先使用（未显式传 --endpoint 时）
    if session.get("endpoint") and args.endpoint == DEFAULT_ENDPOINT:
        endpoint = session["endpoint"].rstrip("/")

    return _run_one(args, session, endpoint)


if __name__ == "__main__":
    raise SystemExit(main())
