#!/usr/bin/env python3
"""Qoder CN campaign claims; see ../reverse-note/qoder-cn-daily-checkin_CN.md."""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = "https://openapi.qoder.com.cn"
CAMPAIGNS = "/sash/api/v1/me/campaigns"


class CheckinError(Exception):
    """A sanitized error safe to display without exposing credentials."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward the bearer token through a redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_json(endpoint, method, headers):
    url = BASE + endpoint
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "openapi.qoder.com.cn":
        raise CheckinError("Untrusted API URL")
    # Scheme and authority are explicitly allowlisted above; redirects are disabled below.
    request = urllib.request.Request(url, headers=headers, method=method)  # noqa: S310
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(request) as response:
            if not 200 <= response.status < 300:
                raise CheckinError(f"HTTP {response.status}")
            try:
                return json.load(response)
            except (ValueError, UnicodeError):
                raise CheckinError("Invalid JSON response") from None
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        raise CheckinError(f"HTTP {status}") from None
    except CheckinError:
        raise
    except Exception:
        raise CheckinError("Network request failed; no automatic retry performed") from None


def unwrap(payload):
    if isinstance(payload, dict) and payload.get("data") is not None:
        return payload["data"]
    return payload


def run(credential, claim=False, transport=request_json):
    if not isinstance(credential, dict):
        raise CheckinError("Invalid credential object")
    token = credential.get("access_token", credential.get("accessToken"))
    machine_id = credential.get("machine_id", credential.get("machineId"))
    if not isinstance(token, str) or not token.strip():
        raise CheckinError("Missing access_token")
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token.strip()}",
        "User-Agent": "Qoder",
        "Cosy-ClientType": "10",
        "Cosy-Business-Product": "app",
        "Cosy-Version": "0.2.5",
    }
    if isinstance(machine_id, str) and machine_id.strip():
        headers["Cosy-MachineId"] = machine_id.strip()

    payload = unwrap(transport(CAMPAIGNS, "GET", headers))
    campaigns = payload if isinstance(payload, list) else (
        payload.get("campaigns") if isinstance(payload, dict) else None
    )
    if not isinstance(campaigns, list):
        raise CheckinError("Invalid campaigns response: expected an array")
    keys = ("campaignId", "campaignKey", "actionType", "claimStatus", "benefit")
    result = {
        "dryRun": not claim,
        "campaigns": [{k: c.get(k) for k in keys} for c in campaigns if isinstance(c, dict)],
        "claimed": [], "skipped": [], "errors": [],
    }
    seen = set()
    for campaign in result["campaigns"]:
        if campaign["actionType"] != "CLAIM_BENEFIT" or campaign["claimStatus"] != "CLAIMABLE":
            continue
        campaign_id = campaign["campaignId"]
        if not isinstance(campaign_id, str) or not campaign_id.strip():
            result["errors"].append({"error": "Claimable campaign has no valid campaignId"})
            continue
        if campaign_id in seen:
            continue
        seen.add(campaign_id)
        if not claim:
            result["skipped"].append(campaign_id)
            continue
        try:
            endpoint = f"{CAMPAIGNS}/{urllib.parse.quote(campaign_id, safe='')}/claim"
            # Match the official iframe: POST without a JSON body.
            response = unwrap(transport(endpoint, "POST", headers))
            if not isinstance(response, dict) or response.get("status") != "CLAIMED":
                raise CheckinError("Unexpected claim response status")
            benefit = campaign.get("benefit")
            result["claimed"].append({
                "campaignId": campaign_id,
                "campaignKey": campaign["campaignKey"],
                "amount": benefit.get("amount") if isinstance(benefit, dict) else None,
            })
        except CheckinError as error:
            result["errors"].append({"campaignId": campaign_id, "error": str(error)})
    return result


def _auth_dir_files(directory, prefix=None):
    if not directory.is_dir():
        raise CheckinError("--auth-dir is not a directory")
    files = sorted(p for p in directory.glob("*.json")
                   if p.is_file() and (prefix is None or p.name.startswith(prefix)))
    if not files:
        raise CheckinError("No matching .json credential files")
    return files


def load_session(path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        raise CheckinError("Cannot read or parse the credential JSON file") from None
    if not isinstance(data, dict):
        raise CheckinError("Invalid credential object")
    # Do not send credentials belonging to other providers to Qoder.
    if data.get("type") not in (None, "qoder-cn"):
        raise CheckinError("Credential type is not qoder-cn")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description="Qoder CN daily check-in (default: checkin).")
    parser.add_argument("action", nargs="?", default="checkin", choices=["status", "checkin"])
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--auth-file", "--auth", dest="auth_file", type=Path)
    source.add_argument("--auth-dir", type=Path, help="Process matching .json files sequentially")
    source.add_argument("--token", help="Manual access token (prefer a file to avoid shell history)")
    parser.add_argument("--prefix", help="Filename prefix filter for --auth-dir")
    parser.add_argument("--machine-id", help="Optional machine ID for --token")
    parser.add_argument("--claim", action="store_true", help="Legacy alias for checkin")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args(argv)
    if args.prefix is not None and args.auth_dir is None:
        parser.error("--prefix requires --auth-dir")
    if args.machine_id is not None and args.token is None:
        parser.error("--machine-id requires --token")
    if args.claim and args.action == "status":
        parser.error("status cannot be combined with --claim")
    if args.auth_file is None and args.auth_dir is None and args.token is None:
        env_file = os.environ.get("QODER_CN_AUTH_FILE")
        if not env_file:
            parser.error("Use --auth-file, --auth-dir, --token or QODER_CN_AUTH_FILE")
        args.auth_file = Path(env_file)
    try:
        files = _auth_dir_files(args.auth_dir, args.prefix) if args.auth_dir else [args.auth_file]
    except CheckinError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    entries = []
    failed = 0
    for path in files:
        entry: dict = {"source": str(path) if path else "manual token"}
        try:
            credential = load_session(path) if path else {
                "access_token": args.token, "machine_id": args.machine_id,
            }
            result = run(credential, claim=args.action == "checkin")
            entry["result"] = result
            if result["errors"]:
                failed += 1
        except CheckinError as error:
            entry["error"] = str(error)
            failed += 1
        except Exception:
            entry["error"] = "Operation failed; no automatic retry performed"
            failed += 1
        entries.append(entry)
        if not args.json:
            print(f"[i] Credential: {entry['source']}")
            if "error" in entry:
                print(f"[x] {entry['error']}")
                continue
            result = entry["result"]
            print("Query only." if result["dryRun"] else "Check-in mode.")
            for campaign in result["campaigns"]:
                print(f"  {campaign['claimStatus']}  {campaign['actionType']}  "
                      f"{campaign['campaignKey'] or campaign['campaignId']}")
            print(f"Claimed: {len(result['claimed'])}; skipped: {len(result['skipped'])}; "
                  f"errors: {len(result['errors'])}")
            for error in result["errors"]:
                print(f"[x] {error['error']}")
    summary = {"total": len(entries), "succeeded": len(entries) - failed, "failed": failed}
    if args.json:
        print(json.dumps({"accounts": entries, "summary": summary}, ensure_ascii=False, indent=2))
    else:
        print(f"Total: {summary['total']}; succeeded: {summary['succeeded']}; failed: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
