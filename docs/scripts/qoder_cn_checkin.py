#!/usr/bin/env python3
"""Qoder CN campaign claims; see ../reverse-note/qoder-cn-daily-checkin_CN.md."""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

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


def main(argv=None):
    parser = argparse.ArgumentParser(description="Qoder CN Credits claims (query only by default).")
    parser.add_argument("--auth", required=True, help="Credential JSON containing access_token")
    parser.add_argument("--claim", action="store_true", help="Submit all claimable CLAIM_BENEFIT campaigns")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args(argv)
    try:
        try:
            with open(args.auth, encoding="utf-8") as file:
                credential = json.load(file)
        except (OSError, ValueError, UnicodeError):
            raise CheckinError("Cannot read or parse the credential JSON file") from None
        result = run(credential, claim=args.claim)
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print("Query only; no claims submitted." if result["dryRun"] else "Claim mode.")
            for campaign in result["campaigns"]:
                print(f"{campaign['claimStatus']}  {campaign['actionType']}  "
                      f"{campaign['campaignKey'] or campaign['campaignId']}")
            print(f"Claimed: {len(result['claimed'])}; skipped: {len(result['skipped'])}; "
                  f"errors: {len(result['errors'])}")
            for error in result["errors"]:
                print(f"{error.get('campaignId', 'campaign')}: {error['error']}", file=sys.stderr)
        return 1 if result["errors"] else 0
    except CheckinError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except Exception:
        print("Error: operation failed; no automatic retry performed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
