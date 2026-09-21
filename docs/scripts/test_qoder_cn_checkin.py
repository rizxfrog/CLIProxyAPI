"""Offline regression tests; never call the live service."""
import io
import unittest
import urllib.request
from http.client import HTTPMessage
from unittest.mock import patch

from qoder_cn_checkin import CheckinError, NoRedirect, request_json, run

CREDENTIAL = {"access_token": "test-only-token"}
CAMPAIGN = {"campaignId": "a/b", "actionType": "CLAIM_BENEFIT", "claimStatus": "CLAIMABLE"}


class CheckinTests(unittest.TestCase):
    def test_query_only(self):
        calls = []

        def transport(path, method, headers):
            calls.append(method)
            self.assertEqual(headers["Cosy-ClientType"], "10")
            return {"campaigns": [CAMPAIGN]}

        result = run(CREDENTIAL, transport=transport)
        self.assertEqual(calls, ["GET"])
        self.assertEqual(result["skipped"], ["a/b"])
        self.assertNotIn(CREDENTIAL["access_token"], str(result))

    def test_claim_filters_and_deduplicates(self):
        calls = []

        def transport(path, method, headers):
            calls.append((path, method))
            if method == "GET":
                return {"data": {"campaigns": [CAMPAIGN, CAMPAIGN,
                    dict(CAMPAIGN, campaignId="details", actionType="VIEW_DETAILS"),
                    dict(CAMPAIGN, campaignId="done", claimStatus="CLAIMED")]}}
            self.assertTrue(path.endswith("/a%2Fb/claim"))
            return {"data": {"status": "CLAIMED"}}

        result = run(CREDENTIAL, claim=True, transport=transport)
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(result["claimed"]), 1)

    def test_invalid_list(self):
        with self.assertRaises(CheckinError):
            run(CREDENTIAL, transport=lambda *args: {})

    def test_invalid_credentials(self):
        for credential in (None, {}, {"access_token": 1}):
            with self.assertRaises(CheckinError):
                run(credential)

    def test_claim_failure(self):
        def transport(path, method, headers):
            if method == "GET":
                return {"campaigns": [CAMPAIGN]}
            return {"status": "UNKNOWN"}
        result = run(CREDENTIAL, claim=True, transport=transport)
        self.assertEqual(len(result["errors"]), 1)
        self.assertEqual(result["claimed"], [])

    def test_redirect_refused(self):
        request = urllib.request.Request('https://example.com')  # noqa: S310 -- fixed HTTPS test URL
        self.assertIsNone(NoRedirect().redirect_request(
            request, io.BytesIO(), 302, '', HTTPMessage(), 'https://example.com'))

    @patch('qoder_cn_checkin.urllib.request.build_opener')
    def test_bodyless_post_and_sanitized_error(self, factory):
        factory.return_value.open.side_effect = OSError('test-only-token')
        with self.assertRaisesRegex(CheckinError, '^Network request failed'):
            request_json('/sash/api/v1/me/campaigns/x/claim', 'POST', {})
        request = factory.return_value.open.call_args.args[0]
        self.assertIsNone(request.data)
        self.assertEqual(request.method, 'POST')
        factory.return_value.open.assert_called_once()


if __name__ == '__main__':
    unittest.main()
