"""Offline regression tests; never call the live service."""
import contextlib
import io
import json
import tempfile
import unittest
import urllib.request
from http.client import HTTPMessage
from pathlib import Path
from unittest.mock import patch

from qoder_cn_checkin import CheckinError, NoRedirect, main, request_json, run

CREDENTIAL = {"access_token": "test-only-token"}
CAMPAIGN = {"campaignId": "a/b", "actionType": "CLAIM_BENEFIT", "claimStatus": "CLAIMABLE"}


class CheckinTests(unittest.TestCase):
    @patch('qoder_cn_checkin.run')
    def test_cli_batch_continues_and_filters(self, runner):
        runner.return_value = {"dryRun": False, "campaigns": [], "claimed": [], "skipped": [], "errors": []}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'qoder-1.json').write_text('invalid', encoding='utf-8')
            (root / 'qoder-2.json').write_text(json.dumps(CREDENTIAL), encoding='utf-8')
            (root / 'other.json').write_text(json.dumps(CREDENTIAL), encoding='utf-8')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(['--auth-dir', directory, '--prefix', 'qoder-', '--json'])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output.getvalue())['summary'],
                             {'total': 2, 'succeeded': 1, 'failed': 1})
            runner.assert_called_once_with(CREDENTIAL, claim=True)

    @patch('qoder_cn_checkin.run')
    def test_cli_status_and_default_action(self, runner):
        runner.return_value = {"errors": []}
        for action, expected in [([], True), (['status'], False)]:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(action + ['--token', 'test-token', '--json']), 0)
            self.assertEqual(runner.call_args.kwargs['claim'], expected)

    def test_cli_invalid_options(self):
        for args in [['--prefix', 'qoder'], ['status', '--claim', '--token', 'x'],
                     ['--auth-file', 'x', '--auth-dir', 'y']]:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(args)

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
