"""Local-only HTTP integration checks for the decision-model testbench.

Run with: python3 -m unittest discover -s testcases/web -p 'test_server.py' -v
All upstream calls terminate at an ephemeral loopback HTTP server.
"""

import importlib.util
import json
from pathlib import Path
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener


WEB_ROOT = Path(__file__).resolve().parent
DATA_ROOT = WEB_ROOT.parent / "code_vulnerability"
LOCAL_HTTP = build_opener(ProxyHandler({}))


def answer(score=0.8, **extra):
    return {
        "model": "mock-jev",
        "answers": {"has_vulnerability": {"type": "noul", "noul": score}},
        **extra,
    }


class MockDecisionHandler(BaseHTTPRequestHandler):
    """Record the actual wire request and return the test's chosen payload."""

    def log_message(self, *_args):
        pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.requests.append({
            "path": self.path,
            "headers": dict(self.headers),
            "body": json.loads(raw),
        })
        response = self.server.response
        payload = response if isinstance(response, bytes) else json.dumps(response).encode()
        self.send_response(self.server.status)
        self.send_header("Content-Type", self.server.content_type)
        self.send_header("Content-Length", str(len(payload)))
        if self.server.redirect:
            self.send_header("Location", self.server.redirect)
        self.end_headers()
        self.wfile.write(payload)


class TestDecisionServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("decision_testbench_server", WEB_ROOT / "server.py")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), MockDecisionHandler)
        cls.upstream.daemon_threads = True
        cls.upstream_thread = threading.Thread(target=cls.upstream.serve_forever, daemon=True)
        cls.upstream_thread.start()
        cls.app = cls.module.create_server(host="127.0.0.1", port=0)
        cls.app_thread = threading.Thread(target=cls.app.serve_forever, daemon=True)
        cls.app_thread.start()
        cls.base_url = "http://127.0.0.1:%d" % cls.app.server_address[1]
        cls.endpoint = "http://127.0.0.1:%d/v1/systemone/" % cls.upstream.server_address[1]
        cls.input_cases = [json.loads(line) for line in (DATA_ROOT / "inputs/cases.jsonl").read_text().splitlines() if line]
        cls.gold = [json.loads(line) for line in (DATA_ROOT / "gold/answers.jsonl").read_text().splitlines() if line]
        cls.case_id = cls.input_cases[0]["id"]
        deadline = time.monotonic() + 3
        while True:
            try:
                with LOCAL_HTTP.open(cls.base_url + "/api/dataset", timeout=0.25) as response:
                    cls.dataset = json.load(response)
                break
            except URLError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)

    @classmethod
    def tearDownClass(cls):
        for server, thread in ((cls.app, cls.app_thread), (cls.upstream, cls.upstream_thread)):
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def setUp(self):
        self.upstream.requests = []
        self.upstream.response = answer()
        self.upstream.status = 200
        self.upstream.content_type = "application/json"
        self.upstream.redirect = None

    def request(self, path, payload=None, headers=None, trusted=True):
        request_headers = {"Content-Type": "application/json"}
        if trusted:
            request_headers["X-Testbench-Request"] = "1"
        request_headers.update(headers or {})
        request = Request(
            self.base_url + path,
            data=None if payload is None else json.dumps(payload).encode(),
            headers=request_headers,
        )
        try:
            response = LOCAL_HTTP.open(request, timeout=5)
        except HTTPError as error:
            response = error
        with response:
            content = response.read()
            try:
                parsed = json.loads(content)
            except (json.JSONDecodeError, UnicodeDecodeError):
                parsed = content
            return response.status, parsed

    def run_case(self, **config):
        merged = {"endpoint": self.endpoint, "api_key": "", "model": "custom-model", "threshold": 0.5, "timeout": 2}
        merged.update(config)
        return self.request("/api/run", {"case_id": self.case_id, "config": merged})

    def assert_failed_run(self, result):
        status, body = result
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "error")
        self.assertNotIn(body.get("verdict"), ("vulnerable", "not_vulnerable"))
        self.assertTrue(body.get("error"))
        return body

    def test_dataset_contains_all_cases_and_defaults(self):
        self.assertEqual(len(self.dataset["cases"]), 48)
        self.assertEqual({row["id"] for row in self.dataset["cases"]}, {row["id"] for row in self.input_cases})
        self.assertIn("manifest", self.dataset)
        self.assertIn("defaults", self.dataset)

    def test_wire_body_is_direct_request_without_gold_or_metadata(self):
        status, body = self.run_case(api_key="local-test-key")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["id"], self.case_id)
        self.assertEqual(body["verdict"], "vulnerable")
        self.assertEqual(body["score"], 0.8)
        self.assertEqual(body["http_status"], 200)
        self.assertEqual(body["response_model"], "mock-jev")
        self.assertGreaterEqual(body["latency_ms"], 0)
        self.assertEqual(len(self.upstream.requests), 1)
        sent = self.upstream.requests[0]
        self.assertEqual(sent["path"], "/v1/systemone/")
        self.assertEqual(sent["headers"].get("Authorization"), "Bearer local-test-key")
        expected = json.loads((DATA_ROOT / "inputs/requests" / (self.case_id + ".json")).read_text())
        expected["model"] = "custom-model"
        self.assertEqual(sent["body"], expected)
        self.assertEqual(set(sent["body"]), {"state", "model", "questions"})
        self.assertEqual(set(sent["body"]["state"]), {"language", "scope", "target_cwe", "context", "code"})
        self.assertEqual(sent["body"]["state"]["code"], self.input_cases[0]["code"])
        for forbidden in ("id", "verdict", "rationale", "evidence", "pair_id", "provenance"):
            self.assertNotIn(forbidden, sent["body"])
            self.assertNotIn(forbidden, sent["body"]["state"])
        self.assertEqual(set(sent["body"]["questions"]), {"has_vulnerability"})
        self.assertEqual(sent["body"]["questions"]["has_vulnerability"]["type"], "noul")

    def test_optional_key_is_not_sent_and_custom_path_is_preserved(self):
        endpoint = self.endpoint.replace("/v1/systemone/", "/custom/nested/decision/?version=2")
        status, body = self.run_case(endpoint=endpoint)
        self.assertEqual((status, body["status"]), (200, "ok"))
        sent = self.upstream.requests[0]
        self.assertEqual(sent["path"], "/custom/nested/decision/?version=2")
        self.assertNotIn("Authorization", sent["headers"])

    def test_threshold_includes_boundary_and_supports_custom_value(self):
        for score, threshold, verdict in ((0.5, 0.5, "vulnerable"), (0.499, 0.5, "not_vulnerable"), (0.8, 0.9, "not_vulnerable"), (1, 1, "vulnerable"), (0, 0.5, "not_vulnerable")):
            with self.subTest(score=score, threshold=threshold):
                self.upstream.response = answer(score)
                status, body = self.run_case(threshold=threshold)
                self.assertEqual(status, 200)
                self.assertEqual(body["status"], "ok")
                self.assertEqual(body["verdict"], verdict)

    def test_invalid_scores_are_errors_and_never_negative_decisions(self):
        malformed = [
            {}, {"answers": {}},
            {"answers": {"has_vulnerability": {"type": "noul"}}},
            {"answers": {"has_vulnerability": {"type": "boolean", "noul": 0.8}}},
            answer(True), answer(False), answer(-0.1), answer(1.1), answer("0.8"),
            answer(None), answer(float("nan")), answer(float("inf")), [],
        ]
        for response in malformed:
            with self.subTest(response=response):
                self.upstream.response = response
                self.assert_failed_run(self.run_case())

    def test_non_json_response_is_an_error(self):
        self.upstream.response = b"<html>not a decision</html>"
        self.upstream.content_type = "text/html"
        self.assert_failed_run(self.run_case())

    def test_upstream_non_success_status_is_preserved(self):
        self.upstream.status = 429
        self.upstream.response = {"error": "rate limited"}
        body = self.assert_failed_run(self.run_case())
        self.assertEqual(body["http_status"], 429)

    def test_redirect_is_not_followed_with_credentials(self):
        self.upstream.status = 307
        self.upstream.redirect = self.endpoint.replace("/v1/systemone/", "/credential-collector")
        body = self.assert_failed_run(self.run_case(api_key="redirect-test-secret"))
        self.assertEqual(body["http_status"], 307)
        self.assertEqual(len(self.upstream.requests), 1)
        self.assertEqual(self.upstream.requests[0]["path"], "/v1/systemone/")

    def test_echoed_credentials_are_redacted_from_result(self):
        secret = "do-not-return-this-api-key"
        self.upstream.response = answer(model=secret, echo={"Authorization": "Bearer " + secret})
        status, body = self.run_case(api_key=secret)
        self.assertEqual(status, 200)
        self.assertNotIn(secret, json.dumps(body))
        self.upstream.status = 401
        self.upstream.response = {"error": "Bad key: " + secret}
        status, body = self.run_case(api_key=secret)
        self.assertEqual(status, 200)
        self.assertNotIn(secret, json.dumps(body))

    def test_invalid_config_and_unknown_case_are_rejected_before_network(self):
        for config in ({"endpoint": "file:///tmp/local"}, {"model": ""}, {"threshold": -1}, {"threshold": 2}, {"threshold": True}, {"timeout": 0}, {"api_key": "secret\r\nInjected: header"}):
            with self.subTest(config=config):
                status, _body = self.run_case(**config)
                self.assertEqual(status, 400)
        status, _body = self.request("/api/run", {"case_id": "unknown", "config": {"endpoint": self.endpoint, "model": "custom"}})
        self.assertEqual(status, 400)
        self.assertEqual(self.upstream.requests, [])

    def test_cross_origin_wrong_host_and_missing_header_are_rejected(self):
        payload = {"case_id": self.case_id, "config": {"endpoint": self.endpoint, "model": "custom"}}
        for headers, trusted in (({"Origin": "https://unrelated.invalid"}, True), ({"Host": "unrelated.invalid"}, True), ({}, False)):
            with self.subTest(headers=headers, trusted=trusted):
                status, _body = self.request("/api/run", payload, headers=headers, trusted=trusted)
                self.assertEqual(status, 403)
        self.assertEqual(self.upstream.requests, [])

    def test_same_origin_request_is_allowed(self):
        payload = {"case_id": self.case_id, "config": {"endpoint": self.endpoint, "model": "custom", "timeout": 2}}
        status, body = self.request("/api/run", payload, headers={"Origin": self.base_url})
        self.assertEqual((status, body["status"]), (200, "ok"))

    def test_scoring_single_case_allows_incomplete_contrast_pair(self):
        row = next(row for row in self.gold if row.get("pair_id"))
        status, body = self.request("/api/score", {"case_ids": [row["id"]], "predictions": [{"id": row["id"], "verdict": row["verdict"]}]})
        self.assertEqual(status, 200)
        self.assertEqual(body["overall"]["total"], 1)
        self.assertEqual(body["overall"]["primary"]["strict_accuracy"], 1)
        self.assertEqual(body["contrast_pairs"]["total"], 0)

    def test_missing_prediction_is_in_accuracy_denominator(self):
        rows = self.gold[:2]
        status, body = self.request("/api/score", {"case_ids": [row["id"] for row in rows], "predictions": [{"id": rows[0]["id"], "verdict": rows[0]["verdict"]}]})
        self.assertEqual(status, 200)
        self.assertEqual(body["overall"]["total"], 2)
        self.assertEqual(body["overall"]["counts"]["missing"], 1)
        self.assertEqual(body["overall"]["primary"]["strict_accuracy"], 0.5)
        self.assertEqual(body["overall"]["binary_coverage"], 0.5)

    def test_unknown_duplicate_and_out_of_selection_predictions_are_rejected(self):
        prediction = {"id": self.case_id, "verdict": "vulnerable"}
        invalid = [[{"id": "unknown", "verdict": "vulnerable"}], [prediction, prediction], [{"id": self.gold[1]["id"], "verdict": "vulnerable"}]]
        for predictions in invalid:
            with self.subTest(predictions=predictions):
                status, _body = self.request("/api/score", {"case_ids": [self.case_id], "predictions": predictions})
                self.assertEqual(status, 400)

    def test_static_route_allowlist_blocks_gold_and_traversal(self):
        for path in ("/gold/answers.jsonl", "/code_vulnerability/gold/answers.jsonl", "/../code_vulnerability/gold/answers.jsonl", "/%2e%2e/code_vulnerability/gold/answers.jsonl", "/server.py"):
            with self.subTest(path=path):
                status, body = self.request(path)
                self.assertIn(status, (403, 404))
                self.assertNotIn(self.gold[0]["rationale"], str(body))


if __name__ == "__main__":
    unittest.main()
