"""Local-only HTTP integration checks for the decision-model testbench.

Run with: python3 -m unittest discover -s testcases/web -p 'test_server.py' -v
All upstream calls terminate at an ephemeral loopback HTTP server.
"""

import importlib.util
import json
import os
from contextlib import contextmanager
from pathlib import Path
from shutil import copytree
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener
import urllib.request as urllib_request


WEB_ROOT = Path(__file__).resolve().parent
DATA_ROOT = WEB_ROOT.parent / "code_vulnerability"
BASELINE_ROOT = DATA_ROOT / "collections" / "baseline"
LOCAL_HTTP = build_opener(ProxyHandler({}))


def answer(score=0.8, **extra):
    return {
        "model": "mock-jev",
        "answers": {"has_vulnerability": {"type": "noul", "noul": score}},
        **extra,
    }


def load_server_module():
    spec = importlib.util.spec_from_file_location("decision_testbench_server", WEB_ROOT / "server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestUtf8DataLoading(unittest.TestCase):
    def test_server_loads_utf8_dataset_with_gbk_default_encoding(self):
        """Reproduce non-UTF-8 Windows defaults without opening a listening socket."""
        module = load_server_module()
        expected = {}
        for collection_id in ("baseline", "cwe_specific"):
            collection_root = DATA_ROOT / "collections" / collection_id
            cases_path = collection_root / "inputs/cases.jsonl"
            gold_path = collection_root / "gold/answers.jsonl"
            expected[collection_id] = {
                "cases": {row["id"]: row for row in map(json.loads, cases_path.read_text(encoding="utf-8").splitlines())},
                "gold": {row["id"]: row for row in map(json.loads, gold_path.read_text(encoding="utf-8").splitlines())},
                "manifest": json.loads((collection_root / "manifest.json").read_text(encoding="utf-8")),
            }
            expected[collection_id]["manifest"]["description"] = "代码漏洞评估用例"
        original_read_text = Path.read_text

        def gbk_default_read_text(path, encoding=None, errors=None, **kwargs):
            return original_read_text(path, encoding=encoding or "gbk", errors=errors, **kwargs)

        with TemporaryDirectory() as temporary:
            dataset = Path(temporary)
            copytree(DATA_ROOT / "collections", dataset / "collections")
            for collection_id, data in expected.items():
                (dataset / "collections" / collection_id / "manifest.json").write_text(json.dumps(data["manifest"], ensure_ascii=False), encoding="utf-8")
            with patch.object(module, "DATASET_ROOT", dataset), patch.object(Path, "read_text", gbk_default_read_text), patch.object(ThreadingHTTPServer, "__init__", return_value=None):
                server = module.create_server(host="127.0.0.1", port=0)

        self.assertEqual(set(server.collections), {"baseline", "cwe_specific"})
        for collection_id, data in expected.items():
            with self.subTest(collection_id=collection_id):
                loaded = server.collections[collection_id]
                self.assertEqual(len(loaded["cases"]), 48)
                self.assertEqual(len(loaded["gold"]), 48)
                self.assertEqual(loaded["cases"], data["cases"])
                self.assertEqual(loaded["gold"], data["gold"])
                self.assertEqual(loaded["manifest"], data["manifest"])
                self.assertIn("攻击者", loaded["cases"]["cv_ec63ace1718b"]["context"])
                self.assertEqual(loaded["gold"]["cv_ec63ace1718b"]["title"], "PreparedStatement 与动态排序字段")


class TestCollectionDiscovery(unittest.TestCase):
    def test_collection_directories_are_discovered_without_a_hardcoded_list(self):
        module = load_server_module()
        with TemporaryDirectory() as temporary:
            dataset = Path(temporary)
            copytree(DATA_ROOT / "collections", dataset / "collections")
            added = dataset / "collections" / "extra_collection"
            copytree(BASELINE_ROOT, added)
            manifest_path = added / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["collection"]["id"] = "extra_collection"
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
            with patch.object(module, "DATASET_ROOT", dataset), patch.object(ThreadingHTTPServer, "__init__", return_value=None):
                server = module.create_server(host="127.0.0.1", port=0)
        self.assertEqual(set(server.collections), {"baseline", "cwe_specific", "extra_collection"})
        added_collection = server.collections["extra_collection"]
        self.assertEqual(added_collection["metadata"]["id"], "extra_collection")
        self.assertEqual(added_collection["metadata"]["count"], 48)

    def test_collection_id_must_match_its_directory(self):
        module = load_server_module()
        with TemporaryDirectory() as temporary:
            dataset = Path(temporary)
            copytree(DATA_ROOT / "collections", dataset / "collections")
            manifest_path = dataset / "collections" / "baseline" / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["collection"]["id"] = "../cwe_specific"
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
            with patch.object(module, "DATASET_ROOT", dataset), patch.object(ThreadingHTTPServer, "__init__", return_value=None):
                with self.assertRaises(ValueError):
                    module.create_server(host="127.0.0.1", port=0)

    def test_baseline_collection_is_required(self):
        module = load_server_module()
        with TemporaryDirectory() as temporary:
            dataset = Path(temporary)
            copytree(DATA_ROOT / "collections" / "cwe_specific", dataset / "collections" / "cwe_specific")
            with patch.object(module, "DATASET_ROOT", dataset), patch.object(ThreadingHTTPServer, "__init__", return_value=None):
                with self.assertRaises(ValueError):
                    module.create_server(host="127.0.0.1", port=0)


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
        cls.module = load_server_module()
        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), MockDecisionHandler)
        cls.upstream.daemon_threads = True
        cls.upstream_thread = threading.Thread(target=cls.upstream.serve_forever, daemon=True)
        cls.upstream_thread.start()
        cls.proxy = ThreadingHTTPServer(("127.0.0.1", 0), MockDecisionHandler)
        cls.proxy.daemon_threads = True
        cls.proxy_thread = threading.Thread(target=cls.proxy.serve_forever, daemon=True)
        cls.proxy_thread.start()
        cls.app = cls.module.create_server(host="127.0.0.1", port=0)
        cls.app_thread = threading.Thread(target=cls.app.serve_forever, daemon=True)
        cls.app_thread.start()
        cls.base_url = "http://127.0.0.1:%d" % cls.app.server_address[1]
        cls.endpoint = "http://127.0.0.1:%d/v1/systemone/" % cls.upstream.server_address[1]
        cls.proxy_url = "http://127.0.0.1:%d" % cls.proxy.server_address[1]
        cls.input_cases = [json.loads(line) for line in (BASELINE_ROOT / "inputs/cases.jsonl").read_text(encoding="utf-8").splitlines() if line]
        cls.gold = [json.loads(line) for line in (BASELINE_ROOT / "gold/answers.jsonl").read_text(encoding="utf-8").splitlines() if line]
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
        for server, thread in ((cls.app, cls.app_thread), (cls.upstream, cls.upstream_thread), (cls.proxy, cls.proxy_thread)):
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def setUp(self):
        self.upstream.requests = []
        self.upstream.response = answer()
        self.upstream.status = 200
        self.upstream.content_type = "application/json"
        self.upstream.redirect = None
        self.proxy.requests = []
        self.proxy.response = {"error": "local proxy generated 504"}
        self.proxy.status = 504
        self.proxy.content_type = "application/json"
        self.proxy.redirect = None

    @contextmanager
    def proxy_environment(self, no_proxy=None):
        """Use real environment-proxy behavior, isolated from OS proxy settings."""
        environment = {"HTTP_PROXY": self.proxy_url, "http_proxy": self.proxy_url}
        if no_proxy is not None:
            environment["NO_PROXY"] = no_proxy
        with patch.dict(os.environ, environment, clear=True), patch.object(urllib_request, "getproxies", urllib_request.getproxies_environment), patch.object(urllib_request, "proxy_bypass", urllib_request.proxy_bypass_environment):
            yield

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

    def run_case(self, collection_id="baseline", **config):
        merged = {"endpoint": self.endpoint, "api_key": "", "model": "custom-model", "threshold": 0.5, "timeout": 2}
        merged.update(config)
        return self.request("/api/run", {"collection_id": collection_id, "case_id": self.case_id, "config": merged})

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
        self.assertEqual(self.dataset["defaults"]["proxy_mode"], "direct")
        self.assertEqual(self.dataset["collection"]["id"], "baseline")
        self.assertEqual(self.dataset["default_collection_id"], "baseline")

    def test_collection_listing_matches_available_datasets(self):
        status, listing = self.request("/api/collections")
        self.assertEqual(status, 200)
        self.assertEqual(listing["default_collection_id"], "baseline")
        self.assertEqual([row["id"] for row in listing["collections"]], ["baseline", "cwe_specific"])
        self.assertEqual(listing["collections"], self.dataset["collections"])
        for metadata in listing["collections"]:
            with self.subTest(collection_id=metadata["id"]):
                self.assertEqual(metadata["count"], 48)
                status, dataset = self.request("/api/dataset?" + urlencode({"collection_id": metadata["id"]}))
                self.assertEqual(status, 200)
                self.assertEqual(dataset["collection"], metadata)
                self.assertEqual(dataset["manifest"]["collection"]["id"], metadata["id"])
                self.assertEqual(len(dataset["cases"]), 48)

    def test_dataset_rejects_unknown_empty_and_traversal_collection_ids(self):
        for collection_id in ("unknown", "", "..", "../baseline", "baseline/../cwe_specific", "/baseline", "baseline\\..\\cwe_specific", "%2e%2e%2fbaseline"):
            with self.subTest(collection_id=collection_id):
                status, body = self.request("/api/dataset?" + urlencode({"collection_id": collection_id}))
                self.assertEqual(status, 400)
                self.assertNotIn("cases", body)
        status, _body = self.request("/api/dataset?collection_id=baseline&collection_id=cwe_specific")
        self.assertEqual(status, 400)

    def test_mutations_require_valid_explicit_collection_id(self):
        requests = {
            "/api/run": {"case_id": self.case_id, "config": {"endpoint": self.endpoint, "model": "custom"}},
            "/api/score": {"case_ids": [self.case_id], "predictions": []},
        }
        for path, payload in requests.items():
            with self.subTest(path=path, collection_id="missing"):
                status, _body = self.request(path, payload)
                self.assertEqual(status, 400)
            for collection_id in (None, True, 1, [], {}, "", "unknown", "../baseline", "baseline/../cwe_specific"):
                with self.subTest(path=path, collection_id=collection_id):
                    status, _body = self.request(path, {**payload, "collection_id": collection_id})
                    self.assertEqual(status, 400)
        self.assertEqual(self.upstream.requests, [])

    def test_run_requires_a_valid_case_id_within_the_selected_collection(self):
        payload = {"collection_id": "cwe_specific", "config": {"endpoint": self.endpoint, "model": "custom"}}
        status, _body = self.request("/api/run", payload)
        self.assertEqual(status, 400)
        for case_id in (None, True, 1, [], {}, "", "unknown", "../inputs/cases.jsonl"):
            with self.subTest(case_id=case_id):
                status, _body = self.request("/api/run", {**payload, "case_id": case_id})
                self.assertEqual(status, 400)
        self.assertEqual(self.upstream.requests, [])

    def test_same_case_id_uses_each_collections_preview_and_exported_body(self):
        previews = {}
        datasets = {}
        for collection_id in ("baseline", "cwe_specific"):
            status, dataset = self.request("/api/dataset?" + urlencode({"collection_id": collection_id}))
            self.assertEqual(status, 200)
            datasets[collection_id] = {row["id"]: row for row in dataset["cases"]}
            preview = datasets[collection_id][self.case_id]["body"]
            exported_path = DATA_ROOT / "collections" / collection_id / "inputs/requests" / (self.case_id + ".json")
            self.assertEqual(preview, json.loads(exported_path.read_text(encoding="utf-8")))
            previews[collection_id] = preview
            status, result = self.run_case(collection_id=collection_id)
            self.assertEqual((status, result["status"]), (200, "ok"))
            self.assertEqual(result["collection_id"], collection_id)
            self.assertEqual(result["id"], self.case_id)
            self.assertEqual(self.upstream.requests[-1]["body"], {**preview, "model": "custom-model"})
            self.assertNotIn("collection_id", self.upstream.requests[-1]["body"])

        self.assertEqual(set(datasets["baseline"]), set(datasets["cwe_specific"]))
        for case_id, baseline_case in datasets["baseline"].items():
            specific_case = datasets["cwe_specific"][case_id]
            self.assertEqual(baseline_case["code"], specific_case["code"])
            self.assertEqual(baseline_case["expected"], specific_case["expected"])
            self.assertEqual(specific_case["body"]["state"]["scope"], "target_cwe_only")
            self.assertEqual(specific_case["body"]["state"]["target_cwe"], specific_case["focus_cwe"])
        self.assertEqual(previews["baseline"]["state"]["scope"], "snippet_under_assumptions")
        self.assertIsNone(previews["baseline"]["state"]["target_cwe"])
        self.assertNotEqual(previews["baseline"]["questions"], previews["cwe_specific"]["questions"])

    def test_failed_run_retains_requested_collection_identity(self):
        self.upstream.response = {"answers": {}}
        body = self.assert_failed_run(self.run_case(collection_id="cwe_specific"))
        self.assertEqual(body["collection_id"], "cwe_specific")

    def test_default_and_explicit_direct_modes_ignore_proxy_environment(self):
        with self.proxy_environment():
            for config in ({}, {"proxy_mode": "direct"}):
                with self.subTest(config=config):
                    self.upstream.requests = []
                    status, body = self.run_case(**config)
                    self.assertEqual((status, body["status"]), (200, "ok"))
                    self.assertEqual(body["score"], 0.8)
                    self.assertEqual(len(self.upstream.requests), 1)
                    self.assertEqual(self.upstream.requests[0]["path"], "/v1/systemone/")
                    self.assertEqual(self.proxy.requests, [])

    def test_system_proxy_mode_reports_the_proxy_504(self):
        with self.proxy_environment():
            body = self.assert_failed_run(self.run_case(proxy_mode="system"))
        self.assertEqual(body["http_status"], 504)
        self.assertEqual(body["raw_response"], {"error": "local proxy generated 504"})
        self.assertEqual(len(self.proxy.requests), 1)
        self.assertEqual(self.proxy.requests[0]["path"], self.endpoint)
        self.assertEqual(self.upstream.requests, [])

    def test_system_proxy_mode_honors_no_proxy_for_target(self):
        with self.proxy_environment(no_proxy="127.0.0.1"):
            status, body = self.run_case(proxy_mode="system")
        self.assertEqual((status, body["status"]), (200, "ok"))
        self.assertEqual(body["score"], 0.8)
        self.assertEqual(len(self.upstream.requests), 1)
        self.assertEqual(self.proxy.requests, [])

    def test_invalid_proxy_modes_are_rejected_before_network(self):
        for mode in ("auto", "", "DIRECT", None, True, 1, [], {}):
            with self.subTest(proxy_mode=mode):
                status, _body = self.run_case(proxy_mode=mode)
                self.assertEqual(status, 400)
        self.assertEqual(self.upstream.requests, [])
        self.assertEqual(self.proxy.requests, [])

    def test_wire_body_is_direct_request_without_gold_or_metadata(self):
        status, body = self.run_case(api_key="local-test-key")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["id"], self.case_id)
        self.assertEqual(body["collection_id"], "baseline")
        self.assertEqual(body["verdict"], "vulnerable")
        self.assertEqual(body["score"], 0.8)
        self.assertEqual(body["http_status"], 200)
        self.assertEqual(body["response_model"], "mock-jev")
        self.assertGreaterEqual(body["latency_ms"], 0)
        self.assertEqual(len(self.upstream.requests), 1)
        sent = self.upstream.requests[0]
        self.assertEqual(sent["path"], "/v1/systemone/")
        self.assertEqual(sent["headers"].get("Authorization"), "Bearer local-test-key")
        expected = json.loads((BASELINE_ROOT / "inputs/requests" / (self.case_id + ".json")).read_text(encoding="utf-8"))
        expected["model"] = "custom-model"
        self.assertEqual(sent["body"], expected)
        self.assertEqual(set(sent["body"]), {"state", "model", "questions"})
        self.assertEqual(set(sent["body"]["state"]), {"language", "scope", "target_cwe", "context", "code"})
        self.assertEqual(sent["body"]["state"]["code"], self.input_cases[0]["code"])
        for forbidden in ("id", "collection_id", "verdict", "rationale", "evidence", "pair_id", "provenance"):
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
        status, _body = self.request("/api/run", {"collection_id": "baseline", "case_id": "unknown", "config": {"endpoint": self.endpoint, "model": "custom"}})
        self.assertEqual(status, 400)
        self.assertEqual(self.upstream.requests, [])

    def test_cross_origin_wrong_host_and_missing_header_are_rejected(self):
        payload = {"collection_id": "baseline", "case_id": self.case_id, "config": {"endpoint": self.endpoint, "model": "custom"}}
        for headers, trusted in (({"Origin": "https://unrelated.invalid"}, True), ({"Host": "unrelated.invalid"}, True), ({}, False)):
            with self.subTest(headers=headers, trusted=trusted):
                status, _body = self.request("/api/run", payload, headers=headers, trusted=trusted)
                self.assertEqual(status, 403)
        self.assertEqual(self.upstream.requests, [])

    def test_same_origin_request_is_allowed(self):
        payload = {"collection_id": "baseline", "case_id": self.case_id, "config": {"endpoint": self.endpoint, "model": "custom", "timeout": 2}}
        status, body = self.request("/api/run", payload, headers={"Origin": self.base_url})
        self.assertEqual((status, body["status"]), (200, "ok"))

    def test_scoring_single_case_allows_incomplete_contrast_pair(self):
        row = next(row for row in self.gold if row.get("pair_id"))
        status, body = self.request("/api/score", {"collection_id": "baseline", "case_ids": [row["id"]], "predictions": [{"collection_id": "baseline", "id": row["id"], "verdict": row["verdict"]}]})
        self.assertEqual(status, 200)
        self.assertEqual(body["overall"]["total"], 1)
        self.assertEqual(body["overall"]["primary"]["strict_accuracy"], 1)
        self.assertEqual(body["contrast_pairs"]["total"], 0)

    def test_score_uses_the_selected_collections_scope_and_identity(self):
        row = self.gold[0]
        for collection_id, scope in (("baseline", "snippet_under_assumptions"), ("cwe_specific", "target_cwe_only")):
            with self.subTest(collection_id=collection_id):
                prediction = {"collection_id": collection_id, "id": row["id"], "verdict": row["verdict"]}
                status, body = self.request("/api/score", {"collection_id": collection_id, "case_ids": [row["id"]], "predictions": [prediction]})
                self.assertEqual(status, 200)
                self.assertEqual(body["collection_id"], collection_id)
                self.assertEqual(body["overall"]["total"], 1)
                self.assertEqual(body["overall"]["primary"]["strict_accuracy"], 1)
                self.assertEqual(set(body["by"]["scope"]), {scope})

    def test_score_rejects_a_real_result_from_the_other_collection(self):
        status, baseline_result = self.run_case(collection_id="baseline")
        self.assertEqual(status, 200)
        status, _body = self.request("/api/score", {"collection_id": "cwe_specific", "case_ids": [self.case_id], "predictions": [baseline_result]})
        self.assertEqual(status, 400)

    def test_score_requires_every_predictions_collection_to_match(self):
        valid = {"collection_id": "baseline", "id": self.case_id, "verdict": "vulnerable"}
        for collection_id in (None, "cwe_specific", "unknown", [], {}, 1):
            with self.subTest(collection_id=collection_id):
                prediction = {**valid, "collection_id": collection_id}
                status, _body = self.request("/api/score", {"collection_id": "baseline", "case_ids": [self.case_id], "predictions": [prediction]})
                self.assertEqual(status, 400)
        missing = {"id": self.case_id, "verdict": "vulnerable"}
        status, _body = self.request("/api/score", {"collection_id": "baseline", "case_ids": [self.case_id], "predictions": [missing]})
        self.assertEqual(status, 400)

    def test_empty_predictions_count_as_missing_in_selected_collection(self):
        for collection_id in ("baseline", "cwe_specific"):
            with self.subTest(collection_id=collection_id):
                status, body = self.request("/api/score", {"collection_id": collection_id, "case_ids": [self.case_id], "predictions": []})
                self.assertEqual(status, 200)
                self.assertEqual(body["collection_id"], collection_id)
                self.assertEqual(body["overall"]["counts"]["missing"], 1)
                self.assertEqual(body["overall"]["primary"]["strict_accuracy"], 0)

    def test_missing_prediction_is_in_accuracy_denominator(self):
        rows = self.gold[:2]
        status, body = self.request("/api/score", {"collection_id": "baseline", "case_ids": [row["id"] for row in rows], "predictions": [{"collection_id": "baseline", "id": rows[0]["id"], "verdict": rows[0]["verdict"]}]})
        self.assertEqual(status, 200)
        self.assertEqual(body["overall"]["total"], 2)
        self.assertEqual(body["overall"]["counts"]["missing"], 1)
        self.assertEqual(body["overall"]["primary"]["strict_accuracy"], 0.5)
        self.assertEqual(body["overall"]["binary_coverage"], 0.5)

    def test_unknown_duplicate_and_out_of_selection_predictions_are_rejected(self):
        prediction = {"collection_id": "baseline", "id": self.case_id, "verdict": "vulnerable"}
        invalid = [[{"collection_id": "baseline", "id": "unknown", "verdict": "vulnerable"}], [prediction, prediction], [{"collection_id": "baseline", "id": self.gold[1]["id"], "verdict": "vulnerable"}]]
        for predictions in invalid:
            with self.subTest(predictions=predictions):
                status, _body = self.request("/api/score", {"collection_id": "baseline", "case_ids": [self.case_id], "predictions": predictions})
                self.assertEqual(status, 400)

    def test_static_route_allowlist_blocks_gold_and_traversal(self):
        for path in ("/gold/answers.jsonl", "/code_vulnerability/gold/answers.jsonl", "/../code_vulnerability/gold/answers.jsonl", "/%2e%2e/code_vulnerability/gold/answers.jsonl", "/collections/baseline/gold/answers.jsonl", "/code_vulnerability/collections/cwe_specific/gold/answers.jsonl", "/server.py"):
            with self.subTest(path=path):
                status, body = self.request(path)
                self.assertIn(status, (403, 404))
                self.assertNotIn(self.gold[0]["rationale"], str(body))


if __name__ == "__main__":
    unittest.main()
