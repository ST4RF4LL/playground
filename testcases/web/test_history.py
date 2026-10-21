"""Summary-history integration checks; no model or external network is used."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener
from uuid import uuid4

from test_server import load_server_module


class TestResultHistory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = TemporaryDirectory()
        cls.history_path = Path(cls.temporary.name) / "results" / "history.json"
        cls.module = load_server_module()
        cls.app = cls.module.create_server(port=0, history_path=cls.history_path)
        cls.thread = threading.Thread(target=cls.app.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.app.server_port}"
        cls.collection = cls.app.collections["baseline"]
        cls.positive = [row["id"] for row in cls.collection["gold"].values()
                        if row["verdict"] == "vulnerable"]
        cls.negative = [row["id"] for row in cls.collection["gold"].values()
                        if row["verdict"] == "not_vulnerable"]

    @classmethod
    def tearDownClass(cls):
        cls.app.shutdown()
        cls.app.server_close()
        cls.thread.join(timeout=2)
        cls.temporary.cleanup()

    def request(self, path="/api/history", payload=None):
        request = Request(
            self.base_url + path,
            data=None if payload is None else json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Testbench-Request": "1"},
        )
        # Each worker has its own opener; environment proxy settings cannot affect tests.
        opener = build_opener(ProxyHandler({}))
        try:
            response = opener.open(request, timeout=10)
        except HTTPError as error:
            response = error
        with response:
            return response.status, json.load(response)

    def prediction(self, case_id, score=0.9, status="ok", **extra):
        result = {"id": case_id, "collection_id": "baseline", "status": status, **extra}
        if status == "ok":
            result["score"] = score
        return result

    def payload(self, **extra):
        return {
            "run_id": str(uuid4()), "batch_id": str(uuid4()),
            "collection_id": "baseline",
            "collection_fingerprint": self.collection["metadata"]["fingerprint"],
            "case_ids": [self.positive[0], self.negative[0]],
            "predictions": [self.prediction(self.positive[0]), self.prediction(self.negative[0], 0.1)],
            "config": {"endpoint": "http://127.0.0.1:9/v1/systemone/", "model": self.id(),
                       "threshold": 0.5, "timeout": 60, "proxy_mode": "direct"},
            "started_at": "2026-10-21T10:00:00.000Z",
            "finished_at": "2026-10-21T10:00:01.000Z", "status": "completed", **extra,
        }

    def saved_record(self, payload):
        status, body = self.request(payload=payload)
        self.assertEqual(status, 200, body)
        self.assertTrue(body["created"])
        return body["record"]

    def test_stopped_run_recomputes_counts_and_keeps_errors_and_missing_distinct(self):
        ids = self.positive[:4] + self.negative[:3]
        predictions = [
            self.prediction(self.positive[0], 0.8, verdict="not_vulnerable"),
            self.prediction(self.negative[0], 0.1),
            self.prediction(self.negative[1], 0.8),
            self.prediction(self.positive[1], 0.1),
            self.prediction(self.positive[2], status="error"),
        ]
        record = self.saved_record(self.payload(case_ids=ids, predictions=predictions, status="stopped"))
        self.assertEqual(record["counts"], {
            "tp": 1, "tn": 1, "fp": 1, "fn": 1, "error": 1, "missing": 2,
            "correct": 2, "total": 7, "actual_positive": 4, "actual_negative": 3,
        })
        self.assertAlmostEqual(record["metrics"]["accuracy"], 2 / 7)
        self.assertAlmostEqual(record["metrics"]["binary_coverage"], 4 / 7)
        self.assertEqual(record["status"], "stopped")
        self.assertEqual(sum(group["counts"]["total"] for group in record["by_category"].values()), 7)

    def test_completed_run_can_have_errors_but_history_never_stores_raw_payloads_or_credentials(self):
        payload = self.payload()
        payload["config"].update({
            "endpoint": "http://127.0.0.1:9/v1/systemone/?token=endpoint-secret-marker",
            "api_key": "history-api-key-secret-marker", "model_revision": "weights-sha256-example",
        })
        payload["predictions"] = [
            self.prediction(key, status="error", raw_response={"secret": "raw-response-marker"},
                            error="upstream-detail-marker", api_key="prediction-key-marker")
            for key in payload["case_ids"]
        ]
        payload["raw_response"] = "top-level-response-marker"
        record = self.saved_record(payload)
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["counts"]["error"], 2)
        self.assertEqual(record["counts"]["missing"], 0)
        self.assertEqual(record["metrics"]["accuracy"], 0)
        status, history = self.request()
        self.assertEqual(status, 200)
        self.assertEqual(history["schema_version"], 1)
        self.assertIn(record, history["models"][payload["config"]["model"]]["baseline"])
        text = self.history_path.read_text(encoding="utf-8") + json.dumps(history)
        for forbidden in ("endpoint-secret-marker", "history-api-key-secret-marker", "raw-response-marker",
                          "upstream-detail-marker", "prediction-key-marker", "top-level-response-marker",
                          "raw_response", "predictions", payload["config"]["endpoint"]):
            self.assertNotIn(forbidden, text)

    def test_concurrent_append_is_lossless_and_retry_is_idempotent(self):
        payloads = [self.payload() for _ in range(6)]
        with ThreadPoolExecutor(max_workers=4) as workers:
            responses = list(workers.map(lambda body: self.request(payload=body), payloads + [deepcopy(payloads[0])]))
        self.assertTrue(all(status == 200 for status, _ in responses), responses)
        self.assertEqual(sum(body["created"] for _, body in responses), 6)
        _, history = self.request()
        records = history["models"][payloads[0]["config"]["model"]]["baseline"]
        self.assertEqual({row["run_id"] for row in records}, {row["run_id"] for row in payloads})
        self.assertEqual(len(records), 6)
        # The on-disk file remains valid JSON and contains every successful append.
        self.assertEqual(json.loads(self.history_path.read_text(encoding="utf-8")), history)
        changed = deepcopy(payloads[0])
        changed["config"]["threshold"] = 0.95
        self.assertEqual(self.request(payload=changed)[0], 400)

    def test_invalid_or_cross_collection_records_cannot_be_saved(self):
        valid = self.payload()
        malformed = []
        incomplete = deepcopy(valid)
        incomplete["predictions"].pop()
        malformed.append(incomplete)
        stale = deepcopy(valid)
        stale["collection_fingerprint"] = "0" * 64
        malformed.append(stale)
        cross_collection = deepcopy(valid)
        cross_collection["predictions"][0]["collection_id"] = "cwe_specific"
        malformed.append(cross_collection)
        duplicate = deepcopy(valid)
        duplicate["predictions"].append(deepcopy(duplicate["predictions"][0]))
        malformed.append(duplicate)
        unselected = deepcopy(valid)
        unselected["predictions"][0]["id"] = self.positive[1]
        malformed.append(unselected)
        boolean_score = deepcopy(valid)
        boolean_score["predictions"][0]["score"] = True
        malformed.append(boolean_score)
        duplicate_scope = deepcopy(valid)
        duplicate_scope["case_ids"].append(duplicate_scope["case_ids"][0])
        malformed.append(duplicate_scope)
        for payload in malformed:
            with self.subTest(payload=payload):
                status, body = self.request(payload=payload)
                self.assertEqual(status, 400, body)
        _, history = self.request()
        self.assertNotIn(valid["config"]["model"], history["models"])

    def test_endpoint_fingerprint_supports_summary_only_retry_without_raw_configuration(self):
        payload = self.payload()
        endpoint = payload["config"].pop("endpoint")
        payload["config"]["endpoint_fingerprint"] = hashlib.sha256(endpoint.encode("utf-8")).hexdigest()
        record = self.saved_record(payload)
        status, retry = self.request(payload=deepcopy(payload))
        self.assertEqual(status, 200, retry)
        self.assertFalse(retry["created"])
        self.assertEqual(retry["record"], record)

    def test_corrupt_history_is_reported_and_never_overwritten(self):
        self.saved_record(self.payload())
        original = self.history_path.read_bytes()
        try:
            for corrupt in (
                b'{"schema_version": 1, "models": ',
                b'{"schema_version":1,"models":{"model":{"baseline":[{"run_id":"old","value":NaN}]}}}',
            ):
                with self.subTest(corrupt=corrupt):
                    self.history_path.write_bytes(corrupt)
                    self.assertEqual(self.request()[0], 503)
                    self.assertEqual(self.request(payload=self.payload())[0], 503)
                    self.assertEqual(self.history_path.read_bytes(), corrupt)
        finally:
            self.history_path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
