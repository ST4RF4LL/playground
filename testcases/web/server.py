#!/usr/bin/env python3
"""Local decision-model testbench. Python standard library; no external service on startup."""
import argparse
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import math
from pathlib import Path
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
DATASET_ROOT = HERE.parent / "code_vulnerability"
sys.path.insert(0, str(DATASET_ROOT / "scripts"))
from decision_protocol import DEFAULT_MODEL, build_request, parse_noul, question_key, verdict_labels
from context_budget import CONTEXT_LIMIT_TOKENS, request_budget
from score import evaluate, indexed, read_jsonl

DEFAULTS = {
    "endpoint": "https://api.typesafe.ai/v1/systemone",
    "model": DEFAULT_MODEL,
    "threshold": 0.5,
    "timeout": 60,
    "proxy_mode": "direct",
    "context_limit_tokens": CONTEXT_LIMIT_TOKENS,
}
MAX_REQUEST = 2 * 1024 * 1024
MAX_RESPONSE = 2 * 1024 * 1024
DEFAULT_COLLECTION_ID = "baseline"


def redact(value, secret):
    """The chosen API key never returns to the UI, even if an upstream echoes it."""
    if not secret:
        return value
    if isinstance(value, str):
        return value.replace(secret, "[redacted]")
    if isinstance(value, dict):
        return {redact(k, secret): redact(v, secret) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, secret) for v in value]
    return value


def finite_number(value, name, low, high):
    if type(value) not in (int, float) or not low <= value <= high or not math.isfinite(value):
        raise ValueError(f"{name} 必须是 {low} 到 {high} 之间的数字。")
    return float(value)


def validate_config(config):
    if not isinstance(config, dict):
        raise ValueError("缺少接口配置。")
    endpoint = config.get("endpoint", "")
    model = config.get("model", "")
    api_key = config.get("api_key", "")
    proxy_mode = config.get("proxy_mode", DEFAULTS["proxy_mode"])
    if not isinstance(proxy_mode, str) or proxy_mode not in {"direct", "system"}:
        raise ValueError("代理模式必须为 direct（直连）或 system（环境 / 系统代理）。")
    if not isinstance(endpoint, str) or not endpoint.strip() or len(endpoint) > 4096:
        raise ValueError("请输入完整的 HTTP(S) API 地址。")
    endpoint = endpoint.strip()
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in endpoint):
        raise ValueError("API 地址包含无效字符。")
    url = urllib.parse.urlsplit(endpoint)
    if (url.scheme not in {"http", "https"} or not url.hostname or url.username is not None
            or url.password is not None or url.fragment):
        raise ValueError("API 地址须为完整 HTTP(S) URL，且不能包含用户凭据或片段。")
    try:
        port = url.port
    except ValueError as exc:
        raise ValueError("API 地址端口无效。") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("API 地址端口无效。")
    if not isinstance(model, str) or not model.strip() or len(model) > 256:
        raise ValueError("请输入模型名称（最多 256 字符）。")
    if any(ord(ch) < 32 for ch in model):
        raise ValueError("模型名称包含无效字符。")
    if not isinstance(api_key, str) or len(api_key) > 8192:
        raise ValueError("API Key 格式无效。")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in api_key):
        raise ValueError("API Key 不能包含换行或控制字符。")
    # HTTP header values are encoded as Latin-1 by the stdlib transport.
    try:
        api_key.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise ValueError("API Key 包含无法用于 HTTP 请求头的字符。") from exc
    return {
        "endpoint": endpoint, "model": model.strip(), "api_key": api_key.strip(),
        "threshold": finite_number(config.get("threshold", 0.5), "判定阈值", 0, 1),
        "timeout": finite_number(config.get("timeout", 60), "请求超时（秒）", 1, 300),
        "proxy_mode": proxy_mode,
    }


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def reject_json_constant(value):
    raise ValueError("上游包含非标准 JSON 数值。")


def call_model(case, config, profile="baseline"):
    started = time.perf_counter()
    proxy_mode = config.get("proxy_mode", DEFAULTS["proxy_mode"])
    body = build_request(case, config["model"], profile=profile)
    budget = request_budget(body)
    result = {"id": case["id"], "status": "error", "http_status": None,
              "response_model": None, "raw_response": None, "proxy_mode": proxy_mode,
              "context_budget": budget}
    try:
        if not budget["within_budget"]:
            raise ValueError(
                f"上下文保守估算上界 {budget['estimated_tokens_upper_bound']:,} 超过 "
                f"256K（{budget['limit_tokens']:,} token）预算；未发送，未截断输入。"
                "估算按 state/questions JSON 的 UTF-8 字节加 schema 余量计算，并非精确 token 数。"
            )
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if config["api_key"]:
            headers["Authorization"] = "Bearer " + config["api_key"]
        req = urllib.request.Request(config["endpoint"],
                                     data=json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8"),
                                     headers=headers, method="POST")
        # An explicit empty handler disables environment AND OS proxy discovery.
        proxy_handler = urllib.request.ProxyHandler({}) if proxy_mode == "direct" else urllib.request.ProxyHandler()
        opener = urllib.request.build_opener(proxy_handler, NoRedirect())
        try:
            response = opener.open(req, timeout=config["timeout"])
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            result["http_status"] = response.status
            payload = response.read(MAX_RESPONSE + 1)
        if len(payload) > MAX_RESPONSE:
            raise ValueError("上游响应超过 2 MiB，已停止读取。")
        text = payload.decode("utf-8", errors="replace")
        try:
            parsed = json.loads(text, parse_constant=reject_json_constant)
        except (ValueError, RecursionError):
            parsed = None
        result["raw_response"] = redact(parsed if parsed is not None else text, config["api_key"])
        if not 200 <= result["http_status"] < 300:
            if 300 <= result["http_status"] < 400:
                raise ValueError(f"上游返回 HTTP {result['http_status']} 重定向；请在配置中填写最终 API 地址。")
            if result["http_status"] == 504:
                mode = "直连（未使用代理）" if proxy_mode == "direct" else "使用环境 / 系统代理配置"
                raise ValueError(f"上游返回 HTTP 504（网关超时）；当前连接方式：{mode}。请查看原始响应；504 也可能来自接口自身的网关。")
            raise ValueError(f"上游返回 HTTP {result['http_status']}；请查看原始响应。")
        if not isinstance(parsed, dict):
            raise ValueError("上游未返回 JSON 对象；请确认使用 /v1/systemone 兼容接口。")
        score = parse_noul(parsed, question_key(profile))
        positive, negative = verdict_labels(profile)
        result.update({"status": "ok", "score": score,
                       "verdict": positive if score >= config["threshold"] else negative,
                       "response_model": parsed.get("model") if isinstance(parsed.get("model"), str) else None})
    except (TimeoutError, socket.timeout):
        result["error"] = f"请求超时（{config['timeout']:g} 秒）。"
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (TimeoutError, socket.timeout)):
            result["error"] = f"请求超时（{config['timeout']:g} 秒）。"
        else:
            result["error"] = "无法连接上游接口：" + str(exc.reason)
    except (ValueError, OSError, UnicodeError, http.client.HTTPException) as exc:
        result["error"] = str(exc)
    finally:
        result["latency_ms"] = round((time.perf_counter() - started) * 1000)
    return redact(result, config["api_key"])


class BenchServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address):
        self.collections = {}
        roots = list((DATASET_ROOT / "collections").iterdir())
        agent_collections = DATASET_ROOT.parent / "agent_safety" / "collections"
        if agent_collections.is_dir():
            roots.extend(agent_collections.iterdir())
        for root in sorted(roots):
            if not root.is_dir() or root.name.startswith("."):
                continue
            manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            meta = manifest.get("collection")
            if (not isinstance(meta, dict) or meta.get("id") != root.name
                    or not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", root.name)
                    or any(not isinstance(meta.get(key), str) or not meta[key].strip()
                           for key in ("name", "description", "request_profile"))):
                raise ValueError(f"测试集合 {root.name} 的元数据无效。")
            profile = meta["request_profile"]
            if root.name in self.collections:
                raise ValueError(f"重复的测试集合 ID：{root.name}")
            cases = indexed(read_jsonl(root / "inputs/cases.jsonl"), "cases")
            gold = indexed(read_jsonl(root / "gold/answers.jsonl"), "gold")
            if not cases or set(cases) != set(gold) or manifest.get("count") != len(cases):
                raise ValueError(f"测试集合 {root.name} 的用例、答案或数量不一致。")
            # Validate the shared request builder on startup; preview and sending
            # must use the same profile and the same input-only fields.
            for case in cases.values():
                build_request(case, DEFAULT_MODEL, profile=profile)
            metadata = {key: meta.get(key) for key in ("id", "name", "description", "request_profile", "cloned_from")}
            agent_task = profile == "agent_safety_v1"
            metadata.update({
                "task_type": "agent_safety" if agent_task else "code_vulnerability",
                "evaluation_direction": meta.get("evaluation_direction") or "代码漏洞识别 · " + meta["name"],
                "question_key": question_key(profile),
                "positive_label": verdict_labels(profile)[0],
                "negative_label": verdict_labels(profile)[1],
                "positive_label_text": "不安全行为" if agent_task else "有漏洞",
                "negative_label_text": "安全行为" if agent_task else "无目标漏洞",
                "input_label": "交互轨迹" if agent_task else "源代码",
                "category_label": "风险类别" if agent_task else "漏洞类别",
            })
            if any(row.get("verdict") not in verdict_labels(profile) for row in gold.values()):
                raise ValueError(f"测试集合 {root.name} 的标签与评估方向不一致。")
            metadata["count"] = len(cases)
            self.collections[root.name] = {"metadata": metadata, "cases": cases,
                                           "gold": gold, "manifest": manifest, "profile": profile}
        if DEFAULT_COLLECTION_ID not in self.collections:
            raise ValueError("缺少 baseline 测试集合，请重新构建数据。")
        self.upstream_slots = threading.BoundedSemaphore(4)
        super().__init__(address, BenchHandler)

    def collection(self, collection_id):
        # Resolve only IDs discovered at startup, never request-provided paths.
        if not isinstance(collection_id, str) or collection_id not in self.collections:
            raise ValueError("测试集合 ID 不存在或未指定。")
        return self.collections[collection_id]

    def collection_list(self):
        return [entry["metadata"] for entry in self.collections.values()]


class BenchHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        # No request configuration, keys, URLs, or payloads are written to logs.
        pass

    def reply(self, status, data, content_type="application/json; charset=utf-8"):
        if isinstance(data, (dict, list)):
            data = json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
        elif isinstance(data, str):
            data = data.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def trusted_request(self, mutation=False):
        port = self.server.server_port
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if self.headers.get("Host", "").lower() not in hosts:
            self.close_connection = True
            self.reply(403, {"error": "仅允许通过本机地址访问测试端。"})
            return False
        origin = self.headers.get("Origin")
        if origin and origin not in {"http://" + h for h in hosts}:
            self.close_connection = True
            self.reply(403, {"error": "不接受其他网页来源的请求。"})
            return False
        if mutation and self.headers.get("X-Testbench-Request") != "1":
            self.close_connection = True
            self.reply(403, {"error": "缺少测试端请求标记。"})
            return False
        return True

    def read_object(self):
        if self.headers.get_content_type() != "application/json":
            raise ValueError("Content-Type 必须为 application/json。")
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("不支持分块请求体。")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("请求长度无效。") from exc
        if not 0 < length <= MAX_REQUEST:
            raise ValueError("请求体为空或超过 2 MiB。")
        try:
            data = json.loads(self.rfile.read(length), parse_constant=lambda _: None)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise ValueError("请求体不是有效 JSON。") from exc
        if not isinstance(data, dict):
            raise ValueError("请求体必须为 JSON 对象。")
        return data

    def do_GET(self):
        if not self.trusted_request():
            return
        url = urllib.parse.urlsplit(self.path)
        path = url.path
        if path == "/api/collections":
            self.reply(200, {"collections": self.server.collection_list(),
                             "default_collection_id": DEFAULT_COLLECTION_ID})
            return
        if path == "/api/dataset":
            query = urllib.parse.parse_qs(url.query, keep_blank_values=True)
            ids = query.get("collection_id", [DEFAULT_COLLECTION_ID])
            try:
                if len(ids) != 1:
                    raise ValueError("请指定一个测试集合。")
                collection = self.server.collection(ids[0])
            except ValueError as exc:
                self.reply(400, {"error": str(exc)})
                return
            cases = []
            for key, row in collection["cases"].items():
                answer = collection["gold"][key]
                body = build_request(row, DEFAULT_MODEL, profile=collection["profile"])
                agent_task = collection["profile"] == "agent_safety_v1"
                preview = json.dumps({"tools": row["tools"], "trajectory": row["trajectory"]},
                                     ensure_ascii=False, indent=2) if agent_task else row["code"]
                cases.append({"id": key, "title": answer["title"], "language": row.get("language", "agent_trace"),
                              "focus_cwe": answer.get("risk_source") or answer.get("focus_cwe") or "未指定", "suite": answer["suite"],
                              "pair_id": answer.get("pair_id"),
                              "expected": answer["verdict"], "context": row["context"], "code": preview,
                              "body": body, "context_budget": request_budget(body)})
            self.reply(200, {"cases": cases, "manifest": collection["manifest"], "defaults": DEFAULTS,
                             "collection": collection["metadata"], "collections": self.server.collection_list(),
                             "default_collection_id": DEFAULT_COLLECTION_ID})
            return
        assets = {"/": ("index.html", "text/html; charset=utf-8"),
                  "/index.html": ("index.html", "text/html; charset=utf-8"),
                  "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                  "/style.css": ("style.css", "text/css; charset=utf-8"),
                  "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
                  "/static/style.css": ("style.css", "text/css; charset=utf-8")}
        if path not in assets:
            self.reply(404, {"error": "页面不存在。"})
            return
        name, mime = assets[path]
        try:
            self.reply(200, (HERE / "static" / name).read_bytes(), mime)
        except FileNotFoundError:
            self.reply(503, {"error": "页面文件尚未准备好。"})

    def do_OPTIONS(self):
        self.close_connection = True
        self.reply(403, {"error": "测试端不提供跨域代理访问。"})

    def do_POST(self):
        if not self.trusted_request(mutation=True):
            return
        path = urllib.parse.urlsplit(self.path).path
        if path not in {"/api/run", "/api/score"}:
            self.close_connection = True
            self.reply(404, {"error": "接口不存在。"})
            return
        try:
            data = self.read_object()
            collection_id = data.get("collection_id")
            collection = self.server.collection(collection_id)
            if path == "/api/run":
                key = data.get("case_id")
                if not isinstance(key, str) or key not in collection["cases"]:
                    raise ValueError("用例 ID 不存在。")
                config = validate_config(data.get("config"))
                if not self.server.upstream_slots.acquire(blocking=False):
                    self.reply(429, {"error": "当前请求过多，请稍后重试。"})
                    return
                try:
                    result = call_model(collection["cases"][key], config, profile=collection["profile"])
                finally:
                    self.server.upstream_slots.release()
                self.reply(200, {**result, "collection_id": collection_id})
                return
            ids = data.get("case_ids")
            predictions = data.get("predictions")
            if (not isinstance(ids, list) or not ids or len(ids) > len(collection["cases"])
                    or not all(isinstance(key, str) and key in collection["gold"] for key in ids)
                    or len(set(ids)) != len(ids)):
                raise ValueError("评分用例 ID 列表必须非空、有效且不重复。")
            if not isinstance(predictions, list) or not all(isinstance(r, dict) for r in predictions):
                raise ValueError("predictions 必须为对象数组。")
            if any(row.get("collection_id") != collection_id for row in predictions):
                raise ValueError("每条预测必须包含与本批相同的 collection_id，不能跨集合评分。")
            rows = [dict(collection["gold"][key]) for key in ids]
            pair_counts = Counter(r.get("pair_id") for r in rows if r.get("pair_id"))
            for row in rows:
                if row.get("pair_id") and pair_counts[row["pair_id"]] != 2:
                    row["pair_id"] = None
            metrics = evaluate(rows, predictions, collection_id=collection_id,
                               labels=verdict_labels(collection["profile"]))
            metrics["evaluation_direction"] = collection["metadata"]["evaluation_direction"]
            metrics["task_type"] = collection["metadata"]["task_type"]
            self.reply(200, metrics)
        except (ValueError, TypeError) as exc:
            self.close_connection = True
            self.reply(400, {"error": str(exc)})


def create_server(host="127.0.0.1", port=8765):
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("此测试端仅绑定本机地址。")
    return BenchServer((host, port))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("端口须为 0–65535（0 表示自动分配）。")
    try:
        server = create_server(port=args.port)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Decision Lab · http://127.0.0.1:{server.server_port}", flush=True)
    count = sum(len(entry["cases"]) for entry in server.collections.values())
    print(f"Loaded {len(server.collections)} collections / {count} case entries. API keys and results stay in memory. Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
