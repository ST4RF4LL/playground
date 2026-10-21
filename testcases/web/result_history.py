"""Compact, versioned evaluation history; never stores individual responses."""
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import uuid

from decision_protocol import build_request, DEFAULT_MODEL, question_key, verdict_labels
from score import evaluate
from context_budget import CONTEXT_LIMIT_TOKENS


class HistoryStorageError(ValueError):
    pass


def reject_constant(value):
    raise ValueError("历史记录含非标准 JSON 数值。")


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def collection_fingerprint(cases, gold, profile):
    digest = hashlib.sha256()
    for key in sorted(cases):
        body = build_request(cases[key], DEFAULT_MODEL, profile)
        body.pop("model")
        digest.update(fingerprint({"id": key, "request": body, "gold": gold[key]}).encode("ascii"))
    return digest.hexdigest()


def identifier(value, name):
    if not isinstance(value, str):
        raise ValueError(name + " 必须为 UUID。")
    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise ValueError(name + " 必须为 UUID。") from exc


def timestamp(value, name):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError(name + " 必须为带时区的 ISO 时间。")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("missing timezone")
        return parsed.astimezone(timezone.utc)
    except ValueError as exc:
        raise ValueError(name + " 必须为带时区的 ISO 时间。") from exc


def compact_summary(summary):
    counts = summary["counts"]
    primary = summary["primary"]
    return {
        "counts": {**{key: counts[key] for key in ("tp", "tn", "fp", "fn")},
                   "error": counts["invalid"], "missing": counts["missing"],
                   "correct": counts["tp"] + counts["tn"], "total": summary["total"],
                   "actual_positive": summary["actual_positive"],
                   "actual_negative": summary["actual_negative"]},
        "metrics": {"accuracy": primary["strict_accuracy"], "precision": primary["precision"],
                    "recall": primary["strict_recall"], "specificity": primary["strict_specificity"],
                    "f1": primary["strict_f1"], "balanced_accuracy": primary["strict_balanced_accuracy"],
                    "binary_coverage": summary["binary_coverage"]},
    }


def make_record(data, collection, config):
    """Recompute aggregate scores from the selected gold and minimal outcomes."""
    meta = collection["metadata"]
    collection_id = meta["id"]
    if data.get("collection_fingerprint") != meta["fingerprint"]:
        raise ValueError("集合内容已变化；该记录不能按当前集合答案保存，请保留原批次资料。")
    run_id = identifier(data.get("run_id"), "run_id")
    batch_id = identifier(data.get("batch_id"), "batch_id")
    started = timestamp(data.get("started_at"), "started_at")
    finished = timestamp(data.get("finished_at"), "finished_at")
    if finished < started:
        raise ValueError("结束时间不能早于开始时间。")
    status = data.get("status")
    if status not in {"completed", "stopped", "interrupted"}:
        raise ValueError("运行状态必须为 completed、stopped 或 interrupted。")
    ids = data.get("case_ids")
    if (not isinstance(ids, list) or not ids or len(ids) > len(collection["cases"])
            or not all(isinstance(key, str) and key in collection["gold"] for key in ids)
            or len(set(ids)) != len(ids)):
        raise ValueError("记录的用例 ID 必须非空、有效且不重复。")
    source_predictions = data.get("predictions")
    if not isinstance(source_predictions, list) or len(source_predictions) > len(ids):
        raise ValueError("predictions 必须为不超出选定范围的数组。")
    labels = verdict_labels(collection["profile"])
    selected = set(ids)
    predictions, seen = [], set()
    for row in source_predictions:
        if not isinstance(row, dict) or row.get("collection_id") != collection_id:
            raise ValueError("记录中的预测不能跨测试集合。")
        key = row.get("id")
        if not isinstance(key, str) or key not in selected or key in seen:
            raise ValueError("记录中的预测 ID 无效、重复或不在选定范围。")
        seen.add(key)
        if row.get("status") == "error":
            predictions.append({"id": key})
        elif row.get("status") == "ok":
            score = row.get("score")
            if type(score) not in (int, float) or not 0 <= score <= 1:
                raise ValueError("成功预测必须包含 0–1 的有限分值。")
            predictions.append({"id": key, "verdict": labels[0] if score >= config["threshold"] else labels[1]})
        else:
            raise ValueError("预测状态只能为 ok 或 error。")
    if status == "completed" and len(seen) != len(ids):
        raise ValueError("已完成记录必须包含全部选定用例的结果；未完成请标记为停止或中断。")
    rows = [dict(collection["gold"][key]) for key in ids]
    pair_counts = Counter(row.get("pair_id") for row in rows if row.get("pair_id"))
    for row in rows:
        if row.get("pair_id") and pair_counts[row["pair_id"]] != 2:
            row["pair_id"] = None
    report = evaluate(rows, predictions, collection_id, labels)
    category = "risk_source" if meta["task_type"] == "agent_safety" else "focus_cwe"
    return {
        "run_id": run_id, "batch_id": batch_id, "model": config["model"],
        "model_revision": config["model_revision"], "collection_id": collection_id,
        "collection_name": meta["name"], "collection_fingerprint": meta["fingerprint"],
        "task_type": meta["task_type"], "evaluation_direction": meta["evaluation_direction"],
        "request_profile": collection["profile"], "question_key": question_key(collection["profile"]),
        "positive_label": labels[0], "negative_label": labels[1], "scorer_version": report["scorer_version"],
        "context_limit_tokens": CONTEXT_LIMIT_TOKENS,
        "started_at": started.isoformat(), "finished_at": finished.isoformat(), "status": status,
        "threshold": config["threshold"], "timeout": config["timeout"], "proxy_mode": config["proxy_mode"],
        "endpoint_fingerprint": config["endpoint_fingerprint"],
        "scope": "full" if len(ids) == len(collection["cases"]) else "subset",
        "selected_count": len(ids), "collection_count": len(collection["cases"]),
        "selection_fingerprint": fingerprint(sorted(ids)),
        **compact_summary(report["overall"]),
        "pairs": {key: report["contrast_pairs"][key] for key in ("total", "both_correct", "both_binary", "both_correct_rate")},
        "by_category": {key: compact_summary(value) for key, value in report["by"][category].items()},
    }


class HistoryStore:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()

    @contextmanager
    def locked(self):
        # The file lock also serializes two testbench processes using one file.
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.with_suffix(self.path.suffix + ".lock").open("a+b") as handle:
                if os.name == "nt":
                    import msvcrt
                    if handle.tell() == 0:
                        handle.write(b"\0")
                        handle.flush()
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    if os.name == "nt":
                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _read(self):
        if not self.path.exists():
            return {"schema_version": 1, "models": {}}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"), parse_constant=reject_constant)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise HistoryStorageError("历史记录无法解析，原文件未被覆盖。") from exc
        if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("models"), dict):
            raise HistoryStorageError("历史记录格式无效，原文件未被覆盖。")
        for collections in data["models"].values():
            if not isinstance(collections, dict):
                raise HistoryStorageError("历史记录结构无效，原文件未被覆盖。")
            for records in collections.values():
                if not isinstance(records, list) or not all(isinstance(r, dict) and isinstance(r.get("run_id"), str) for r in records):
                    raise HistoryStorageError("历史记录条目无效，原文件未被覆盖。")
        return data

    def read(self):
        with self.locked():
            return self._read()

    def append(self, record):
        with self.locked():
            data = self._read()
            for collections in data["models"].values():
                for records in collections.values():
                    for previous in records:
                        if previous["run_id"] == record["run_id"]:
                            if previous != record:
                                raise ValueError("run_id 已用于不同记录；重试时须保持记录不变。")
                            return previous, False
            data["models"].setdefault(record["model"], {}).setdefault(record["collection_id"], []).append(record)
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.path.parent,
                                                 prefix=".history-", suffix=".tmp", delete=False) as handle:
                    temporary = Path(handle.name)
                    json.dump(data, handle, ensure_ascii=False, indent=2, allow_nan=False)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.path)
            finally:
                if temporary and temporary.exists():
                    temporary.unlink()
            return record, True
