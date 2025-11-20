import os
import json
import re
import time
import datetime
from collections import Counter, deque

from flask import Flask, render_template, jsonify, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "logs.json")

app = Flask(__name__)

_config_cache = {}
_config_mtime = 0
metrics_history = deque(maxlen=50)  # sliding window for trends


def get_config():
    """Load JSON config with lightweight auto-reload on change."""
    global _config_cache, _config_mtime
    try:
        mtime = os.path.getmtime(CONFIG_PATH)
    except OSError:
        return _config_cache or {"logs": [], "ui": {}}

    if mtime != _config_mtime:
        with open(CONFIG_PATH, "r") as f:
            _config_cache = json.load(f)
        _config_mtime = mtime

    # Ensure minimal structure
    _config_cache.setdefault("logs", [])
    _config_cache.setdefault("ui", {})
    return _config_cache


def read_last_lines(path, max_lines=300):
    """
    Efficient-ish tail implementation: reads roughly the last `max_lines` lines
    without loading entire file.
    """
    lines = []
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            file_size = f.tell()
            block_size = 1024
            data = b""
            while file_size > 0 and len(lines) <= max_lines:
                read_size = min(block_size, file_size)
                file_size -= read_size
                f.seek(file_size)
                data = f.read(read_size) + data
                lines = data.splitlines()
    except (FileNotFoundError, PermissionError):
        return []

    # Keep only the last `max_lines`
    tail = lines[-max_lines:]
    return [l.decode("utf-8", errors="replace") for l in tail]


def normalize_log_line(line, log_conf):
    """
    Apply dynamic regex-based normalization as defined in JSON config.
    - Uses `pattern` for structured fields (named groups)
    - Uses `level_patterns` for severity classification
    """
    result = {
        "raw": line,
        "log_id": log_conf.get("id"),
        "level": "info"
    }

    pattern = log_conf.get("pattern")
    if pattern:
        try:
            m = re.match(pattern, line)
        except re.error:
            m = None

        if m:
            # Named groups become normalized fields
            result.update(m.groupdict())

    # Use message or raw line for level normalization
    message_for_level = result.get("message", line)
    level_patterns = log_conf.get("level_patterns", {})

    # First matching level wins (order in JSON matters)
    for level_name, level_regex in level_patterns.items():
        try:
            if re.search(level_regex, message_for_level):
                result["level"] = level_name
                break
        except re.error:
            # Invalid regex shouldn't kill processing
            continue

    return result


def build_metrics():
    """
    Aggregate metrics across all configured logs:
      - total events
      - per-level distribution
      - per-log distribution
      - lightweight history for trend chart
    """
    cfg = get_config()
    logs_cfg = [l for l in cfg["logs"] if l.get("enabled", True)]
    ui_cfg = cfg.get("ui", {})
    max_lines_per_log = int(ui_cfg.get("max_lines_per_log", 300))

    total_events = 0
    global_by_level = Counter()
    by_log = {}

    for log_conf in logs_cfg:
        log_id = log_conf.get("id")
        log_name = log_conf.get("name", log_id)
        path = log_conf.get("path")

        if not path:
            continue

        lines = read_last_lines(path, max_lines=max_lines_per_log)
        log_counter = Counter()
        event_count = 0

        for line in lines:
            ev = normalize_log_line(line, log_conf)
            lvl = ev.get("level", "info")
            log_counter[lvl] += 1
            global_by_level[lvl] += 1
            total_events += 1
            event_count += 1

        by_log[log_id] = {
            "id": log_id,
            "name": log_name,
            "path": path,
            "events": event_count,
            "by_level": dict(log_counter)
        }

    error_count = global_by_level.get("error", 0) + global_by_level.get("critical", 0)
    error_rate = float(error_count) / total_events if total_events > 0 else 0.0

    snapshot_time = time.time()
    snapshot = {
        "ts": snapshot_time,
        "total_events": total_events,
        "error_events": error_count
    }
    metrics_history.append(snapshot)

    # Prepare history for chart (simple rolling window)
    history_payload = []
    for h in metrics_history:
        dt = datetime.datetime.fromtimestamp(h["ts"])
        history_payload.append({
            "timestamp": dt.isoformat(timespec="seconds"),
            "total_events": h["total_events"],
            "error_events": h["error_events"]
        })

    now_iso = datetime.datetime.fromtimestamp(snapshot_time).isoformat(timespec="seconds")

    payload = {
        "generated_at": now_iso,
        "total_events": total_events,
        "error_events": error_count,
        "error_rate": error_rate,
        "by_level": dict(global_by_level),
        "by_log": by_log,
        "log_count": len(by_log),
        "history": history_payload
    }
    return payload


def get_normalized_events(limit_per_log=50):
    """
    Return a sample of the last N normalized events per log
    for UI log-table inspection.
    """
    cfg = get_config()
    logs_cfg = [l for l in cfg["logs"] if l.get("enabled", True)]
    ui_cfg = cfg.get("ui", {})
    max_lines_per_log = int(ui_cfg.get("max_lines_per_log", 300))

    logs_events = []

    for log_conf in logs_cfg:
        log_id = log_conf.get("id")
        log_name = log_conf.get("name", log_id)
        path = log_conf.get("path")
        if not path:
            continue

        lines = read_last_lines(path, max_lines=max_lines_per_log)
        # Take only last `limit_per_log`
        lines = lines[-limit_per_log:]

        events = []
        for line in lines:
            ev = normalize_log_line(line, log_conf)
            events.append(ev)

        logs_events.append({
            "id": log_id,
            "name": log_name,
            "path": path,
            "events": events
        })

    return logs_events


@app.route("/")
def index():
    cfg = get_config()
    refresh_interval = int(cfg.get("ui", {}).get("refresh_interval_ms", 4000))
    return render_template("index.html", refresh_interval_ms=refresh_interval)


@app.route("/api/metrics")
def api_metrics():
    metrics = build_metrics()
    return jsonify(metrics)


@app.route("/api/logs")
def api_logs():
    """
    Optional query parameter: ?log_id=SYSLOG_ID
    If provided, only that log is returned; otherwise all enabled logs.
    """
    requested_log_id = request.args.get("log_id")
    all_logs = get_normalized_events(limit_per_log=50)

    if requested_log_id:
        filtered = [l for l in all_logs if l["id"] == requested_log_id]
        return jsonify(filtered)

    return jsonify(all_logs)


if __name__ == "__main__":
    # For dev: expose on all interfaces, easy to put behind nginx later
    app.run(host="0.0.0.0", port=5000, debug=True)
