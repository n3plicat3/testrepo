import os
import json
import logging
from logging.handlers import TimedRotatingFileHandler
import re
import time
import datetime
from collections import Counter, deque, defaultdict
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from typing import Optional, Tuple, Dict, Any, List

from flask import Flask, render_template, jsonify, request, make_response

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
# Preferred base config with comments (JSONC). Fallback to JSON.
CONFIG_BASE_CANDIDATES = [
    os.path.join(CONFIG_DIR, "logs.jsonc"),
    os.path.join(CONFIG_DIR, "logs.json"),
]
# Overrides are written here so we never destroy comments in the base file
CONFIG_OVERRIDES_PATH = os.path.join(CONFIG_DIR, "overrides.json")

app = Flask(__name__)

_config_cache = {}
_config_mtime = (0, 0)  # (base_mtime, overrides_mtime)
metrics_history = deque(maxlen=50)  # sliding window for trends
# Per-log rolling history for anomaly detection
history_by_log = defaultdict(lambda: deque(maxlen=50))  # {log_id: deque of {events, error_events}}

# In-memory overrides for interactive pipeline tuning (not persisted until POST /api/config/pipeline)
_pipeline_overrides = {}
_overrides_lock = Lock()


def _default_config() -> dict:
    return {
        "logs": [],
        "ui": {
            # Refresh and table sizes are UI-only and safe to tweak at runtime
            "refresh_interval_ms": 4000,
            "max_lines_per_log": 300
        },
        # Shared regex snippets users can reference from log definitions
        # Example usage in logs[*].pattern: "${preset:syslog_basic}"
        "regex_presets": {
            "syslog_basic": r"^(?P<timestamp>\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+)\\s+(?P<host>\\S+)\\s+(?P<process>[^:]+):\\s+(?P<message>.*)$",
            "level_error": r"(?i)\\berror\\b|\\bfail(ed)?\\b",
            "level_warning": r"(?i)\\bwarn(ing)?\\b",
            "level_info": r"(?i)\\binfo\\b|\\bstarted\\b|\\bstopped\\b",
            "level_critical": r"(?i)\\bpanic\\b|\\bcrit(ical)?\\b|\\balert\\b"
        },
        "pipeline": {
            "workers": 4,           # threads for per-log processing
            "mps_limit": 0,         # messages per second limit (0 disables)
            "batch_size": 500,      # max lines per log per request
            "pdf_engine": "auto"   # auto|weasyprint|pdfkit|none
        },
        # Optional export of normalized events to JSONL with rotation & retention
        "archive": {
            "enabled": False,
            # Where to write derived archives. Suggestion: /var/lib/logmon/archive
            "dir": os.path.join(BASE_DIR, "data", "archive"),
            # daily rotation is recommended for simplicity
            "rotation": "daily",  # daily|none (size-based can be added later)
            # Delete derived archives older than N days (default 2)
            "retention_days": 2,
            # Append exports when the UI fetches logs (best effort, may duplicate)
            "write_on_fetch": True,
            # Limit events exported per log per batch
            "export_sample": 200
        },
        # Application's own logging with rotation (does not touch source logs)
        "app_logging": {
            "enabled": True,
            "level": "INFO",
            # Suggestion: /var/log/logmon
            "dir": os.path.join(BASE_DIR, "logs"),
            # Keep N days of app logs
            "retention_days": 2
        }
    }


def _read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _strip_json_comments(text: str) -> str:
    """Remove // and /* */ comments to allow JSONC-like files."""
    # Remove block comments
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    # Remove line comments (// ...)
    text = re.sub(r"(^|\s)//.*$", "", text, flags=re.M)
    return text


def _load_base_config() -> Tuple[dict, float]:
    for cand in CONFIG_BASE_CANDIDATES:
        if os.path.exists(cand):
            try:
                raw = _read_file(cand)
                if cand.endswith(".jsonc"):
                    raw = _strip_json_comments(raw)
                base = json.loads(raw)
            except Exception:
                base = {}
            try:
                mtime = os.path.getmtime(cand)
            except OSError:
                mtime = 0.0
            return base, mtime
    return {}, 0.0


def _load_overrides() -> Tuple[dict, float]:
    if not os.path.exists(CONFIG_OVERRIDES_PATH):
        return {}, 0.0
    try:
        with open(CONFIG_OVERRIDES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}
    try:
        mtime = os.path.getmtime(CONFIG_OVERRIDES_PATH)
    except OSError:
        mtime = 0.0
    return data, mtime


def _deep_merge(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in (b or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def get_config():
    """Load config layering base (json/jsonc) + overrides.json, with auto-reload."""
    global _config_cache, _config_mtime
    base, base_mtime = _load_base_config()
    overrides, ov_mtime = _load_overrides()
    mtimes = (base_mtime, ov_mtime)

    if mtimes != _config_mtime:
        merged = _deep_merge(_default_config(), base)
        merged = _deep_merge(merged, overrides)
        # Ensure minimal structure
        merged.setdefault("logs", [])
        merged.setdefault("ui", {})
        merged.setdefault("pipeline", _default_config()["pipeline"]) 
        merged.setdefault("archive", _default_config()["archive"]) 
        merged.setdefault("regex_presets", _default_config()["regex_presets"]) 
        merged.setdefault("app_logging", _default_config()["app_logging"]) 
        _config_cache = merged
        _config_mtime = mtimes

    # Apply in-memory overrides for interactive changes (pipeline only)
    with _overrides_lock:
        if _pipeline_overrides:
            merged = dict(_config_cache.get("pipeline", {}))
            merged.update(_pipeline_overrides)
            _config_cache["pipeline"] = merged
    return _config_cache


def save_config(updated: dict) -> None:
    """Persist full config to overrides.json, preserving base file with comments."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_OVERRIDES_PATH, "w", encoding="utf-8") as f:
        json.dump(updated, f, indent=2, sort_keys=False)
    # Force reload on next read
    global _config_mtime
    _config_mtime = (0, 0)


def _setup_app_logging():
    cfg = get_config().get("app_logging", {})
    if not cfg.get("enabled", True):
        return
    log_dir = cfg.get("dir") or os.path.join(BASE_DIR, "logs")
    try:
        os.makedirs(log_dir, exist_ok=True)
    except Exception:
        # If we cannot create dir, skip file logging silently
        return
    level_name = str(cfg.get("level", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)
    retention_days = int(cfg.get("retention_days", 2) or 2)
    handler = TimedRotatingFileHandler(
        filename=os.path.join(log_dir, "app.log"), when="midnight", backupCount=max(0, retention_days)
    )
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)


# Initialize app logging early
_setup_app_logging()
logger = logging.getLogger("logmon")


class TokenBucket:
    """Simple token bucket rate limiter for messages-per-second control."""

    def __init__(self, rate_per_sec: int):
        self.rate = max(0, int(rate_per_sec or 0))
        self.capacity = self.rate
        self.tokens = float(self.capacity)
        self.timestamp = time.time()
        self._lock = Lock()

    def consume(self, units: int = 1) -> None:
        if self.rate <= 0:
            return  # disabled
        with self._lock:
            now = time.time()
            elapsed = now - self.timestamp
            # Refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.timestamp = now
            if self.tokens < units:
                # Sleep just enough to accumulate required tokens
                needed = units - self.tokens
                sleep_time = needed / float(self.rate)
                if sleep_time > 0:
                    time.sleep(min(sleep_time, 0.05))  # cap sleep for responsiveness
                # Update tokens after sleep
                now2 = time.time()
                elapsed2 = now2 - self.timestamp
                self.tokens = min(self.capacity, self.tokens + elapsed2 * self.rate)
                self.timestamp = now2
            # Consume what we can (may still be < units, but we proceed)
            take = min(self.tokens, units)
            self.tokens -= take


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


def _resolve_preset(value: Optional[str], presets: Dict[str, str]) -> Optional[str]:
    if not value or not isinstance(value, str):
        return value
    m = re.match(r"^\$\{\s*preset:(?P<name>[a-zA-Z0-9_\-]+)\s*\}$", value)
    if m:
        return presets.get(m.group("name")) or value
    return value


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

    cfg = get_config()
    presets = cfg.get("regex_presets", {})

    pattern = _resolve_preset(log_conf.get("pattern"), presets) or log_conf.get("pattern")
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
            level_regex = _resolve_preset(level_regex, presets) or level_regex
            if re.search(level_regex, message_for_level):
                result["level"] = level_name
                break
        except re.error:
            # Invalid regex shouldn't kill processing
            continue

    # Optional message transformations (regex find/replace)
    transforms = log_conf.get("transforms", [])
    if transforms and (result.get("message") or result.get("raw")):
        msg = result.get("message") or result.get("raw") or ""
        for tr in transforms:
            find = tr.get("find")
            repl = tr.get("replace", "")
            flags = 0
            if str(tr.get("flags", "")).lower().find("i") >= 0:
                flags |= re.IGNORECASE
            if find:
                try:
                    msg = re.sub(find, repl, msg, flags=flags)
                except re.error:
                    continue
        # Keep raw for integrity; update normalized message view
        result["message"] = msg

    return result


def parse_timestamp(ev: dict, log_conf: dict) -> Optional[datetime.datetime]:
    ts_text = ev.get("timestamp")
    if not ts_text:
        return None
    # Specific format from config or default syslog-like
    fmt = log_conf.get("timestamp_format")
    guesses: List[str] = []
    if fmt:
        guesses.append(fmt)
    # Common syslog format without year
    guesses.append("%b %d %H:%M:%S")
    for g in guesses:
        try:
            dt = datetime.datetime.strptime(ts_text, g)
            # If no year in format, assume current year
            if "%Y" not in g and "%y" not in g:
                dt = dt.replace(year=datetime.datetime.now().year)
            return dt
        except Exception:
            continue
    return None


def _process_log(log_conf: dict, max_lines_per_log: int, limiter: Optional[TokenBucket]) -> Tuple[str, Dict[str, Any]]:
    log_id = log_conf.get("id")
    log_name = log_conf.get("name", log_id)
    path = log_conf.get("path")
    if not path:
        return log_id, {
            "id": log_id,
            "name": log_name,
            "path": path,
            "events": 0,
            "by_level": {}
        }

    lines = read_last_lines(path, max_lines=max_lines_per_log)
    log_counter = Counter()
    event_count = 0

    for line in lines:
        if limiter:
            limiter.consume(1)
        ev = normalize_log_line(line, log_conf)
        lvl = ev.get("level", "info")
        log_counter[lvl] += 1
        event_count += 1

    return log_id, {
        "id": log_id,
        "name": log_name,
        "path": path,
        "events": event_count,
        "by_level": dict(log_counter)
    }


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
    pipe_cfg = cfg.get("pipeline", {})
    # Support workers="auto" to scale with enabled log sources
    workers_cfg = pipe_cfg.get("workers", 4)
    if isinstance(workers_cfg, str) and workers_cfg.strip().lower() == "auto":
        workers = max(1, len(logs_cfg))
    else:
        try:
            workers = int(workers_cfg or 1)
        except Exception:
            workers = 1
    mps_limit = int(pipe_cfg.get("mps_limit", 0) or 0)
    batch_size = int(pipe_cfg.get("batch_size", 0) or 0)
    if batch_size > 0:
        max_lines_per_log = min(max_lines_per_log, batch_size)

    limiter = TokenBucket(mps_limit) if mps_limit > 0 else None

    total_events = 0
    global_by_level = Counter()
    by_log = {}

    # Parallelize per-log processing
    if workers <= 1:
        for log_conf in logs_cfg:
            log_id, summary = _process_log(log_conf, max_lines_per_log, limiter)
            by_log[log_id] = summary
            total_events += summary["events"]
            for lvl, cnt in summary["by_level"].items():
                global_by_level[lvl] += cnt
    else:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(_process_log, log_conf, max_lines_per_log, limiter) for log_conf in logs_cfg]
            for fut in futures:
                log_id, summary = fut.result()
                if not log_id:
                    # Skip malformed configs with no id
                    continue
                by_log[log_id] = summary
                total_events += summary["events"]
                for lvl, cnt in summary["by_level"].items():
                    global_by_level[lvl] += cnt

    error_count = global_by_level.get("error", 0) + global_by_level.get("critical", 0)
    error_rate = float(error_count) / total_events if total_events > 0 else 0.0

    snapshot_time = time.time()
    snapshot = {
        "ts": snapshot_time,
        "total_events": total_events,
        "error_events": error_count
    }
    metrics_history.append(snapshot)

    # Update per-log rolling history for anomalies
    for lid, summary in by_log.items():
        err = summary["by_level"].get("error", 0) + summary["by_level"].get("critical", 0)
        history_by_log[lid].append({"events": summary["events"], "error_events": err})

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


def _signature_of(message: str) -> str:
    """Create a coarse signature for grouping similar messages.
    Masks numbers, IPs, and hex strings; normalizes whitespace.
    """
    if not message:
        return ""
    s = message.lower()
    # Mask IPv4
    s = re.sub(r"\b(\d{1,3}\.){3}\d{1,3}\b", "<ip>", s)
    # Mask hex hashes/ids
    s = re.sub(r"\b0x[0-9a-f]+\b", "<hex>", s)
    s = re.sub(r"\b[0-9a-f]{8,}\b", "<hex>", s)
    # Mask numbers
    s = re.sub(r"\b\d+\b", "<num>", s)
    # Collapse whitespace
    s = re.sub(r"\s+", " ", s).strip()
    # Truncate to keep signatures compact
    return s[:160]


def _zscore(values: List[int], current: int) -> float:
    if not values:
        return 0.0
    import math
    mean = sum(values) / float(len(values))
    var = sum((v - mean) ** 2 for v in values) / float(len(values))
    std = math.sqrt(var) if var > 0 else 0.0
    if std == 0:
        return 0.0
    return (current - mean) / std


def build_insights() -> Dict[str, Any]:
    """Compute higher-level insights: anomalies, top patterns, outliers, risk."""
    metrics = build_metrics()
    logs_events = get_normalized_events(limit_per_log=150)

    # Severity breakdown
    sev = Counter(metrics.get("by_level", {}))

    # Anomalies per log (events and error events z-score)
    anomalies: List[Dict[str, Any]] = []
    for lid, summary in metrics.get("by_log", {}).items():
        hist = history_by_log.get(lid, deque())
        hist_events = [h["events"] for h in hist]
        hist_errors = [h["error_events"] for h in hist]
        z_events = _zscore(hist_events, summary["events"])
        err = summary["by_level"].get("error", 0) + summary["by_level"].get("critical", 0)
        z_errors = _zscore(hist_errors, err)
        if z_events >= 2.0 or z_errors >= 2.0:
            anomalies.append({
                "log_id": lid,
                "name": summary.get("name", lid),
                "events": summary["events"],
                "error_events": err,
                "z_events": round(z_events, 2),
                "z_errors": round(z_errors, 2)
            })

    # Top error/critical patterns using coarse signatures
    sig_counts = Counter()
    sig_examples = {}
    process_counts = Counter()
    per_log_error_rate = []
    for le in logs_events:
        lid = le.get("id")
        name = le.get("name", lid)
        events = le.get("events", [])
        if not events:
            continue
        # Per-log error rate
        levels = Counter((e.get("level") or "info").lower() for e in events)
        errc = levels.get("error", 0) + levels.get("critical", 0)
        erate = float(errc) / max(1, len(events))
        per_log_error_rate.append({
            "log_id": lid,
            "name": name,
            "error_rate": erate,
            "events": len(events),
            "error_events": errc
        })

        for ev in events:
            proc = (ev.get("process") or "").strip() or "unknown"
            process_counts[proc] += 1
            lvl = (ev.get("level") or "info").lower()
            if lvl in ("error", "critical"):
                msg = ev.get("message") or ev.get("raw") or ""
                sig = _signature_of(msg)
                if sig:
                    sig_counts[sig] += 1
                    sig_examples.setdefault(sig, {"log_id": lid, "name": name, "example": msg})

    top_error_patterns = []
    for sig, cnt in sig_counts.most_common(10):
        meta = sig_examples.get(sig, {})
        top_error_patterns.append({
            "signature": sig,
            "count": cnt,
            "log_id": meta.get("log_id"),
            "name": meta.get("name"),
            "example": meta.get("example")
        })

    # Rare events (unique signatures)
    rare_events = [
        {
            "signature": sig,
            "count": cnt,
            "name": sig_examples.get(sig, {}).get("name"),
            "example": sig_examples.get(sig, {}).get("example")
        }
        for sig, cnt in sig_counts.items() if cnt == 1
    ][:10]

    # Noisiest processes
    noisy_processes = [
        {"process": p, "events": c}
        for p, c in process_counts.most_common(10)
    ]

    # Risk scoring per log
    risks = []
    anomalies_map = {a["log_id"]: a for a in anomalies}
    for item in per_log_error_rate:
        lid = item["log_id"]
        base = item["error_rate"] * 100.0
        if lid in anomalies_map:
            base += 20.0  # anomaly boost
        base += min(20.0, item.get("error_events", 0) * 0.5)
        risks.append({
            "log_id": lid,
            "name": item["name"],
            "risk": round(min(100.0, base), 1),
            "error_rate": round(item["error_rate"], 3),
            "events": item["events"],
            "error_events": item["error_events"]
        })

    risks.sort(key=lambda r: r["risk"], reverse=True)

    return {
        "generated_at": metrics.get("generated_at"),
        "severity": dict(sev),
        "anomalies": anomalies,
        "top_error_patterns": top_error_patterns,
        "rare_events": rare_events,
        "noisy_processes": noisy_processes,
        "risks": risks[:10]
    }


@app.route("/api/insights")
def api_insights():
    insights = build_insights()
    return jsonify(insights)


def get_normalized_events(limit_per_log=50):
    """
    Return a sample of the last N normalized events per log
    for UI log-table inspection.
    """
    cfg = get_config()
    logs_cfg = [l for l in cfg["logs"] if l.get("enabled", True)]
    ui_cfg = cfg.get("ui", {})
    max_lines_per_log = int(ui_cfg.get("max_lines_per_log", 300))
    pipe_cfg = cfg.get("pipeline", {})
    mps_limit = int(pipe_cfg.get("mps_limit", 0) or 0)
    batch_size = int(pipe_cfg.get("batch_size", 0) or 0)
    if batch_size > 0:
        max_lines_per_log = min(max_lines_per_log, batch_size)
    limiter = TokenBucket(mps_limit) if mps_limit > 0 else None

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
            if limiter:
                limiter.consume(1)
            ev = normalize_log_line(line, log_conf)
            events.append(ev)

        bundle = {
            "id": log_id,
            "name": log_name,
            "path": path,
            "events": events
        }
        logs_events.append(bundle)

    # Optional archive export with rotation/retention
    try:
        _maybe_export_archive(logs_events)
    except Exception as e:
        logger.debug(f"archive export skipped: {e}")

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


@app.route("/api/config/pipeline", methods=["GET", "POST"])
def api_config_pipeline():
    cfg = get_config()
    pipeline = dict(cfg.get("pipeline", {}))

    if request.method == "GET":
        return jsonify(pipeline)

    data = request.get_json(silent=True) or {}
    allowed = {
        "workers": (int, str),     # supports integer or "auto"
        "mps_limit": int,
        "batch_size": int,
        "pdf_engine": str,
    }
    updates = {}
    for k, caster in allowed.items():
        if k in data:
            val = data[k]
            if k == "workers":
                # Accept "auto" or a positive integer
                if isinstance(val, str) and val.strip().lower() == "auto":
                    updates[k] = "auto"
                else:
                    try:
                        updates[k] = int(val)
                    except Exception:
                        return jsonify({"error": "Invalid value for workers (use integer or 'auto')"}), 400
            else:
                try:
                    updates[k] = caster(val) if caster is not str else str(val)
                except Exception:
                    return jsonify({"error": f"Invalid value for {k}"}), 400

    # Apply in-memory immediately for interactivity
    with _overrides_lock:
        _pipeline_overrides.update(updates)

    # Persist to config file
    cfg_all = get_config()
    merged = dict(cfg_all)
    merged["pipeline"] = dict(merged.get("pipeline", {}))
    merged["pipeline"].update(updates)
    try:
        save_config(merged)
    except Exception as e:
        # Keep overrides even if saving fails
        return jsonify({"warning": f"Applied in-memory only. Persist failed: {e}"}), 202

    return jsonify({"ok": True, "pipeline": merged.get("pipeline", {})})


def _collect_events_for_period(period: str) -> Dict[str, Any]:
    """Aggregate events filtered by time period: daily|monthly|quarterly."""
    cfg = get_config()
    logs_cfg = [l for l in cfg["logs"] if l.get("enabled", True)]
    ui_cfg = cfg.get("ui", {})
    max_lines_per_log = int(ui_cfg.get("max_lines_per_log", 300))

    now = datetime.datetime.now()
    if period == "daily":
        start = now - datetime.timedelta(days=1)
        title = "Daily"
    elif period == "monthly":
        start = now - datetime.timedelta(days=30)
        title = "Monthly"
    elif period == "quarterly":
        start = now - datetime.timedelta(days=90)
        title = "Quarterly"
    else:
        start = now - datetime.timedelta(days=1)
        title = "Daily"

    total_events = 0
    by_level = Counter()
    by_log: Dict[str, Dict[str, Any]] = {}

    for log_conf in logs_cfg:
        log_id = log_conf.get("id")
        log_name = log_conf.get("name", log_id)
        path = log_conf.get("path")
        if not path:
            continue
        lines = read_last_lines(path, max_lines=max_lines_per_log)
        log_counter = Counter()
        event_count = 0
        sample_msgs = []
        for line in lines:
            ev = normalize_log_line(line, log_conf)
            dt = parse_timestamp(ev, log_conf)
            if dt and dt < start:
                continue
            lvl = ev.get("level", "info")
            log_counter[lvl] += 1
            total_events += 1
            event_count += 1
            if len(sample_msgs) < 10:
                sample_msgs.append(ev.get("message") or ev.get("raw") or "")
        by_log[log_id] = {
            "id": log_id,
            "name": log_name,
            "events": event_count,
            "by_level": dict(log_counter),
            "samples": sample_msgs,
        }
        for lvl, cnt in log_counter.items():
            by_level[lvl] += cnt

    payload = {
        "period": period,
        "title": title,
        "generated_at": now.isoformat(timespec="seconds"),
        "start_from": start.isoformat(timespec="seconds"),
        "total_events": total_events,
        "by_level": dict(by_level),
        "by_log": by_log,
    }
    return payload


def _render_report_html(context: Dict[str, Any]) -> str:
    return render_template("report.html", **context)


def _try_make_pdf(html: str) -> Optional[bytes]:
    cfg = get_config()
    engine = (cfg.get("pipeline", {}).get("pdf_engine") or "auto").lower()
    # Try engines in order
    engines = []
    if engine == "auto":
        engines = ["weasyprint", "pdfkit"]
    elif engine in ("weasyprint", "pdfkit"):
        engines = [engine]
    else:
        engines = []

    for e in engines:
        try:
            if e == "weasyprint":
                from weasyprint import HTML
                pdf = HTML(string=html).write_pdf()
                return pdf
            if e == "pdfkit":
                import pdfkit
                pdf = pdfkit.from_string(html, False)
                return pdf
        except Exception:
            continue
    return None


@app.route("/report")
def report():
    period = request.args.get("period", "daily").lower()
    fmt = request.args.get("format", "html").lower()
    context = _collect_events_for_period(period)
    html = _render_report_html(context)
    if fmt == "pdf":
        pdf_bytes = _try_make_pdf(html)
        if pdf_bytes:
            resp = make_response(pdf_bytes)
            resp.headers["Content-Type"] = "application/pdf"
            filename = f"report-{period}-{int(time.time())}.pdf"
            resp.headers["Content-Disposition"] = f"inline; filename={filename}"
            return resp
        # Fallback to HTML if PDF engine unavailable
        resp = make_response(html)
        resp.headers["X-Report-PDF-Error"] = "PDF engine unavailable; returning HTML"
        return resp
    return html


if __name__ == "__main__":
    # For dev: expose on all interfaces, easy to put behind nginx later
    app.run(host="0.0.0.0", port=5240, debug=True)


def _maybe_export_archive(logs_events: List[Dict[str, Any]]):
    cfg = get_config().get("archive", {})
    if not cfg.get("enabled", False):
        return
    if not cfg.get("write_on_fetch", True):
        return
    base_dir = cfg.get("dir") or os.path.join(BASE_DIR, "data", "archive")
    rotation = (cfg.get("rotation") or "daily").lower()
    retention_days = int(cfg.get("retention_days", 2) or 2)
    sample = int(cfg.get("export_sample", 200) or 200)
    try:
        os.makedirs(base_dir, exist_ok=True)
    except Exception:
        return
    today = datetime.datetime.now().strftime("%Y%m%d")
    for le in logs_events:
        lid = le.get("id") or "unknown"
        events = (le.get("events") or [])[-sample:]
        subdir = os.path.join(base_dir, lid)
        try:
            os.makedirs(subdir, exist_ok=True)
        except Exception:
            continue
        if rotation == "daily":
            out_path = os.path.join(subdir, f"{today}.jsonl")
        else:
            out_path = os.path.join(subdir, f"current.jsonl")
        try:
            with open(out_path, "a", encoding="utf-8") as f:
                for ev in events:
                    f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        except Exception:
            # best-effort only
            pass
        # Retention cleanup
        if rotation == "daily" and retention_days >= 0:
            cutoff = datetime.datetime.now() - datetime.timedelta(days=retention_days)
            try:
                for name in os.listdir(subdir):
                    if not name.endswith(".jsonl"):
                        continue
                    # Parse YYYYMMDD
                    stamp = name.split(".")[0]
                    try:
                        dt = datetime.datetime.strptime(stamp, "%Y%m%d")
                    except Exception:
                        continue
                    if dt < cutoff:
                        try:
                            os.remove(os.path.join(subdir, name))
                        except Exception:
                            pass
            except Exception:
                pass


@app.route("/api/config/archive", methods=["GET", "POST"])
def api_config_archive():
    cfg = get_config()
    arch = dict(cfg.get("archive", {}))
    if request.method == "GET":
        return jsonify(arch)
    data = request.get_json(silent=True) or {}
    allowed = {
        "enabled": bool,
        "dir": str,
        "rotation": str,
        "retention_days": int,
        "write_on_fetch": bool,
        "export_sample": int,
    }
    updates = {}
    for k, caster in allowed.items():
        if k in data:
            try:
                updates[k] = caster(data[k]) if caster is not bool else bool(data[k])
            except Exception:
                return jsonify({"error": f"Invalid value for {k}"}), 400
    # Persist to overrides
    cfg_all = get_config()
    merged = dict(cfg_all)
    merged["archive"] = dict(merged.get("archive", {}))
    merged["archive"].update(updates)
    try:
        save_config(merged)
    except Exception as e:
        return jsonify({"warning": f"Applied in-memory only. Persist failed: {e}"}), 202
    return jsonify({"ok": True, "archive": merged.get("archive", {})})
