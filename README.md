# Logdash – Linux Log Monitoring Dashboard (Flask)

This is a small Flask-based web application that visualizes Linux logs with a configurable JSON-based config and dynamic regex normalization.

## Added Feature Notes (Summary)

- Pipeline tuning via `/api/config/pipeline` and UI (workers, MPS limit, batch size, PDF engine)
- Per-log parallel processing using a thread pool (faster aggregation)
- Token-bucket messages-per-second limiter to control processing throughput
- Reports in HTML/PDF for daily, monthly, and quarterly periods (`/report?...`)
- Printable report template with per-log breakdown and sample messages
- Optional `timestamp_format` in config to improve time-windowed reporting
- Dashboard UI: quick report links and inline Pipeline Settings form
- Config persisted to `config/logs.json` with auto-reload on change

## Features

- JSON config for:
  - Which log files to monitor
  - Regex to parse each log line (named capture groups)
  - Regex patterns to classify log levels (info/warning/error/critical)
- Backend:
  - Reads the tail of each configured log file
  - Normalizes entries using regex from config
  - Aggregates metrics per log and per level
  - Provides the data via `/api/metrics` and `/api/logs`
  - Pipeline tuning via `/api/config/pipeline` with workers and MPS limit
  - Report generation at `/report?period=daily|monthly|quarterly&format=html|pdf`
- Frontend:
  - Animated metric cards (total events, errors, log sources)
  - Line chart (events over time)
  - Bar chart (events per log source)
  - Table of normalized log entries
  - Inline Pipeline Settings form and quick report export links

## Project structure

```text
logdash/
├── app.py
├── config/
│   └── logs.json
├── templates/
│   └── index.html
└── static/
    ├── css/
    │   └── styles.css
    └── js/
        └── main.js
```

## Requirements

- Python 3.8+
- pip
- Linux machine with standard logs like `/var/log/syslog`, `/var/log/auth.log` (or customize paths in `config/logs.json`)

Install Python dependencies:

```bash
pip install flask
# Optional for PDF export (choose one):
# pip install weasyprint
# pip install pdfkit && brew install wkhtmltopdf  # or your OS package
```

## Running

From inside the `logdash` folder:

```bash
python app.py
```

Then open:

```text
http://localhost:5000
```

## Configuration

All configuration is in `config/logs.json`.

```json
{
  "ui": {
    "refresh_interval_ms": 4000,
    "max_lines_per_log": 300
  },
  "pipeline": {
    "workers": 4,
    "mps_limit": 0,
    "batch_size": 500,
    "pdf_engine": "auto"
  },
  "logs": [
    {
      "id": "syslog",
      "name": "System Log",
      "path": "/var/log/syslog",
      "enabled": true,
      "pattern": "^(?P<timestamp>\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+)\\s+(?P<host>\\S+)\\s+(?P<process>[^:]+):\\s+(?P<message>.*)$",
      "timestamp_format": "%b %d %H:%M:%S",
      "level_patterns": {
        "critical": "(?i)\\bpanic\\b|\\bcrit(ical)?\\b|\\balert\\b",
        "error": "(?i)\\berror\\b|\\bfail(ed)?\\b",
        "warning": "(?i)\\bwarn(ing)?\\b",
        "info": "(?i)\\binfo\\b|\\bstarted\\b|\\bstopped\\b"
      }
    }
  ]
}
```

- `pattern` is a Python regex with **named groups** like `?P<timestamp>`, `?P<process>`, `?P<message>`.
- `timestamp_format` is optional and helps parse the `timestamp` group for reporting; defaults to syslog style if omitted.
- `level_patterns` is a map from a level name to a regex. The first matching level wins.

To monitor different logs:

1. Add more objects under `"logs"` with their `id`, `name`, `path`, and regex fields.
2. Ensure the Linux user running the app has read access to those log files.

## Load Balancing & Concurrency

Run multiple workers behind a proxy (nginx/caddy) using gunicorn for higher throughput:

```bash
gunicorn -w 4 -k gthread --threads 4 -b 0.0.0.0:5240 app:app
```

- `pipeline.workers`: controls per-log parallel processing. You can now set this to a number or to the string `"auto"`.
  - When set to `"auto"`, the app spawns one worker per enabled log source (e.g., 2 workers for 2 logs).
  - When set to a number, that fixed worker count is used.
- `pipeline.mps_limit`: enables a simple messages-per-second limiter across normalization to keep CPU usage in check during peaks (0 disables).

Example `config/logs.json` snippet using auto-scaling workers:

```json
{
  "pipeline": {
    "workers": "auto",
    "mps_limit": 0,
    "batch_size": 500
  }
}
```

## Insights

The dashboard computes higher-level insights from recent events and lightweight rolling history:

- Anomalies: per-log spikes in events or errors using rolling z-scores.
- Risk: per-log risk score combining error rate, spikes, and error volume.
- Top error patterns: grouped by coarse message signatures (numbers/IPs masked).
- Noisiest processes: processes contributing the most events.
- Rare events: unique error signatures worth investigation.

API: `GET /api/insights`. The UI renders insights in “Risk & Anomalies”, “Top Error Patterns”, “Noisiest Processes”, and “Rare Events”. Use the filter bar above the events table to filter by source, level, and free text.

## Reports

Generate printable reports at `/report`:

- `GET /report?period=daily&format=html` – daily HTML report
- `GET /report?period=monthly&format=pdf` – monthly PDF (requires `weasyprint` or `pdfkit` with `wkhtmltopdf`)
- `GET /report?period=quarterly&format=html` – quarterly HTML

If a PDF engine is unavailable, the endpoint falls back to HTML and includes header `X-Report-PDF-Error`.

## Notes

- The backend uses a simple tail-like reader that reads approximately the last `max_lines_per_log` lines without loading the entire file into memory.
- History for the line chart is kept in-memory only, in a small rolling window (`metrics_history`).
