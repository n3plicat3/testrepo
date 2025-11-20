# Logdash – Linux Log Monitoring Dashboard (Flask)

This is a small Flask-based web application that visualizes Linux logs with a configurable JSON-based config and dynamic regex normalization.

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
- Frontend:
  - Animated metric cards (total events, errors, log sources)
  - Line chart (events over time)
  - Bar chart (events per log source)
  - Table of normalized log entries

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
  "logs": [
    {
      "id": "syslog",
      "name": "System Log",
      "path": "/var/log/syslog",
      "enabled": true,
      "pattern": "^(?P<timestamp>\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+)\\s+(?P<host>\\S+)\\s+(?P<process>[^:]+):\\s+(?P<message>.*)$",
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
- `level_patterns` is a map from a level name to a regex. The first matching level wins.

To monitor different logs:

1. Add more objects under `"logs"` with their `id`, `name`, `path`, and regex fields.
2. Ensure the Linux user running the app has read access to those log files.

## Notes

- The backend uses a simple tail-like reader that reads approximately the last `max_lines_per_log` lines without loading the entire file into memory.
- History for the line chart is kept in-memory only, in a small rolling window (`metrics_history`).
