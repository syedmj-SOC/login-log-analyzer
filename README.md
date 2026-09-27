# Login Attempt Analyzer

A local Python and Flask tool that analyzes login logs for repeated failed authentication attempts and flags suspicious IP addresses or usernames.

## Features

- Parses and validates comma-separated login records
- Counts failed attempts by IP and username
- Flags values above a configurable threshold
- Handles malformed input without crashing
- Exports a text report and optional CSV
- Provides a browser-based Flask interface for uploading logs
- Keeps uploaded logs and generated reports local

## Setup

Requires Python 3.10+.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Open `http://127.0.0.1:5000` in your browser.

## Log format

```text
2026-08-20 09:14:30, user=arjun, ip=203.0.113.5, status=failed
```

Valid statuses are `success` and `failed`.

## Command line

```bash
python3 login_analyzer.py --log data/sample_login_log.txt --threshold 3 --csv
```

The analyzer flags IPs and usernames with more than the configured number of failed attempts.
