# Login Attempt Analyzer

A local tool that scans a login log for repeated failed attempts and flags
IPs or usernames that look like brute-force activity. Upload a file through
the browser, and it runs the analysis and shows the results on the same page.

## What it demonstrates

This started as a Python fundamentals project and grew into a small full-stack
tool:

- **Parsing and validation** — reads comma-separated log lines, validates each
  field, and skips malformed lines without crashing (`log_analyzer.py`)
- **Dictionaries and list comprehension** — counts failed attempts per IP and
  per username, then flags anything over a threshold
- **Error handling** — missing files, unreadable files, and bad log lines are
  all caught and reported instead of raising
- **File I/O** — writes a plain-text report and an optional CSV export
- **A Flask backend** (`app.py`) that wraps the analyzer behind a simple API
- **A vanilla HTML/CSS/JS frontend** for uploading a file and viewing results
  without leaving the browser

## How it fits together

```
Browser (index.html)
   |  upload a file via the form
   v
Flask route  POST /analyze
   |  saves the file, calls into log_analyzer.py
   v
log_analyzer.py
   |  parses lines -> counts failures -> flags outliers -> writes report/csv
   v
Flask returns JSON
   |
   v
script.js renders the stats, tables, and report text in the page
```

Everything runs on your own machine. No data leaves localhost.

## Project structure

```
login-log-analyzer/
├── app.py
├── log_analyzer.py
├── templates/
│   └── index.html
├── static/
│   ├── style.css
│   └── script.js
├── data/
│   └── sample_login_log.txt
├── uploads/
├── output/
├── requirements.txt
└── README.md
```

## Setup

Requires Python 3.10+.

1. **Clone the repo**
   ```bash
   git clone https://github.com/<your-username>/login-log-analyzer.git
   cd login-log-analyzer
   ```

2. **Create and activate a virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate        # Windows: venv\\Scripts\\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the app**
   ```bash
   python3 app.py
   ```

5. **Open it in your browser**
   ```
   http://127.0.0.1:5000
   ```

## Using it

1. Click the upload area and choose a log file.
2. Set the failure threshold.
3. Click **Run analysis**.
4. Review the flagged IPs, usernames, report, and optional CSV export.

## Expected log format

```
2026-08-20 09:14:30, user=arjun, ip=203.0.113.5, status=failed
```

Lines that do not match this shape are skipped.

## Command-line usage

```bash
python3 log_analyzer.py --log data/sample_login_log.txt --threshold 3 --csv
```
