"""Flask web interface for the login log analyzer."""

from __future__ import annotations

import os

from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

from log_analyzer import DEFAULT_THRESHOLD, count_failed_attempts, flag_suspicious, load_log_file, write_report

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
REPORT_PATH = os.path.join(OUTPUT_DIR, "flagged_report.txt")
CSV_PATH = os.path.join(OUTPUT_DIR, "flagged_entries.csv")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    if "logfile" not in request.files or not request.files["logfile"].filename:
        return jsonify({"error": "Choose a file before running the analysis."}), 400

    upload = request.files["logfile"]
    filename = secure_filename(upload.filename) or "uploaded_log.csv"
    saved_path = os.path.join(UPLOAD_DIR, filename)
    upload.save(saved_path)

    try:
        threshold = int(request.form.get("threshold", DEFAULT_THRESHOLD))
    except ValueError:
        threshold = DEFAULT_THRESHOLD

    entries = load_log_file(saved_path)
    if not entries:
        return jsonify({"error": "No valid entries could be parsed from that file."}), 400

    failed_counts = count_failed_attempts(entries)
    flagged_ips = flag_suspicious(failed_counts["ip"], threshold)
    flagged_users = flag_suspicious(failed_counts["username"], threshold)

    write_report(
        flagged_ips, REPORT_PATH, failed_counts=failed_counts,
        flagged_users=flagged_users, entries=entries,
        threshold=threshold, csv_path=CSV_PATH,
    )

    with open(REPORT_PATH, encoding="utf-8") as handle:
        report_text = handle.read()

    return jsonify({
        "total_entries": len(entries),
        "threshold": threshold,
        "flagged_ips": [{"ip": ip, "failed": failed_counts["ip"][ip]} for ip in flagged_ips],
        "flagged_users": [{"username": user, "failed": failed_counts["username"][user]} for user in flagged_users],
        "ip_counts": failed_counts["ip"],
        "username_counts": failed_counts["username"],
        "report_text": report_text,
        "csv_available": os.path.exists(CSV_PATH),
    })


@app.route("/download/report")
def download_report():
    if not os.path.exists(REPORT_PATH):
        return jsonify({"error": "No report yet. Run an analysis first."}), 404
    return send_file(REPORT_PATH, as_attachment=True, download_name="flagged_report.txt")


@app.route("/download/csv")
def download_csv():
    if not os.path.exists(CSV_PATH):
        return jsonify({"error": "No CSV yet. Install pandas and re-run the analysis."}), 404
    return send_file(CSV_PATH, as_attachment=True, download_name="flagged_entries.csv")


if __name__ == "__main__":
    app.run(debug=True, port=5000)
