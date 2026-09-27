"""Mini SOC-style login log analyzer.

Reads timestamped login attempts, counts failures by IP and username,
flags possible brute-force activity, and writes a text (and optional CSV) report.
"""

from __future__ import annotations

import argparse
import os
from collections import defaultdict
from typing import Any

DEFAULT_LOG = os.path.join("data", "sample_login_log.txt")
DEFAULT_REPORT = os.path.join("output", "flagged_report.txt")
DEFAULT_THRESHOLD = 3
REQUIRED_FIELDS = ("username", "ip", "timestamp", "status")


class MalformedLogLineError(ValueError):
    """Raised when a log line cannot be parsed into the expected fields."""


def parse_log_line(line: str) -> dict[str, str]:
    """Take one raw log line and return a dict with username, ip, timestamp, and status."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        raise MalformedLogLineError("empty or comment line")

    parts = [part.strip() for part in stripped.split(",")]
    if len(parts) < 4:
        raise MalformedLogLineError(f"expected at least 4 comma-separated fields, got {len(parts)}")

    timestamp = parts[0]
    if " " not in timestamp:
        raise MalformedLogLineError("timestamp is missing a date or time")

    record: dict[str, str] = {"timestamp": timestamp}
    for part in parts[1:]:
        if "=" not in part:
            raise MalformedLogLineError(f"missing key=value pair in '{part}'")
        key, value = part.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if not key or not value:
            raise MalformedLogLineError(f"empty key or value in '{part}'")
        if key == "user":
            key = "username"
        record[key] = value.lower() if key == "status" else value

    missing = [field for field in REQUIRED_FIELDS if field not in record]
    if missing:
        raise MalformedLogLineError(f"missing field(s): {', '.join(missing)}")
    if record["status"] not in {"success", "failed"}:
        raise MalformedLogLineError(f"unknown status '{record['status']}'")
    return record


def load_log_file(filepath: str) -> list[dict[str, str]]:
    """Read the file, parse every line, and return a list of dicts. Handle FileNotFoundError."""
    entries: list[dict[str, str]] = []
    skipped = 0
    try:
        with open(filepath, encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                try:
                    entries.append(parse_log_line(line))
                except MalformedLogLineError as exc:
                    skipped += 1
                    print(f"Skipping line {line_number}: {exc}")
    except FileNotFoundError:
        print(f"Log file not found: {filepath}")
        return []
    except OSError as exc:
        print(f"Could not read log file '{filepath}': {exc}")
        return []

    print(f"Loaded {len(entries)} valid entries ({skipped} malformed line(s) skipped).")
    return entries


def count_failed_attempts(entries: list[dict[str, str]]) -> dict[str, dict[str, int]]:
    """Count failed attempts per IP and per username."""
    by_ip: dict[str, int] = defaultdict(int)
    by_username: dict[str, int] = defaultdict(int)
    for entry in entries:
        if entry.get("status") != "failed":
            continue
        by_ip[entry["ip"]] += 1
        by_username[entry["username"]] += 1
    return {"ip": dict(by_ip), "username": dict(by_username)}


def flag_suspicious(failed_counts: dict[str, int], threshold: int = DEFAULT_THRESHOLD) -> list[str]:
    """Return keys whose failed count exceeds the threshold. Uses list comprehension."""
    return [key for key, count in failed_counts.items() if count > threshold]


def _flagged_entry_rows(
    entries: list[dict[str, str]],
    flagged_ips: list[str],
    flagged_users: list[str],
) -> list[dict[str, Any]]:
    flagged_ip_set = set(flagged_ips)
    flagged_user_set = set(flagged_users)
    rows: list[dict[str, Any]] = []
    for entry in entries:
        reasons = []
        if entry["ip"] in flagged_ip_set:
            reasons.append("ip")
        if entry["username"] in flagged_user_set:
            reasons.append("username")
        if not reasons:
            continue
        rows.append(
            {
                "timestamp": entry["timestamp"],
                "username": entry["username"],
                "ip": entry["ip"],
                "status": entry["status"],
                "flag_reason": "+".join(reasons),
            }
        )
    return rows


def write_report(
    flagged_ips: list[str],
    output_path: str,
    failed_counts: dict[str, dict[str, int]] | None = None,
    flagged_users: list[str] | None = None,
    entries: list[dict[str, str]] | None = None,
    threshold: int = DEFAULT_THRESHOLD,
    csv_path: str | None = None,
) -> None:
    """Write a summary report of flagged IPs/usernames, and optionally export flagged rows to CSV."""
    failed_counts = failed_counts or {"ip": {}, "username": {}}
    flagged_users = flagged_users or []
    entries = entries or []

    directory = os.path.dirname(output_path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    lines = [
        "Login attempt analysis report",
        f"Failure threshold: more than {threshold} failed attempt(s)",
        "",
        f"Suspicious IPs ({len(flagged_ips)}):",
    ]
    if flagged_ips:
        lines.extend(
            f"  - {ip}  failed={failed_counts['ip'].get(ip, 0)}" for ip in flagged_ips
        )
    else:
        lines.append("  (none)")

    lines.extend(["", f"Suspicious usernames ({len(flagged_users)}):"])
    if flagged_users:
        lines.extend(
            f"  - {user}  failed={failed_counts['username'].get(user, 0)}"
            for user in flagged_users
        )
    else:
        lines.append("  (none)")

    ip_lines = [
        f"  - {ip}: {count}"
        for ip, count in sorted(failed_counts["ip"].items(), key=lambda item: item[1], reverse=True)
    ]
    user_lines = [
        f"  - {user}: {count}"
        for user, count in sorted(
            failed_counts["username"].items(), key=lambda item: item[1], reverse=True
        )
    ]
    lines.extend(["", "All failed attempts by IP:"])
    lines.extend(ip_lines or ["  (none)"])
    lines.extend(["", "All failed attempts by username:"])
    lines.extend(user_lines or ["  (none)"])
    lines.append("")

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")

    if csv_path:
        _export_csv(csv_path, entries, flagged_ips, flagged_users)


def _export_csv(
    csv_path: str,
    entries: list[dict[str, str]],
    flagged_ips: list[str],
    flagged_users: list[str],
) -> None:
    try:
        import pandas as pd
    except ImportError:
        print("pandas is not installed. Skipping CSV export. Install with: pip install pandas")
        return

    rows = _flagged_entry_rows(entries, flagged_ips, flagged_users)
    directory = os.path.dirname(csv_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    pd.DataFrame(rows).to_csv(csv_path, index=False)
    print(f"CSV export written to {csv_path} ({len(rows)} row(s)).")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Flag suspicious login activity from a text log.")
    parser.add_argument("--log", default=DEFAULT_LOG, help="Path to the login log file")
    parser.add_argument("--output", default=DEFAULT_REPORT, help="Path for the text summary report")
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        help="Flag IPs/usernames with more than this many failures (default: 3)",
    )
    parser.add_argument(
        "--csv",
        nargs="?",
        const=os.path.join("output", "flagged_entries.csv"),
        default=None,
        help="Optional CSV path for flagged entries (default: output/flagged_entries.csv)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    entries = load_log_file(args.log)
    failed_counts = count_failed_attempts(entries)
    flagged_ips = flag_suspicious(failed_counts["ip"], threshold=args.threshold)
    flagged_users = flag_suspicious(failed_counts["username"], threshold=args.threshold)
    write_report(
        flagged_ips,
        args.output,
        failed_counts=failed_counts,
        flagged_users=flagged_users,
        entries=entries,
        threshold=args.threshold,
        csv_path=args.csv,
    )
    print(
        f"Analysis complete. {len(flagged_ips)} suspicious IP(s) and "
        f"{len(flagged_users)} suspicious username(s) flagged."
    )
    print(f"Report: {args.output}")


if __name__ == "__main__":
    main()
