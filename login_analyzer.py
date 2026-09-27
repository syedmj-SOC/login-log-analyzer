"""Mini SOC-style login log analyzer."""

from __future__ import annotations
import argparse
import os
from collections import defaultdict

DEFAULT_LOG=os.path.join("data","sample_login_log.txt")
DEFAULT_REPORT=os.path.join("output","flagged_report.txt")
DEFAULT_THRESHOLD=3
REQUIRED_FIELDS=("username","ip","timestamp","status")

class MalformedLogLineError(ValueError):
    pass

def parse_log_line(line):
    stripped=line.strip()
    if not stripped or stripped.startswith("#"):
        raise MalformedLogLineError("empty or comment line")
    parts=[p.strip() for p in stripped.split(",")]
    if len(parts)<4:
        raise MalformedLogLineError("expected at least 4 comma-separated fields")
    timestamp=parts[0]
    if " " not in timestamp:
        raise MalformedLogLineError("timestamp is missing a date or time")
    record={"timestamp":timestamp}
    for part in parts[1:]:
        if "=" not in part:
            raise MalformedLogLineError(f"missing key=value pair in '{part}'")
        key,value=part.split("=",1)
        key=key.strip().lower(); value=value.strip()
        if key=="user": key="username"
        if not key or not value:
            raise MalformedLogLineError("empty key or value")
        record[key]=value.lower() if key=="status" else value
    missing=[f for f in REQUIRED_FIELDS if f not in record]
    if missing: raise MalformedLogLineError(f"missing field(s): {', '.join(missing)}")
    if record["status"] not in {"success","failed"}:
        raise MalformedLogLineError(f"unknown status '{record['status']}'")
    return record

def load_log_file(filepath):
    entries=[]
    try:
        with open(filepath,encoding="utf-8") as handle:
            for line_number,line in enumerate(handle,1):
                try: entries.append(parse_log_line(line))
                except MalformedLogLineError as exc: print(f"Skipping line {line_number}: {exc}")
    except (FileNotFoundError,OSError) as exc:
        print(f"Could not read log file '{filepath}': {exc}")
        return []
    return entries

def count_failed_attempts(entries):
    by_ip=defaultdict(int); by_username=defaultdict(int)
    for entry in entries:
        if entry["status"]=="failed":
            by_ip[entry["ip"]]+=1
            by_username[entry["username"]]+=1
    return {"ip":dict(by_ip),"username":dict(by_username)}

def flag_suspicious(failed_counts,threshold=DEFAULT_THRESHOLD):
    return [key for key,count in failed_counts.items() if count>threshold]

def _flagged_entry_rows(entries,flagged_ips,flagged_users):
    ips=set(flagged_ips); users=set(flagged_users); rows=[]
    for entry in entries:
        reasons=[]
        if entry["ip"] in ips: reasons.append("ip")
        if entry["username"] in users: reasons.append("username")
        if reasons:
            rows.append({**entry,"flag_reason":"+ ".join(reasons).replace("+ ","+")})
    return rows

def write_report(flagged_ips,output_path,failed_counts=None,flagged_users=None,entries=None,threshold=DEFAULT_THRESHOLD,csv_path=None):
    failed_counts=failed_counts or {"ip":{},"username":{}}
    flagged_users=flagged_users or []; entries=entries or []
    os.makedirs(os.path.dirname(output_path) or ".",exist_ok=True)
    lines=["Login attempt analysis report",f"Failure threshold: more than {threshold} failed attempt(s)","",f"Suspicious IPs ({len(flagged_ips)}):"]
    lines += [f"  - {ip}  failed={failed_counts['ip'].get(ip,0)}" for ip in flagged_ips] or ["  (none)"]
    lines += ["",f"Suspicious usernames ({len(flagged_users)}):"]
    lines += [f"  - {u}  failed={failed_counts['username'].get(u,0)}" for u in flagged_users] or ["  (none)"]
    lines += ["","All failed attempts by IP:"] + [f"  - {ip}: {n}" for ip,n in sorted(failed_counts["ip"].items(),key=lambda x:x[1],reverse=True)] or ["  (none)"]
    lines += ["","All failed attempts by username:"] + [f"  - {u}: {n}" for u,n in sorted(failed_counts["username"].items(),key=lambda x:x[1],reverse=True)] or ["  (none)"]
    with open(output_path,"w",encoding="utf-8") as handle: handle.write("\n".join(lines)+"\n")
    if csv_path:
        try:
            import pandas as pd
            os.makedirs(os.path.dirname(csv_path) or ".",exist_ok=True)
            pd.DataFrame(_flagged_entry_rows(entries,flagged_ips,flagged_users)).to_csv(csv_path,index=False)
        except ImportError:
            print("pandas is not installed. Skipping CSV export.")

def main():
    parser=argparse.ArgumentParser(description="Flag suspicious login activity from a text log.")
    parser.add_argument("--log",default=DEFAULT_LOG)
    parser.add_argument("--output",default=DEFAULT_REPORT)
    parser.add_argument("--threshold",type=int,default=DEFAULT_THRESHOLD)
    parser.add_argument("--csv",nargs="?",const=os.path.join("output","flagged_entries.csv"),default=None)
    args=parser.parse_args()
    entries=load_log_file(args.log)
    counts=count_failed_attempts(entries)
    ips=flag_suspicious(counts["ip"],args.threshold)
    users=flag_suspicious(counts["username"],args.threshold)
    write_report(ips,args.output,counts,users,entries,args.threshold,args.csv)
    print(f"Analysis complete. {len(ips)} suspicious IP(s) and {len(users)} suspicious username(s) flagged.")

if __name__=="__main__":
    main()
