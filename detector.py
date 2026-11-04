#!/usr/bin/env python3
"""
SSH Brute-Force Detector
------------------------
Reads a Linux authentication log (auth.log / secure) and reports:
  * failed SSH login attempts per source IP
  * IPs that crossed a brute-force threshold
  * IPs that logged in SUCCESSFULLY after failing (possible compromise)

Usage:
    python3 detector.py sample_logs/auth.log
    python3 detector.py /var/log/auth.log --threshold 5 --csv report.csv

Only uses the Python standard library.
"""

import argparse
import csv
import os
import re
import sys
from collections import defaultdict

# Example lines this script understands:
# Nov  3 14:02:11 web01 sshd[2211]: Failed password for root from 203.0.113.45 port 51234 ssh2
# Nov  3 14:02:15 web01 sshd[2213]: Failed password for invalid user admin from 203.0.113.45 port 51240 ssh2
# Nov  3 14:05:40 web01 sshd[2301]: Accepted password for deploy from 198.51.100.7 port 60111 ssh2
FAILED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]+).*sshd\[\d+\]: Failed password for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>[\d.]+)"
)
ACCEPTED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]+).*sshd\[\d+\]: Accepted (?:password|publickey) for "
    r"(?P<user>\S+) from (?P<ip>[\d.]+)"
)


def parse_log(lines):
    """Return per-IP stats built from the log lines."""
    stats = defaultdict(lambda: {
        "failed": 0,
        "users_tried": set(),
        "first_seen": None,
        "last_seen": None,
        "success_after_fail": [],
    })

    for line in lines:
        m = FAILED_RE.search(line)
        if m:
            s = stats[m["ip"]]
            s["failed"] += 1
            s["users_tried"].add(m["user"])
            s["first_seen"] = s["first_seen"] or m["ts"]
            s["last_seen"] = m["ts"]
            continue

        m = ACCEPTED_RE.search(line)
        if m:
            s = stats[m["ip"]]
            # A successful login from an IP that already failed is worth a look
            if s["failed"] > 0:
                s["success_after_fail"].append(f'{m["user"]} at {m["ts"]}')
            s["first_seen"] = s["first_seen"] or m["ts"]
            s["last_seen"] = m["ts"]

    return stats


def classify(s, threshold):
    if s["success_after_fail"] and s["failed"] >= threshold:
        return "CRITICAL - brute force then successful login"
    if s["failed"] >= threshold:
        return "HIGH - brute-force pattern"
    if s["success_after_fail"]:
        return "MEDIUM - login after failed attempts"
    if s["failed"] > 0:
        return "LOW - a few failed attempts"
    return "INFO - successful logins only"


def print_report(stats, threshold):
    rows = sorted(stats.items(), key=lambda kv: kv[1]["failed"], reverse=True)
    total_failed = sum(s["failed"] for _, s in rows)
    flagged = [ip for ip, s in rows if s["failed"] >= threshold or s["success_after_fail"]]

    print("=" * 78)
    print(" SSH BRUTE-FORCE DETECTOR - REPORT")
    print("=" * 78)
    print(f" Source IPs seen:        {len(rows)}")
    print(f" Failed login attempts:  {total_failed}")
    print(f" Alert threshold:        {threshold} failed attempts")
    print(f" IPs flagged:            {len(flagged)}")
    print("-" * 78)
    print(f" {'Source IP':<16}{'Failed':>7}  {'Users tried':<24}Severity")
    print("-" * 78)
    for ip, s in rows:
        users = ", ".join(sorted(s["users_tried"])) or "-"
        if len(users) > 22:
            users = users[:19] + "..."
        print(f" {ip:<16}{s['failed']:>7}  {users:<24}{classify(s, threshold)}")
        for event in s["success_after_fail"]:
            print(f" {'':<16}{'':>7}  -> SUCCESSFUL LOGIN: {event}")
    print("=" * 78)
    if flagged:
        print(" Recommended next steps:")
        print("  1. Block flagged IPs at the firewall (or with fail2ban).")
        print("  2. For any successful login after failures: check that account's activity,")
        print("     reset its password and look for new users, cron jobs or SSH keys.")
        print("  3. Disable password login for SSH and use key-based authentication.")


def write_csv(stats, threshold, path):
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["source_ip", "failed_attempts", "users_tried", "first_seen",
                    "last_seen", "success_after_fail", "severity"])
        for ip, s in sorted(stats.items(), key=lambda kv: kv[1]["failed"], reverse=True):
            w.writerow([ip, s["failed"], ";".join(sorted(s["users_tried"])), s["first_seen"],
                        s["last_seen"], ";".join(s["success_after_fail"]), classify(s, threshold)])


def main():
    p = argparse.ArgumentParser(description="Detect SSH brute-force attempts in a Linux auth log.")
    p.add_argument("logfile", help="path to auth.log (or /var/log/secure)")
    p.add_argument("--threshold", type=int, default=5,
                   help="failed attempts from one IP before it is flagged (default: 5)")
    p.add_argument("--csv", metavar="FILE", help="also save the results to a CSV file")
    args = p.parse_args()

    try:
        with open(args.logfile, encoding="utf-8", errors="replace") as f:
            stats = parse_log(f)
    except FileNotFoundError:
        sys.exit(f"Log file not found: {args.logfile}")
    except PermissionError:
        sys.exit(f"Permission denied: {args.logfile} (try running with sudo)")

    if not stats:
        print("No SSH login events found in this file.")
        return

    print_report(stats, args.threshold)
    if args.csv:
        write_csv(stats, args.threshold, args.csv)
        print(f" CSV saved to {args.csv}")


if __name__ == "__main__":
    main()
