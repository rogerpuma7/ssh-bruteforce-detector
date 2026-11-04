#!/usr/bin/env python3
"""
Creates sample_logs/auth.log: a fake (synthetic) auth log for testing the detector.
It uses documentation-only IP ranges (192.0.2.x, 198.51.100.x, 203.0.113.x),
so no real systems or people are involved.

Scenarios included:
  203.0.113.45  -> classic brute force (many users, many failures)
  198.51.100.23 -> brute force against 'deploy', then a SUCCESSFUL login
  192.0.2.10    -> normal user mistypes password twice, then logs in
  198.51.100.99 -> single failed attempt (noise)
  192.0.2.55    -> admin logging in with an SSH key (normal)
"""
import os
from datetime import datetime, timedelta

HOST = "web01"
start = datetime(2026, 11, 3, 14, 0, 0)
lines = []
pid = 2200
t = start


def stamp(dt):
    return dt.strftime("%b %e %H:%M:%S")


def add(msg, seconds):
    global t, pid
    t += timedelta(seconds=seconds)
    pid += 1
    lines.append(f"{stamp(t)} {HOST} sshd[{pid}]: {msg}")


def noise(msg, seconds):
    global t
    t += timedelta(seconds=seconds)
    lines.append(f"{stamp(t)} {HOST} {msg}")


noise("CRON[2190]: pam_unix(cron:session): session opened for user root by (uid=0)", 5)
add("Accepted publickey for admin from 192.0.2.55 port 50122 ssh2", 20)

# Scenario 1: brute force from 203.0.113.45 (dictionary of usernames)
for i, user in enumerate(["root", "root", "admin", "admin", "test", "ubuntu", "root", "oracle",
                          "pi", "root", "admin", "guest", "root", "ftp", "user", "root",
                          "postgres", "root"]):
    invalid = "" if user in ("root",) else "invalid user "
    add(f"Failed password for {invalid}{user} from 203.0.113.45 port {51000 + i} ssh2", 2)

add("Failed password for roger from 192.0.2.10 port 61001 ssh2", 40)
add("Failed password for roger from 192.0.2.10 port 61002 ssh2", 6)
add("Accepted password for roger from 192.0.2.10 port 61003 ssh2", 5)
noise("sudo:    roger : TTY=pts/0 ; PWD=/home/roger ; USER=root ; COMMAND=/usr/bin/apt update", 30)

# Scenario 2: brute force on 'deploy' that eventually succeeds
for i in range(9):
    add(f"Failed password for deploy from 198.51.100.23 port {52000 + i} ssh2", 3)
add("Accepted password for deploy from 198.51.100.23 port 52010 ssh2", 4)

add("Failed password for invalid user support from 198.51.100.99 port 40001 ssh2", 60)
noise("CRON[2290]: pam_unix(cron:session): session closed for user root", 15)

os.makedirs("sample_logs", exist_ok=True)
with open("sample_logs/auth.log", "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"Wrote {len(lines)} lines to sample_logs/auth.log")
