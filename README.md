# SSH Brute-Force Detector

A Python tool that reads a Linux authentication log and finds **SSH brute-force attacks**, including the most dangerous case: an attacker who fails many times and then **logs in successfully**.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![No dependencies](https://img.shields.io/badge/dependencies-none-brightgreen) ![MITRE ATT&CK T1110](https://img.shields.io/badge/MITRE%20ATT%26CK-T1110%20Brute%20Force-red)

---

## The problem

Any server with SSH open to the internet gets password-guessing attempts from bots all day. Every attempt is written to the auth log (`/var/log/auth.log` on Ubuntu/Debian, `/var/log/secure` on RHEL). The problem is volume: a busy log has thousands of lines, and reading them by hand is slow and easy to get wrong. The thing an analyst really needs to know is buried in the noise:

- **Who is attacking?** Which IPs are guessing passwords, and how many times.
- **What are they trying?** Which usernames (root, admin, test...).
- **Did anyone get in?** A successful login from an IP that was just failing is a possible compromise.

I wanted a small tool that answers those three questions in a few seconds, the same way a SOC analyst triages an alert.

## My approach

1. **Studied the log format.** I looked at how `sshd` writes failed and successful logins, including the `invalid user` variant used when the username does not exist.
2. **Wrote regular expressions** to pull out the timestamp, username and source IP from each relevant line, and skip everything else (cron, sudo, etc.).
3. **Grouped events by source IP** with a dictionary: number of failures, usernames tried, first/last seen, and any successful logins that came *after* failures.
4. **Classified each IP by severity:**

   | Severity | Rule |
   |---|---|
   | CRITICAL | Over the threshold **and** then logged in successfully |
   | HIGH | Over the threshold (default: 5 failed attempts) |
   | MEDIUM | Logged in after a few failures (often a user mistyping, but worth a check) |
   | LOW | A few failures, no success |
   | INFO | Successful logins only |

5. **Produced two outputs:** a readable report in the terminal with recommended next steps, and an optional CSV file for a spreadsheet or SIEM.
6. **Tested it** with a synthetic log I generated (safe documentation-only IP ranges) that contains five scenarios, plus unit tests for the parsing logic.

## Tools used

- **Python 3** (standard library only: `re`, `argparse`, `collections`, `csv`)
- **Regular expressions** for log parsing
- **unittest** for automated tests
- **Linux auth log format** (`sshd`)
- **MITRE ATT&CK** for mapping the attack: [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)
- **Git & GitHub** for version control and documentation

## How to run it

```bash
git clone https://github.com/<your-username>/ssh-bruteforce-detector.git
cd ssh-bruteforce-detector

# run against the included sample log
python3 detector.py sample_logs/auth.log

# change the threshold and save a CSV
python3 detector.py sample_logs/auth.log --threshold 10 --csv sample_output/report.csv

# on a real Linux machine (needs permission to read the log)
sudo python3 detector.py /var/log/auth.log

# regenerate the sample log / run the tests
python3 make_sample_log.py
python3 -m unittest
```

## Results

Output on the sample log (`sample_output/report.txt`):

```
==============================================================================
 SSH BRUTE-FORCE DETECTOR - REPORT
==============================================================================
 Source IPs seen:        5
 Failed login attempts:  30
 Alert threshold:        5 failed attempts
 IPs flagged:            3
------------------------------------------------------------------------------
 Source IP        Failed  Users tried             Severity
------------------------------------------------------------------------------
 203.0.113.45         18  admin, ftp, guest, ...  HIGH - brute-force pattern
 198.51.100.23         9  deploy                  CRITICAL - brute force then successful login
                          -> SUCCESSFUL LOGIN: deploy at Nov  3 14:02:53
 192.0.2.10            2  roger                   MEDIUM - login after failed attempts
                          -> SUCCESSFUL LOGIN: roger at Nov  3 14:01:52
 198.51.100.99         1  support                 LOW - a few failed attempts
 192.0.2.55            0  -                       INFO - successful logins only
==============================================================================
```

**What the results mean:**

- **203.0.113.45** tried 10 different usernames 18 times in about 30 seconds. That speed and the list of common names (root, admin, oracle, pi, postgres) are typical of an automated dictionary attack.
- **198.51.100.23** is the real incident: 9 failed passwords against `deploy`, then a successful login. In a real environment I would treat the `deploy` account as compromised: disable it, reset the password, and check what the attacker did after logging in.
- **192.0.2.10** is most likely a false positive (a user who mistyped their password twice). This showed me why alerts need context, and why the tool marks it MEDIUM instead of CRITICAL.

## What I learned

- **Log analysis is pattern recognition.** The same line format repeated thousands of times hides a few events that matter, and grouping by source IP is what makes them visible.
- **Regular expressions need edge cases.** Failed logins for usernames that don't exist are written differently (`Failed password for invalid user ...`), and they are a big part of real attacks. I added a unit test to make sure the pattern catches both forms.
- **Not every alert is an attack.** Thresholds and severity levels help reduce false positives, which matters a lot in a SOC where analysts face alert fatigue.
- **Detection is only half the job.** The report includes response steps (block the IP, investigate the account, switch to SSH keys) because an alert without a next step is not very useful.
- **Automating a repetitive task** turned something that would take me minutes of scrolling into a 1-second command, and that is the kind of work I want to do as a Cybersecurity Analyst.

## Next steps

- [ ] Run it on the auth log from my own Ubuntu VM in my home lab (pfSense + VMs)
- [ ] Add time-window detection (e.g., 5 failures within 60 seconds)
- [ ] Add GeoIP lookup for source IPs
- [ ] Send alerts into a Wazuh SIEM and compare with its built-in brute-force rules

## Project structure

```
ssh-bruteforce-detector/
├── detector.py            # the detector
├── make_sample_log.py     # creates the synthetic test log
├── test_detector.py       # unit tests
├── sample_logs/auth.log   # synthetic log (documentation-only IPs, no real data)
└── sample_output/         # example report (.txt) and CSV output
```

## Notes

- All IPs in the sample data are from ranges reserved for documentation (RFC 5737), so no real systems are involved.
- Only analyze logs from systems you own or are authorized to monitor.
- Built with guidance from an AI assistant; I ran, tested and documented the project myself.

---

**Author:** Roger Pumarola, Cybersecurity student
