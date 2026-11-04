import unittest
from detector import parse_log, classify

LOG = """\
Nov  3 14:00:01 web01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2
Nov  3 14:00:02 web01 sshd[2]: Failed password for invalid user admin from 203.0.113.45 port 2 ssh2
Nov  3 14:00:03 web01 sshd[3]: Failed password for root from 203.0.113.45 port 3 ssh2
Nov  3 14:00:04 web01 sshd[4]: Accepted password for root from 203.0.113.45 port 4 ssh2
Nov  3 14:00:05 web01 sshd[5]: Accepted publickey for admin from 192.0.2.55 port 5 ssh2
Nov  3 14:00:06 web01 CRON[6]: pam_unix(cron:session): session opened for user root
"""


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.stats = parse_log(LOG.splitlines())

    def test_counts_failures_per_ip(self):
        self.assertEqual(self.stats["203.0.113.45"]["failed"], 3)

    def test_collects_usernames_including_invalid_users(self):
        self.assertEqual(self.stats["203.0.113.45"]["users_tried"], {"root", "admin"})

    def test_flags_success_after_failures(self):
        self.assertEqual(len(self.stats["203.0.113.45"]["success_after_fail"]), 1)
        self.assertTrue(classify(self.stats["203.0.113.45"], 3).startswith("CRITICAL"))

    def test_key_login_without_failures_is_info(self):
        self.assertTrue(classify(self.stats["192.0.2.55"], 3).startswith("INFO"))

    def test_ignores_non_ssh_lines(self):
        self.assertEqual(len(self.stats), 2)


if __name__ == "__main__":
    unittest.main()
