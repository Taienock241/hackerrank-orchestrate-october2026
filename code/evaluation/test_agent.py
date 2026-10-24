"""Regression cases for request authorization and trace-based evidence linking."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main


class RequestIntentCases(unittest.TestCase):
    def test_explicit_account_deletion_is_authorized(self):
        self.assertTrue(main.request_authorizes_deletion("Please delete my account and personal data."))

    def test_negated_close_is_not_authorized(self):
        self.assertFalse(main.request_authorizes_deletion("I need login help. Do not close the account."))

    def test_correction_without_removal_is_not_authorized(self):
        self.assertFalse(main.request_authorizes_deletion("Correct my surname without removing any records."))

    def test_marketing_only_is_not_account_deletion(self):
        self.assertFalse(main.request_authorizes_deletion("Remove me from marketing lists only; keep my account."))

    def test_explicit_non_erasure_information_request(self):
        self.assertFalse(main.request_authorizes_deletion("This is an information request, not a request to erase data."))

    def test_negated_delete_is_not_authorized(self):
        self.assertFalse(main.request_authorizes_deletion("Send me a copy; do not delete anything."))

    def test_marketing_stop_is_not_account_deletion(self):
        self.assertFalse(main.request_authorizes_deletion("Stop promotional emails. I still need the account."))


class LogTraceCases(unittest.TestCase):
    def test_json_trace_id(self):
        self.assertEqual(main.extract_log_trace_id('{"trace_id":"tr-7750694"}'), "tr-7750694")

    def test_key_value_request_id(self):
        self.assertEqual(main.extract_log_trace_id("requestId=tr-2078317"), "tr-2078317")

    def test_pipe_delimited_trace_id(self):
        self.assertEqual(main.extract_log_trace_id("| INFO | account_service | tr-6648486 | profile_lookup_completed"), "tr-6648486")

    def test_legacy_rb_trace_id(self):
        self.assertEqual(main.extract_log_trace_id("trace_id=rb-085737-009"), "rb-085737-009")

    def test_hyphenated_trace_id(self):
        self.assertEqual(main.extract_log_trace_id("trace_id=tr-rp-002"), "tr-rp-002")


if __name__ == "__main__":
    unittest.main()
