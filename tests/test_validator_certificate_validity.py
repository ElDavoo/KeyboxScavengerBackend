from __future__ import annotations

import unittest
from datetime import datetime, timezone

from scavenger.validator import KeyboxValidator


class NewStyleCertificate:
    def __init__(self, not_valid_before: datetime, not_valid_after: datetime):
        self._not_valid_before = not_valid_before
        self._not_valid_after = not_valid_after

    @property
    def not_valid_before_utc(self) -> datetime:
        return self._not_valid_before

    @property
    def not_valid_after_utc(self) -> datetime:
        return self._not_valid_after

    @property
    def not_valid_before(self) -> datetime:
        raise AssertionError("legacy property should not be used when UTC properties exist")

    @property
    def not_valid_after(self) -> datetime:
        raise AssertionError("legacy property should not be used when UTC properties exist")


class CertificateValidityTests(unittest.TestCase):
    def test_prefers_utc_certificate_validity_properties(self):
        not_before = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
        not_after = datetime(2027, 1, 1, 0, 0, tzinfo=timezone.utc)
        certificate = NewStyleCertificate(not_before, not_after)

        self.assertIs(KeyboxValidator._not_valid_before(certificate), not_before)
        self.assertIs(KeyboxValidator._not_valid_after(certificate), not_after)


if __name__ == "__main__":
    unittest.main()