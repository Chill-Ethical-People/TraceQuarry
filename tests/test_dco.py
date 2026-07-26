from __future__ import annotations

import unittest

from tools.check_dco import has_valid_sign_off


class DcoCheckTests(unittest.TestCase):
    def test_accepts_conventional_sign_off_trailer(self) -> None:
        message = "Add parser coverage\n\nSigned-off-by: Analyst Name <analyst@example.com>"

        self.assertTrue(has_valid_sign_off(message))

    def test_rejects_missing_or_incomplete_sign_off(self) -> None:
        self.assertFalse(has_valid_sign_off("Add parser coverage"))
        self.assertFalse(has_valid_sign_off("Signed-off-by: Analyst Name"))


if __name__ == "__main__":
    unittest.main()
