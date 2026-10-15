"""Real template unit checks, run only on the rendered artifact."""

# ruff: noqa: PT009 -- stdlib unittest keeps template CI dependency-free

import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "public"


class LandingTests(unittest.TestCase):
    def test_recorded_ci_pins_and_hashed_requirements(self):
        runpy.run_path(str(ROOT.parent / "ci/pin_check.py"))["validate"]()

    def test_form_is_closed_and_consent_is_explicit(self):
        text = (ROOT / "index.html").read_text()
        self.assertIn('id="consent" type="checkbox" required disabled', text)
        self.assertIn("form-action 'none'", text)
        self.assertIn("connect-src 'none'", text)
        self.assertNotIn("{{", text)

    def test_privacy_and_rights_paths_exist(self):
        for name in ("privacy.html", "rights.html"):
            self.assertTrue((ROOT / name).is_file())
        self.assertIn("90 days", (ROOT / "privacy.html").read_text())

    def test_usable_small_screens_keyboard_and_reduced_motion(self):
        css = (ROOT / "styles.css").read_text()
        self.assertIn("@media(max-width:700px)", css)
        self.assertIn(":focus-visible", css)
        self.assertIn("prefers-reduced-motion:reduce", css)

    def test_no_contact_sinks_or_transport(self):
        js = (ROOT / "waitlist.js").read_text()
        for term in ("fetch(", "console.", ".value", "localStorage", "sessionStorage", "innerHTML"):
            self.assertNotIn(term, js)


if __name__ == "__main__":
    unittest.main()
