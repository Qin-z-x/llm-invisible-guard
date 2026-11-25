"""Tests for invisi_guard.clean()."""

from __future__ import annotations

import unittest

from invisi_guard import clean, scan
from invisi_guard.chars import is_bidi_control
from invisi_guard.demo import CLEAN_MEMO, build_poisoned_text

from tests.helpers import has_invisible, read_fixture


def contains_invisible(text: str) -> bool:
    return bool(has_invisible(text))


class StripTests(unittest.TestCase):
    def test_strip_restores_visible_text_of_poisoned_memo(self) -> None:
        poisoned = build_poisoned_text()
        self.assertNotEqual(poisoned, CLEAN_MEMO)
        self.assertEqual(clean(poisoned, "strip"), CLEAN_MEMO)

    def test_strip_removes_zero_width_payload(self) -> None:
        fixture = read_fixture("zero_width_payload.txt")
        stripped = clean(fixture, "strip")
        self.assertNotIn("\u200b", stripped)
        self.assertNotIn("\u200c", stripped)
        self.assertIn("The quarterly report is attached.", stripped)
        self.assertIn("Please review it before the meeting.", stripped)

    def test_strip_removes_tag_payload(self) -> None:
        stripped = clean(read_fixture("tag_payload.txt"), "strip")
        self.assertEqual(stripped, "Normal paragraph.  End of paragraph.\n")

    def test_strip_removes_variation_selector_payload(self) -> None:
        stripped = clean(read_fixture("vs_payload.txt"), "strip")
        self.assertFalse(contains_invisible(stripped))
        self.assertIn("Great work", stripped)

    def test_strip_removes_bidi_controls(self) -> None:
        fixture = read_fixture("trojan_source_comment.txt")
        stripped = clean(fixture, "strip")
        self.assertFalse(any(is_bidi_control(ch) for ch in stripped))
        expected = "".join(ch for ch in fixture if not is_bidi_control(ch))
        self.assertEqual(stripped, expected)

    def test_strip_preserves_emoji_zwj_sequences(self) -> None:
        fixture = read_fixture("emoji_legit.txt")
        self.assertEqual(clean(fixture, "strip"), fixture)

    def test_strip_preserves_persian_zwnj(self) -> None:
        fixture = read_fixture("persian_zwnj.txt")
        self.assertEqual(clean(fixture, "strip"), fixture)

    def test_strip_preserves_utf8_bom_at_start(self) -> None:
        self.assertEqual(clean("\ufeffHello", "strip"), "\ufeffHello")

    def test_strip_removes_bom_in_the_middle(self) -> None:
        stripped = clean("a\ufeffb", "strip")
        self.assertEqual(stripped, "ab")

    def test_strip_preserves_subdivision_flag_sequences(self) -> None:
        flag = "\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F"
        self.assertEqual(clean("Flag: " + flag, "strip"), "Flag: " + flag)

    def test_strip_keeps_clean_text_unchanged(self) -> None:
        text = read_fixture("clean_english.txt")
        self.assertEqual(clean(text, "strip"), text)

    def test_stripped_payload_fixtures_have_no_high_findings(self) -> None:
        for fixture in (
            "zero_width_payload.txt",
            "zero_width_payload_zwj.txt",
            "zero_width_payload_lsb.txt",
            "tag_payload.txt",
            "vs_payload.txt",
            "vs_payload_bytes.txt",
            "trojan_source_comment.txt",
        ):
            with self.subTest(fixture=fixture):
                stripped = clean(read_fixture(fixture), "strip")
                high = [finding for finding in scan(stripped) if finding.severity == "high"]
                self.assertEqual(high, [])


class EscapeTests(unittest.TestCase):
    def test_escape_replaces_zero_width_with_marker(self) -> None:
        self.assertEqual(clean("a\u200bb", "escape"), "a\\u200Bb")

    def test_escape_replaces_astral_tag_char_with_U_marker(self) -> None:
        self.assertEqual(clean("a\U000E0041b", "escape"), "a\\U000E0041b")

    def test_escape_replaces_stray_variation_selector(self) -> None:
        output = clean("a \ufe0f b", "escape")
        self.assertIn("\\uFE0F", output)

    def test_escape_output_has_no_invisible_characters(self) -> None:
        output = clean(read_fixture("zero_width_payload.txt"), "escape")
        self.assertFalse(contains_invisible(output))
        self.assertIn("\\u200B", output)

    def test_escape_keeps_legitimate_emoji_unchanged(self) -> None:
        fixture = read_fixture("emoji_legit.txt")
        self.assertEqual(clean(fixture, "escape"), fixture)

    def test_escape_keeps_plain_text_unchanged(self) -> None:
        text = "Plain ASCII text, 100% unchanged."
        self.assertEqual(clean(text, "escape"), text)


class ReportTests(unittest.TestCase):
    def test_report_structure_and_hidden_content(self) -> None:
        report = clean(read_fixture("hidden_instructions.txt"), "report")
        self.assertIsInstance(report, dict)
        for key in (
            "tool",
            "version",
            "mode",
            "input_chars",
            "removed_chars",
            "removed_by_class",
            "findings",
            "payloads",
            "summary",
            "hidden_content",
        ):
            self.assertIn(key, report)
        self.assertEqual(report["mode"], "report")
        self.assertTrue(report["hidden_content"])
        self.assertGreater(report["removed_chars"], 0)
        self.assertGreater(len(report["payloads"]), 0)
        self.assertGreater(len(report["findings"]), 0)

    def test_report_counts_classes(self) -> None:
        report = clean(build_poisoned_text(), "report")
        by_class = report["removed_by_class"]
        self.assertGreater(by_class["zero_width"], 0)
        self.assertGreater(by_class["unicode_tag"], 0)

    def test_report_on_clean_text_has_no_hidden_content(self) -> None:
        report = clean(read_fixture("clean_english.txt"), "report")
        self.assertFalse(report["hidden_content"])
        self.assertEqual(report["removed_chars"], 0)
        self.assertEqual(report["payloads"], [])
        self.assertEqual(report["findings"], [])

    def test_report_removed_chars_matches_class_sum(self) -> None:
        report = clean(read_fixture("zero_width_payload.txt"), "report")
        self.assertEqual(
            report["removed_chars"], sum(report["removed_by_class"].values())
        )


class ApiContractTests(unittest.TestCase):
    def test_invalid_mode_raises(self) -> None:
        with self.assertRaises(ValueError):
            clean("text", "shred")  # type: ignore[arg-type]

    def test_non_string_input_raises(self) -> None:
        with self.assertRaises(TypeError):
            clean(b"bytes", "strip")  # type: ignore[arg-type]

    def test_default_mode_is_strip(self) -> None:
        self.assertEqual(clean("a\u200bb"), "ab")


if __name__ == "__main__":
    unittest.main()
