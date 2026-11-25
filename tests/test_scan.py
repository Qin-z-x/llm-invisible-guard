"""Tests for invisi_guard.scan()."""

from __future__ import annotations

import unittest

from invisi_guard import SEVERITIES, decode, scan, summarize

from tests.helpers import read_fixture


def codes(findings):
    return [finding.code for finding in findings]


def severities(findings):
    return [finding.severity for finding in findings]


class CleanInputTests(unittest.TestCase):
    def test_empty_string_has_no_findings(self) -> None:
        self.assertEqual(scan(""), [])

    def test_plain_english_has_no_findings(self) -> None:
        self.assertEqual(scan(read_fixture("clean_english.txt")), [])

    def test_plain_rtl_arabic_has_no_findings(self) -> None:
        self.assertEqual(scan(read_fixture("rtl_arabic.txt")), [])

    def test_plain_rtl_hebrew_has_no_findings(self) -> None:
        self.assertEqual(scan(read_fixture("rtl_hebrew.txt")), [])

    def test_persian_zwnj_is_legitimate(self) -> None:
        self.assertEqual(scan(read_fixture("persian_zwnj.txt")), [])

    def test_cyrillic_only_is_not_confusable(self) -> None:
        self.assertEqual(scan(read_fixture("cyrillic_only.txt")), [])

    def test_greek_only_is_not_confusable(self) -> None:
        self.assertEqual(scan(read_fixture("greek_only.txt")), [])

    def test_japanese_mixed_scripts_are_normal(self) -> None:
        self.assertEqual(scan(read_fixture("japanese_mixed.txt")), [])

    def test_latin_cjk_token_is_not_flagged(self) -> None:
        self.assertEqual(scan("iPhone手机很好用"), [])

    def test_bom_at_start_is_not_an_attack(self) -> None:
        self.assertEqual(scan("\ufeffHello"), [])

    def test_plain_emoji_is_not_an_attack(self) -> None:
        self.assertEqual(scan("Great job \U0001F600\U0001F44D done."), [])


class EmojiFalsePositiveTests(unittest.TestCase):
    def test_emoji_zwj_sequences_have_no_attack_severity(self) -> None:
        findings = scan(read_fixture("emoji_legit.txt"))
        self.assertTrue(all(severity == "low" for severity in severities(findings)))
        self.assertNotIn("IG-ZW-RUN", codes(findings))

    def test_subdivision_flag_is_classified_benign(self) -> None:
        findings = scan(read_fixture("emoji_legit.txt"))
        benign = [finding for finding in findings if finding.code == "IG-TAG-BENIGN-FLAG"]
        # The fixture contains two subdivision flags (one labelled "Waving flag", one "England flag").
        self.assertEqual(len(benign), 2)
        self.assertTrue(all(finding.severity == "low" for finding in benign))
        self.assertTrue(all(finding.data["benign"] for finding in benign))
        self.assertTrue(all(finding.data["decoded"] == "gbeng" for finding in benign))
        self.assertEqual(decode(read_fixture("emoji_legit.txt")), [])

    def test_heart_with_vs16_is_not_flagged(self) -> None:
        self.assertEqual(scan("I \u2764\ufe0f Unicode."), [])

    def test_emoji_and_cjk_presentation_selectors_are_not_flagged(self) -> None:
        self.assertEqual(scan("\u845b\U000e0100 and \u2764\ufe0f"), [])


class BidiTests(unittest.TestCase):
    def test_trojan_source_override_is_high(self) -> None:
        findings = scan(read_fixture("trojan_source_comment.txt"))
        override = [finding for finding in findings if finding.code == "IG-BIDI-OVERRIDE"]
        self.assertEqual(len(override), 1)
        self.assertEqual(override[0].severity, "high")
        self.assertIn("RLO", override[0].message)

    def test_trojan_source_terminator_is_escalated_to_high(self) -> None:
        findings = scan(read_fixture("trojan_source_comment.txt"))
        terminator = [finding for finding in findings if finding.code == "IG-BIDI-TERMINATOR"]
        self.assertEqual(len(terminator), 1)
        self.assertEqual(terminator[0].severity, "high")
        self.assertTrue(terminator[0].data.get("paired"))

    def test_balanced_isolate_pair_is_high(self) -> None:
        findings = scan(read_fixture("bidi_isolate_pair.txt"))
        isolates = [finding for finding in findings if finding.code == "IG-BIDI-ISOLATE"]
        self.assertEqual(len(isolates), 2)
        self.assertTrue(all(finding.severity == "high" for finding in isolates))

    def test_single_directional_mark_is_low(self) -> None:
        findings = scan("left\u200e right")
        self.assertEqual(codes(findings), ["IG-BIDI-MARK"])
        self.assertEqual(findings[0].severity, "low")

    def test_arabic_with_directional_marks_is_not_high(self) -> None:
        findings = scan("\u200fمرحبا بالعالم\u200e")
        self.assertTrue(all(finding.severity == "low" for finding in findings))


class ZeroWidthTests(unittest.TestCase):
    def test_single_zero_width_is_low(self) -> None:
        findings = scan("in\u200bvisible")
        self.assertEqual(codes(findings), ["IG-ZW-RUN"])
        self.assertEqual(findings[0].severity, "low")

    def test_short_zero_width_run_is_medium(self) -> None:
        findings = scan("in\u200b\u200cvisible")
        self.assertEqual(findings[0].severity, "medium")

    def test_long_zero_width_run_is_high(self) -> None:
        findings = scan("x" + "\u200b\u200c" * 4 + "y")
        self.assertEqual(codes(findings), ["IG-ZW-RUN"])
        self.assertEqual(findings[0].severity, "high")

    def test_zero_width_payload_is_detected_with_decoded_text(self) -> None:
        findings = scan(read_fixture("zero_width_payload.txt"))
        payload_findings = [finding for finding in findings if finding.code == "IG-ZW-ENC"]
        self.assertEqual(len(payload_findings), 1)
        self.assertEqual(payload_findings[0].severity, "high")
        self.assertIn("PWNED-7F3A", payload_findings[0].data["decoded"])
        self.assertNotIn("IG-ZW-RUN", codes(findings))

    def test_zero_width_zwj_variant_payload(self) -> None:
        findings = scan(read_fixture("zero_width_payload_zwj.txt"))
        decoded = [finding.data["decoded"] for finding in findings if finding.code == "IG-ZW-ENC"]
        self.assertEqual(decoded, ["ZWJ-VARIANT"])

    def test_zero_width_lsb_variant_payload(self) -> None:
        findings = scan(read_fixture("zero_width_payload_lsb.txt"))
        decoded = [finding.data["decoded"] for finding in findings if finding.code == "IG-ZW-ENC"]
        self.assertEqual(decoded, ["LSB-ORDER"])


class TagAndVariationSelectorTests(unittest.TestCase):
    def test_tag_payload_is_high_and_decoded(self) -> None:
        findings = scan(read_fixture("tag_payload.txt"))
        tag_findings = [finding for finding in findings if finding.code == "IG-TAG-ASCII"]
        self.assertEqual(len(tag_findings), 1)
        self.assertEqual(tag_findings[0].severity, "high")
        self.assertEqual(tag_findings[0].data["decoded"], "EXFILTRATE SECRETS")

    def test_vs_hex_payload_is_high_and_decoded(self) -> None:
        findings = scan(read_fixture("vs_payload.txt"))
        payload_findings = [finding for finding in findings if finding.code == "IG-VS-ENC"]
        self.assertEqual(len(payload_findings), 1)
        self.assertEqual(payload_findings[0].severity, "high")
        self.assertEqual(payload_findings[0].data["decoded"], "HIDDEN-VS")

    def test_vs_byte_payload_is_high_and_decoded(self) -> None:
        findings = scan(read_fixture("vs_payload_bytes.txt"))
        payload_findings = [finding for finding in findings if finding.code == "IG-VS-ENC"]
        self.assertEqual(len(payload_findings), 1)
        self.assertEqual(payload_findings[0].data["decoded"], "HELLO")

    def test_single_presentation_selector_is_not_flagged(self) -> None:
        self.assertEqual(scan("\u2764\ufe0f"), [])


class ConfusableTests(unittest.TestCase):
    def test_cyrillic_looking_token_is_high(self) -> None:
        findings = scan(read_fixture("mixed_script.txt"))
        confusable = [finding for finding in findings if finding.code == "IG-CONF-MIXED-SCRIPT"]
        self.assertEqual(len(confusable), 1)
        self.assertEqual(confusable[0].severity, "high")
        self.assertIn("CYRILLIC", confusable[0].data["scripts"])

    def test_greek_looking_token_is_high(self) -> None:
        findings = scan(read_fixture("mixed_script_greek.txt"))
        confusable = [finding for finding in findings if finding.code == "IG-CONF-MIXED-SCRIPT"]
        self.assertEqual(len(confusable), 1)
        self.assertEqual(confusable[0].severity, "high")
        self.assertIn("GREEK", confusable[0].data["scripts"])


class FindingContractTests(unittest.TestCase):
    def test_findings_are_sorted_by_offset(self) -> None:
        findings = scan(read_fixture("hidden_instructions.txt"))
        offsets = [(finding.start, finding.end) for finding in findings]
        self.assertEqual(offsets, sorted(offsets))

    def test_scan_is_deterministic(self) -> None:
        text = read_fixture("hidden_instructions.txt")
        first = [finding.to_dict() for finding in scan(text)]
        second = [finding.to_dict() for finding in scan(text)]
        self.assertEqual(first, second)

    def test_finding_fields_respect_contract(self) -> None:
        text = read_fixture("hidden_instructions.txt")
        findings = scan(text)
        self.assertGreater(len(findings), 0)
        for finding in findings:
            self.assertIn(finding.severity, SEVERITIES)
            self.assertTrue(finding.code.startswith("IG-"))
            self.assertGreaterEqual(finding.start, 0)
            self.assertLessEqual(finding.start, finding.end)
            self.assertLessEqual(finding.end, len(text))
            self.assertGreaterEqual(finding.column, 1)
            self.assertGreaterEqual(finding.line, 1)
            self.assertTrue(finding.message)
            self.assertIsInstance(finding.to_dict()["data"], dict)

    def test_multiline_locations_are_correct(self) -> None:
        text = "line one\nline two \u202e here\nline three"
        findings = scan(text)
        override = [finding for finding in findings if finding.code == "IG-BIDI-OVERRIDE"][0]
        self.assertEqual(override.line, 2)
        self.assertEqual(override.column, 10)

    def test_summary_counts_match_findings(self) -> None:
        findings = scan(read_fixture("hidden_instructions.txt"))
        summary = summarize(findings)
        self.assertEqual(summary["total"], len(findings))
        self.assertEqual(summary["high"] + summary["medium"] + summary["low"], len(findings))
        self.assertEqual(sum(summary["by_code"].values()), len(findings))

    def test_scan_rejects_bytes(self) -> None:
        with self.assertRaises(TypeError):
            scan(b"invisible \xe2\x80\x8b")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
