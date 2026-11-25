"""False-positive regression tests.

Legitimate multilingual text, RTL scripts, emoji sequences and typographic
characters must not be reported as attacks. These tests encode the promise from
the README: RTL Arabic/Hebrew text and legitimate ZWJ emoji are not attacks.
"""

from __future__ import annotations

import unittest

from invisi_guard import clean, decode, scan

from tests.helpers import read_fixture

ATTACK_SEVERITIES = {"medium", "high"}


def attack_findings(findings):
    return [finding for finding in findings if finding.severity in ATTACK_SEVERITIES]


class RtlTextTests(unittest.TestCase):
    def test_arabic_sentences(self) -> None:
        text = (
            "الموظفون بدوام كامل يحصلون على 15 يومًا إجازة سنوية مدفوعة الأجر. "
            "يجب تقديم إيصالات السفر خلال 30 يومًا.\n"
        )
        self.assertEqual(scan(text), [])

    def test_hebrew_sentences(self) -> None:
        text = "העובדים במשרה מלאה זכאים ל־15 ימי חופשה שנתית בתשלום.\n"
        self.assertEqual(scan(text), [])

    def test_arabic_punctuation_and_numbers(self) -> None:
        self.assertEqual(scan("السعر: 100٪ (خصم) — نعم!\n"), [])

    def test_arabic_with_legitimate_directional_marks_is_only_low(self) -> None:
        text = "\u200fالعنوان الرئيسي\u200e: تقرير الربع الثالث\n"
        findings = scan(text)
        self.assertEqual(attack_findings(findings), [])
        self.assertTrue(all(finding.code == "IG-BIDI-MARK" for finding in findings))

    def test_rtl_fixture_files(self) -> None:
        self.assertEqual(scan(read_fixture("rtl_arabic.txt")), [])
        self.assertEqual(scan(read_fixture("rtl_hebrew.txt")), [])
        self.assertEqual(clean(read_fixture("rtl_arabic.txt"), "strip"), read_fixture("rtl_arabic.txt"))


class EmojiAndJoinerTests(unittest.TestCase):
    def test_family_emoji(self) -> None:
        self.assertEqual(scan("\U0001F468\u200d\U0001F469\u200d\U0001F467\u200d\U0001F466"), [])

    def test_couple_with_heart(self) -> None:
        self.assertEqual(scan("\U0001F469\u200d\u2764\ufe0f\u200d\U0001F468"), [])

    def test_profession_emoji(self) -> None:
        self.assertEqual(scan("\U0001F469\u200d\U0001F4BB developer"), [])

    def test_skin_tone_and_keycap(self) -> None:
        self.assertEqual(scan("\U0001F44D\U0001F3FD 1\ufe0f\u20e3 #\ufe0f\u20e3"), [])

    def test_subdivision_flag_sequence(self) -> None:
        findings = scan("\U0001F3F4\U000E0067\U000E0062\U000E0073\U000E0063\U000E0074\U000E007F")
        self.assertEqual(attack_findings(findings), [])

    def test_zwj_between_indic_letters(self) -> None:
        # Devanagari ksha: ZWJ between Devanagari letters is legitimate typography.
        self.assertEqual(scan("\u0915\u094d\u200d\u0937"), [])

    def test_persian_zwnj(self) -> None:
        self.assertEqual(scan(read_fixture("persian_zwnj.txt")), [])
        self.assertEqual(clean(read_fixture("persian_zwnj.txt"), "strip"), read_fixture("persian_zwnj.txt"))


class TypographyTests(unittest.TestCase):
    def test_combining_accents(self) -> None:
        for text in ("naïve café", "Zürich, Kraków", "cafe\u0301 au lait"):
            with self.subTest(text=text):
                self.assertEqual(scan(text), [])

    def test_math_and_currency(self) -> None:
        self.assertEqual(scan("x \u2264 y, \u2211 = 100\u20ac or $50 or \u00a5200"), [])

    def test_smart_quotes_and_dashes(self) -> None:
        self.assertEqual(scan("\u201cquoted\u201d \u2014 dash \u2013 en dash\u2026"), [])

    def test_bom_prefixed_document(self) -> None:
        text = "\ufeff# Title\n\nBody text.\n"
        self.assertEqual(scan(text), [])
        self.assertEqual(clean(text, "strip"), text)

    def test_no_decode_false_positives_in_clean_documents(self) -> None:
        for fixture in ("clean_english.txt", "rtl_arabic.txt", "rtl_hebrew.txt", "emoji_legit.txt"):
            with self.subTest(fixture=fixture):
                self.assertEqual(decode(read_fixture(fixture)), [])

    def test_clean_document_strip_is_identity(self) -> None:
        for fixture in (
            "clean_english.txt",
            "rtl_arabic.txt",
            "rtl_hebrew.txt",
            "persian_zwnj.txt",
            "emoji_legit.txt",
            "japanese_mixed.txt",
        ):
            with self.subTest(fixture=fixture):
                text = read_fixture(fixture)
                self.assertEqual(clean(text, "strip"), text)


if __name__ == "__main__":
    unittest.main()
