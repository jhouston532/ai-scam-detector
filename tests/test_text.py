"""
Unit tests for src/analysis/text.py

Run from the project root:

    pytest tests/test_text.py

Imported as `analysis.text`, so these rely on `pythonpath = src` (see
pytest.ini). No network at all — text.py has no external calls.

Each test builds a small HTML fragment or passes a string directly to an
extractor. Where a homoglyph or zero-width character is needed, it's written
with an explicit \\u escape so the intent is unambiguous.
"""
from bs4 import BeautifulSoup

from analysis.text import (
    build_text_report,
    detect_text_obfuscation,
    extract_key_snippets,
    extract_structured_text,
    extract_text_signals,
    extract_visible_text,
    normalize_text,
    report_from_html,
    segment_text,
)


def _soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


# ---------------------------------------------------------------------------
# extract_visible_text
# ---------------------------------------------------------------------------
class TestExtractVisibleText:
    def test_returns_body_text_only(self):
        html = (
            "<html><head><title>T</title><style>.x{color:red}</style></head>"
            "<body><h1>Hello</h1><script>var a=1;</script><p>World</p></body></html>"
        )
        assert extract_visible_text(_soup(html)) == "Hello World"

    def test_excludes_scripts_and_styles(self):
        html = "<body><p>Keep</p><script>secret()</script><style>.a{}</style></body>"
        text = extract_visible_text(_soup(html))
        assert "secret" not in text
        assert ".a{}" not in text
        assert text == "Keep"

    def test_collapses_whitespace(self):
        html = "<body><p>one</p>\n\n   <p>two</p></body>"
        assert extract_visible_text(_soup(html)) == "one two"

    def test_ignores_comments(self):
        html = "<body><p>visible</p><!-- hidden comment --></body>"
        assert extract_visible_text(_soup(html)) == "visible"


# ---------------------------------------------------------------------------
# extract_structured_text
# ---------------------------------------------------------------------------
class TestExtractStructuredText:
    HTML = (
        "<html><head>"
        "<title>Account Alert</title>"
        '<meta name="description" content="Please verify">'
        "</head><body>"
        "<h1>Urgent Notice</h1><h2>Action Required</h2>"
        "<p>Your account is suspended.</p><p>Confirm now.</p>"
        "<ul><li>Step one</li><li>Step two</li></ul>"
        '<a href="/x">Verify Account</a><a href="/y">Contact Us</a>'
        "<button>Submit</button>"
        '<input type="submit" value="Send">'
        '<img src="a.png" alt="logo image">'
        '<span aria-label="close dialog">x</span>'
        '<input type="text" placeholder="Enter password">'
        "<label>Card number</label>"
        "</body></html>"
    )

    def test_title_and_description(self):
        s = extract_structured_text(_soup(self.HTML))
        assert s.title == "Account Alert"
        assert s.meta_description == "Please verify"

    def test_headings_paragraphs_lists(self):
        s = extract_structured_text(_soup(self.HTML))
        assert s.headings == ["Urgent Notice", "Action Required"]
        assert s.paragraphs == ["Your account is suspended.", "Confirm now."]
        assert s.list_items == ["Step one", "Step two"]

    def test_links_and_buttons(self):
        s = extract_structured_text(_soup(self.HTML))
        assert s.link_texts == ["Verify Account", "Contact Us"]
        assert s.button_texts == ["Submit", "Send"]  # <button> + submit input value

    def test_alts_aria_placeholders_labels(self):
        s = extract_structured_text(_soup(self.HTML))
        assert s.image_alts == ["logo image"]
        assert s.aria_labels == ["close dialog"]
        assert s.placeholders == ["Enter password"]
        assert s.labels == ["Card number"]


# ---------------------------------------------------------------------------
# normalize_text
# ---------------------------------------------------------------------------
class TestNormalizeText:
    def test_collapses_whitespace(self):
        assert normalize_text("a\n\t  b   c") == "a b c"

    def test_nfkc_folds_fullwidth(self):
        # Fullwidth "ＶＥＲＩＦＹ" -> ASCII "VERIFY" under NFKC.
        assert normalize_text("\uff36\uff25\uff32\uff29\uff26\uff39") == "VERIFY"


# ---------------------------------------------------------------------------
# detect_text_obfuscation
# ---------------------------------------------------------------------------
class TestDetectObfuscation:
    def test_zero_width_characters(self):
        obf = detect_text_obfuscation("hello\u200bworld\u200bfoo")
        assert obf.has_zero_width is True
        assert obf.zero_width_count == 2

    def test_homoglyph_mixed_script_word(self):
        # "paypal" with a Cyrillic 'а' (U+0430) in place of Latin 'a'.
        obf = detect_text_obfuscation("secure p\u0430ypal login")
        assert "p\u0430ypal" in obf.mixed_script_words

    def test_excessive_spacing(self):
        obf = detect_text_obfuscation("V E R I F Y your account")
        assert obf.has_excessive_spacing is True

    def test_clean_text_flags_nothing(self):
        obf = detect_text_obfuscation("This is a normal sentence.")
        assert obf.has_zero_width is False
        assert obf.mixed_script_words == []
        assert obf.has_excessive_spacing is False


# ---------------------------------------------------------------------------
# extract_text_signals
# ---------------------------------------------------------------------------
class TestExtractTextSignals:
    def test_scam_lexicon_hits(self):
        text = (
            "ACT NOW! You won a FREE prize. Verify your account immediately "
            "or it will be suspended."
        )
        sig = extract_text_signals(text)
        assert set(sig.urgency_hits) == {"immediately", "act now"}
        assert set(sig.money_hits) == {"free", "prize", "you won"}
        assert set(sig.credential_hits) == {"verify your account"}
        assert set(sig.threat_hits) == {"suspended"}

    def test_exclamation_count(self):
        assert extract_text_signals("Wow! Amazing! Buy!").exclamation_count == 3

    def test_uppercase_ratio(self):
        # ACT, NOW, WIN are all-caps; to, big are not -> 3/5.
        assert extract_text_signals("ACT NOW to WIN big").uppercase_ratio == 0.6

    def test_email_and_url_extraction(self):
        sig = extract_text_signals("Contact support@secure-verify.com or http://evil.example.com/login now")
        assert sig.emails == ["support@secure-verify.com"]
        assert sig.urls_in_text == ["http://evil.example.com/login"]

    def test_phone_number_extraction(self):
        sig = extract_text_signals("Call us at +1 (800) 555-1234 anytime")
        assert len(sig.phone_numbers) == 1
        assert "800" in sig.phone_numbers[0]

    def test_crypto_address_extraction(self):
        sig = extract_text_signals(
            "Send to 0x52908400098527886E0F7030069857D2E4169EE7 please"
        )
        assert len(sig.crypto_addresses) == 1
        assert sig.crypto_addresses[0].startswith("0x")

    def test_currency_symbols(self):
        assert extract_text_signals("Pay $50 or £40 or €30").currency_symbol_count == 3


# ---------------------------------------------------------------------------
# extract_key_snippets
# ---------------------------------------------------------------------------
class TestExtractKeySnippets:
    def test_orders_and_dedupes(self):
        s = extract_structured_text(TestExtractStructuredText.HTML and _soup(TestExtractStructuredText.HTML))
        snippets = extract_key_snippets(s)
        assert snippets[0] == "Account Alert"          # title first
        assert "Urgent Notice" in snippets             # heading
        assert "Please verify" in snippets             # meta description
        assert len(snippets) == len(set(snippets))     # no duplicates


# ---------------------------------------------------------------------------
# segment_text
# ---------------------------------------------------------------------------
class TestSegmentText:
    TEXT = "Sentence one is here. Sentence two is here. Sentence three is here."

    def test_splits_on_sentence_boundaries_under_budget(self):
        chunks = segment_text(self.TEXT, max_chars=30)
        assert len(chunks) == 3
        assert chunks[0] == "Sentence one is here."

    def test_single_chunk_when_budget_is_large(self):
        chunks = segment_text(self.TEXT, max_chars=1000)
        assert chunks == [self.TEXT]

    def test_empty_text_returns_empty_list(self):
        assert segment_text("") == []
        assert segment_text("   ") == []

    def test_oversized_sentence_is_hard_split(self):
        long_sentence = "x" * 50  # no sentence boundary, exceeds budget
        chunks = segment_text(long_sentence, max_chars=20)
        assert all(len(c) <= 20 for c in chunks)
        assert "".join(chunks) == long_sentence


# ---------------------------------------------------------------------------
# build_text_report / report_from_html
# ---------------------------------------------------------------------------
class TestBuildReport:
    HTML = (
        "<html><head><title>Account Suspended</title>"
        '<meta name="description" content="Verify your account immediately">'
        "</head><body>"
        "<h1>URGENT: Action Required</h1>"
        "<p>You won a FREE prize! Claim your reward now.</p>"
        "<p>Your account is suspended. Verify your account or it will be deleted.</p>"
        '<a href="/verify">Verify Now</a>'
        "<button>Confirm</button>"
        "</body></html>"
    )

    def _report(self):
        return report_from_html(self.HTML)

    def test_feature_counts(self):
        f = self._report().features
        assert f["title"] == "Account Suspended"
        assert f["urgency_hit_count"] == 2      # "urgent", "verify now"
        assert f["money_hit_count"] == 5        # free, prize, you won, claim your, reward
        assert f["credential_hit_count"] == 1   # "verify your account"
        assert f["threat_hit_count"] == 2       # "suspended", "will be deleted"
        assert f["exclamation_count"] == 1
        assert f["has_zero_width"] is False

    def test_meta_description_not_in_visible_text(self):
        # meta description lives in <head>, so it must not leak into body text.
        report = self._report()
        assert "immediately" not in report.visible_text

    def test_key_snippets_present(self):
        report = self._report()
        assert report.key_snippets[0] == "Account Suspended"

    def test_report_is_json_serializable(self):
        import json

        dumped = json.dumps(self._report().to_dict())
        assert '"features"' in dumped

    def test_build_from_shared_soup_matches_wrapper(self):
        soup = _soup(self.HTML)
        direct = build_text_report(soup)
        assert direct.features == self._report().features