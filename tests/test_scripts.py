"""
Unit tests for src/analysis/scripts.py

Run from the project root:

    pytest tests/test_scripts.py

Imported as `analysis.scripts`, so these rely on `pythonpath = src` (see
pytest.ini). get_domain uses tldextract (public-suffix list; fetched once or
from the bundled snapshot). All hosts are unambiguous .com/.net so origin
classification is stable.

None of these tests execute any JavaScript — the "code" strings are inert data
passed to regex-based extractors.
"""
from bs4 import BeautifulSoup

from analysis.scripts import (
    build_scripts_report,
    chunk_script,
    count_json_data_blocks,
    extract_event_handlers,
    extract_external_scripts,
    extract_inline_scripts,
    extract_js_urls,
    extract_script_features,
    normalize_script,
    report_from_html,
)


def _soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


BASE = "https://example.com/"
HOME = "example.com"


# ---------------------------------------------------------------------------
# extract_inline_scripts / count_json_data_blocks
# ---------------------------------------------------------------------------
class TestInlineScripts:
    HTML = (
        "<script>var a=1;</script>"
        '<script src="x.js"></script>'
        '<script type="application/ld+json">{"a":1}</script>'
        '<script type="text/javascript">run();</script>'
        "<script></script>"  # empty -> ignored
    )

    def test_returns_only_executable_inline_bodies(self):
        assert extract_inline_scripts(_soup(self.HTML)) == ["var a=1;", "run();"]

    def test_counts_json_data_blocks(self):
        assert count_json_data_blocks(_soup(self.HTML)) == 1

    def test_ignores_external_and_empty(self):
        scripts = extract_inline_scripts(_soup(self.HTML))
        assert all(s.strip() for s in scripts)
        assert "x.js" not in " ".join(scripts)


# ---------------------------------------------------------------------------
# extract_external_scripts
# ---------------------------------------------------------------------------
class TestExternalScripts:
    HTML = (
        '<script src="/app.js"></script>'
        '<script src="https://www.google-analytics.com/analytics.js"></script>'
        '<script src="https://cdn.jsdelivr.net/npm/x.js" async></script>'
        '<script src="https://evil.tracker-xyz.com/e.js" defer></script>'
    )

    def test_origin_classification(self):
        ext = extract_external_scripts(_soup(self.HTML), BASE, HOME)
        assert [e.origin for e in ext] == [
            "first-party",
            "known-tracker",
            "known-cdn",
            "third-party",
        ]

    def test_resolves_and_flags_off_domain(self):
        ext = extract_external_scripts(_soup(self.HTML), BASE, HOME)
        assert ext[0].url == "https://example.com/app.js"
        assert ext[0].off_domain is False
        assert ext[1].domain == "google-analytics.com"
        assert ext[1].off_domain is True

    def test_async_and_defer_flags(self):
        ext = extract_external_scripts(_soup(self.HTML), BASE, HOME)
        assert ext[2].is_async is True
        assert ext[3].is_defer is True


# ---------------------------------------------------------------------------
# extract_event_handlers
# ---------------------------------------------------------------------------
class TestEventHandlers:
    HTML = (
        '<body onload="init()">'
        '<a href="#" onclick="steal(event)">x</a>'
        '<img src="a" onerror="hack()">'
        "</body>"
    )

    def test_finds_all_on_attributes(self):
        handlers = extract_event_handlers(_soup(self.HTML))
        assert {h.attribute for h in handlers} == {"onload", "onclick", "onerror"}

    def test_captures_handler_code(self):
        handlers = extract_event_handlers(_soup(self.HTML))
        assert any(h.attribute == "onclick" and "steal" in h.code for h in handlers)

    def test_no_handlers_returns_empty(self):
        assert extract_event_handlers(_soup("<div><p>plain</p></div>")) == []


# ---------------------------------------------------------------------------
# extract_js_urls
# ---------------------------------------------------------------------------
class TestJsUrls:
    def test_finds_javascript_hrefs_and_srcs(self):
        html = (
            '<a href="javascript:void(0)">x</a>'
            '<a href="/normal">y</a>'
            '<iframe src="javascript:alert(1)"></iframe>'
        )
        assert extract_js_urls(_soup(html)) == [
            "javascript:void(0)",
            "javascript:alert(1)",
        ]

    def test_empty_when_none(self):
        assert extract_js_urls(_soup('<a href="/x">y</a>')) == []


# ---------------------------------------------------------------------------
# normalize_script
# ---------------------------------------------------------------------------
class TestNormalizeScript:
    def test_strips_block_comments_and_collapses_whitespace(self):
        assert normalize_script("var a = 1;   /* c */\n\n var b=2;") == "var a = 1; var b=2;"

    def test_preserves_urls_in_code(self):
        # Line comments are NOT stripped, so http:// stays intact.
        assert normalize_script("go('http://x.com');") == "go('http://x.com');"


# ---------------------------------------------------------------------------
# extract_script_features
# ---------------------------------------------------------------------------
class TestScriptFeatures:
    def test_benign_code_scores_zero(self):
        f = extract_script_features("console.log('hello world');")
        assert f.suspicious_score == 0
        assert f.uses_eval is False
        assert f.high_entropy is False

    def test_flags_multiple_risky_apis(self):
        code = (
            "eval(atob('ZG9j')); document.write(x); "
            "window.location.href='http://evil.com'; document.cookie='a';"
        )
        f = extract_script_features(code)
        assert f.uses_eval is True
        assert f.uses_base64 is True
        assert f.uses_document_write is True
        assert f.uses_redirect is True
        assert f.uses_cookie_access is True
        assert f.suspicious_score == 5

    def test_keyboard_and_form_hooks(self):
        code = "el.addEventListener('keydown', log); form.addEventListener('submit', send);"
        f = extract_script_features(code)
        assert f.listens_keyboard is True
        assert f.hooks_forms is True
        assert f.uses_eval is False

    def test_function_constructor(self):
        f = extract_script_features("new Function('return 1')()")
        assert f.uses_function_ctor is True

    def test_long_escape_runs_counted(self):
        f = extract_script_features(r"var s='\x61\x62\x63\x64\x65\x66';")
        assert f.long_escape_runs >= 1

    def test_high_entropy_on_long_token(self):
        f = extract_script_features("a" * 250)
        assert f.high_entropy is True


# ---------------------------------------------------------------------------
# chunk_script
# ---------------------------------------------------------------------------
class TestChunkScript:
    def test_splits_on_statement_boundaries(self):
        chunks = chunk_script("a=1;b=2;c=3;", max_chars=4)
        assert chunks == ["a=1;", "b=2;", "c=3;"]

    def test_single_chunk_when_small(self):
        assert chunk_script("a=1;", max_chars=100) == ["a=1;"]

    def test_hard_splits_oversized_statement(self):
        chunks = chunk_script("x" * 10, max_chars=4)
        assert all(len(c) <= 4 for c in chunks)
        assert "".join(chunks) == "x" * 10

    def test_empty_returns_empty(self):
        assert chunk_script("") == []


# ---------------------------------------------------------------------------
# build_scripts_report / report_from_html
# ---------------------------------------------------------------------------
class TestBuildReport:
    HTML = (
        "<html><body>"
        "<script>eval(atob('ZG9j')); window.location.href='http://evil.com'; "
        "document.cookie='x';</script>"
        '<script src="https://www.google-analytics.com/analytics.js"></script>'
        '<script src="/app.js"></script>'
        '<script type="application/ld+json">{"@context":"x"}</script>'
        '<a href="javascript:steal()">click</a>'
        '<button onclick="grab()">go</button>'
        "</body></html>"
    )

    def _report(self):
        return report_from_html(self.HTML, BASE, HOME)

    def test_counts(self):
        f = self._report().features
        assert f["inline_script_count"] == 1
        assert f["external_script_count"] == 2
        assert f["third_party_script_count"] == 1
        assert f["known_tracker_count"] == 1
        assert f["event_handler_count"] == 1
        assert f["javascript_url_count"] == 1
        assert f["json_data_block_count"] == 1

    def test_aggregated_flags(self):
        f = self._report().features
        assert f["uses_eval"] is True
        assert f["uses_base64"] is True
        assert f["uses_redirect"] is True
        assert f["uses_cookie_access"] is True
        assert f["uses_document_write"] is False
        assert f["max_suspicious_score"] == 4

    def test_report_is_json_serializable(self):
        import json

        dumped = json.dumps(self._report().to_dict())
        assert '"features"' in dumped

    def test_build_from_shared_soup_matches_wrapper(self):
        soup = _soup(self.HTML)
        direct = build_scripts_report(soup, BASE, HOME)
        assert direct.features == self._report().features