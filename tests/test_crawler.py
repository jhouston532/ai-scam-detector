"""
Unit tests for src/analysis/crawler.py

Fully offline: the only thing that touches the network in the real crawler is
fetch_page (via utils.ping.grab_html), and every test here either patches
fetch_page or patches grab_html underneath it. No real HTTP happens.

Imported as `analysis.crawler`, so these rely on `pythonpath = src`
(see pytest.ini).

Note: get_domain uses tldextract, which reads the public-suffix list. The
first call may fetch it (or fall back to a bundled snapshot offline); results
are correct either way. These tests don't mock it, so get_domain is exercised
for real.
"""
from unittest.mock import patch

import pytest

from analysis import crawler
from analysis.crawler import (
    crawl,
    extract_links,
    fetch_page,
    get_domain,
    normalize_url,
    same_domain,
)


# ---------------------------------------------------------------------------
# get_domain
# ---------------------------------------------------------------------------
class TestGetDomain:
    def test_strips_subdomain_and_path(self):
        assert get_domain("https://www.example.com/some/path") == "example.com"

    def test_multi_part_suffix(self):
        assert get_domain("https://a.b.example.co.uk/x") == "example.co.uk"

    def test_bare_hostname_without_scheme(self):
        assert get_domain("example.com") == "example.com"

    def test_hostname_with_no_public_suffix_returns_none_string(self):
        # "localhost" has a domain but no registrable suffix.
        assert get_domain("http://localhost") == "None"

    def test_ip_address_returns_none_string(self):
        assert get_domain("http://127.0.0.1/") == "None"

    def test_empty_string_returns_none_string(self):
        assert get_domain("") == "None"

    def test_garbage_returns_none_string(self):
        assert get_domain("not a url") == "None"

    def test_returns_literal_string_not_none_object(self):
        # The sentinel is the string "None", not the None object — crawl()
        # relies on this exact comparison.
        assert get_domain("") is not None
        assert get_domain("") == "None"


# ---------------------------------------------------------------------------
# fetch_page
# ---------------------------------------------------------------------------
class TestFetchPage:
    @patch("analysis.crawler.Ping.grab_html")
    def test_returns_html_when_grab_html_succeeds(self, mock_grab):
        mock_grab.return_value = "<html>hi</html>"
        assert fetch_page("https://example.com") == "<html>hi</html>"

    @patch("analysis.crawler.Ping.grab_html")
    def test_returns_none_when_grab_html_returns_none(self, mock_grab):
        mock_grab.return_value = None
        assert fetch_page("https://example.com") is None

    @patch("analysis.crawler.Ping.grab_html")
    def test_forwards_url_and_default_timeout(self, mock_grab):
        mock_grab.return_value = "<html></html>"
        fetch_page("https://example.com")
        mock_grab.assert_called_once_with("https://example.com", crawler.DEFAULT_TIME_OUT)

    @patch("analysis.crawler.Ping.grab_html")
    def test_preserves_empty_string(self, mock_grab):
        # "" is not None, so it should pass through unchanged (an empty but
        # successfully fetched page), NOT be turned into None.
        mock_grab.return_value = ""
        assert fetch_page("https://example.com") == ""


# ---------------------------------------------------------------------------
# extract_links
# ---------------------------------------------------------------------------
class TestExtractLinks:
    def test_resolves_relative_against_base(self):
        html = '<a href="/about">a</a><a href="contact">b</a>'
        result = extract_links(html, "https://example.com/dir/")
        assert result == [
            "https://example.com/about",
            "https://example.com/dir/contact",
        ]

    def test_keeps_absolute_urls(self):
        html = '<a href="https://other.com/x">x</a>'
        assert extract_links(html, "https://example.com/") == ["https://other.com/x"]

    def test_resolves_protocol_relative(self):
        html = '<a href="//cdn.com/y">y</a>'
        assert extract_links(html, "https://example.com/") == ["https://cdn.com/y"]

    def test_no_anchors_returns_empty_list(self):
        assert extract_links("<p>no links here</p>", "https://example.com/") == []

    def test_empty_html_returns_empty_list(self):
        assert extract_links("", "https://example.com/") == []

    def test_ignores_anchors_without_href(self):
        html = '<a>no href</a><a href="/yes">yes</a>'
        assert extract_links(html, "https://example.com/") == ["https://example.com/yes"]

    def test_ignores_non_anchor_tags(self):
        html = '<link href="/style.css"><a href="/page">p</a>'
        assert extract_links(html, "https://example.com/") == ["https://example.com/page"]

    def test_preserves_duplicate_hrefs(self):
        # extract_links does no de-duplication; crawl() dedupes later.
        html = '<a href="/a">1</a><a href="/a">2</a>'
        assert extract_links(html, "https://example.com/") == [
            "https://example.com/a",
            "https://example.com/a",
        ]

    def test_preserves_document_order(self):
        html = '<a href="/1">1</a><a href="/2">2</a><a href="/3">3</a>'
        assert extract_links(html, "https://example.com/") == [
            "https://example.com/1",
            "https://example.com/2",
            "https://example.com/3",
        ]

    def test_mailto_href_passes_through(self):
        html = '<a href="mailto:me@example.com">mail</a>'
        assert extract_links(html, "https://example.com/") == ["mailto:me@example.com"]


# ---------------------------------------------------------------------------
# normalize_url
# ---------------------------------------------------------------------------
class TestNormalizeUrl:
    def test_lowercases_host_only_not_path(self):
        assert normalize_url("https://Example.COM/A/B/") == "https://example.com/A/B"

    def test_lowercases_scheme(self):
        # urlsplit normalizes the scheme to lowercase.
        assert normalize_url("HTTPS://example.com/a") == "https://example.com/a"

    def test_strips_trailing_slash_on_nonroot_path(self):
        assert normalize_url("https://example.com/a/b/") == "https://example.com/a/b"

    def test_keeps_root_slash(self):
        assert normalize_url("https://example.com/") == "https://example.com/"

    def test_drops_fragment(self):
        assert normalize_url("https://example.com/a#section") == "https://example.com/a"

    def test_keeps_query(self):
        assert normalize_url("https://example.com/a?x=1&y=2") == "https://example.com/a?x=1&y=2"

    def test_strips_trailing_slash_but_keeps_query(self):
        assert normalize_url("https://example.com/a/?x=1") == "https://example.com/a?x=1"

    def test_is_idempotent(self):
        for u in [
            "https://Example.com/A/",
            "https://example.com/a#frag",
            "https://example.com/",
            "https://example.com/a?x=1",
        ]:
            assert normalize_url(normalize_url(u)) == normalize_url(u)

    def test_empty_path_and_root_slash_do_not_currently_agree(self):
        # KNOWN QUIRK: the docstring says "example.com" and "example.com/"
        # should agree, but an empty path normalizes to no slash while "/" is
        # kept, so the two forms differ. Documented here so a future fix to
        # normalize_url flips this test deliberately. See notes in chat.
        assert normalize_url("https://example.com") != normalize_url("https://example.com/")


# ---------------------------------------------------------------------------
# same_domain
# ---------------------------------------------------------------------------
class TestSameDomain:
    def test_true_across_subdomains(self):
        assert same_domain("https://blog.example.com/post", "example.com") is True

    def test_true_for_bare_and_www(self):
        assert same_domain("https://www.example.com/", "example.com") is True

    def test_false_for_different_domain(self):
        assert same_domain("https://other.com/x", "example.com") is False

    def test_false_for_unparseable_url(self):
        assert same_domain("not a url", "example.com") is False


# ---------------------------------------------------------------------------
# crawl
# ---------------------------------------------------------------------------
def _make_fetcher(pages):
    """
    Build a fake fetch_page that maps a NORMALIZED url to canned HTML and
    records every call, so tests can assert on both coverage and de-duplication.
    Returns (fetcher, calls_list).
    """
    calls = []

    def fake_fetch(url):
        key = normalize_url(url)
        calls.append(key)
        return pages.get(key)

    return fake_fetch, calls


class TestCrawl:
    def test_returns_empty_set_for_invalid_seed(self):
        # No registrable domain -> nothing to crawl, fetch never called.
        with patch("analysis.crawler.fetch_page") as mock_fetch:
            assert crawl("http://localhost/") == set()
            mock_fetch.assert_not_called()

    def test_empty_string_seed_returns_empty_set(self):
        with patch("analysis.crawler.fetch_page") as mock_fetch:
            assert crawl("") == set()
            mock_fetch.assert_not_called()

    def test_visits_all_same_domain_pages_once(self):
        pages = {
            "https://site.com/": (
                '<a href="/about">about</a>'
                '<a href="/contact">contact</a>'
                '<a href="https://ext.com/">external</a>'  # off-domain
                '<a href="/about">about-dup</a>'            # duplicate
                '<a href="#top">frag</a>'                   # fragment -> home
            ),
            "https://site.com/about": (
                '<a href="/">home</a>'
                '<a href="/team">team</a>'
                '<a href="/contact">contact</a>'
            ),
            "https://site.com/contact": '<a href="/about">about</a>',
            "https://site.com/team": '<a href="/about">about</a><a href="/">home</a>',
        }
        fetcher, calls = _make_fetcher(pages)

        with patch("analysis.crawler.fetch_page", side_effect=fetcher):
            visited = crawl("https://site.com/")

        assert visited == {
            "https://site.com/",
            "https://site.com/about",
            "https://site.com/contact",
            "https://site.com/team",
        }
        # Each page fetched exactly once (dedup + visited-set working).
        assert len(calls) == len(set(calls))

    def test_excludes_off_domain_links(self):
        pages = {
            "https://site.com/": '<a href="https://ext.com/page">ext</a>',
            "https://ext.com/page": '<a href="/deep">deep</a>',  # must never be fetched
        }
        fetcher, calls = _make_fetcher(pages)

        with patch("analysis.crawler.fetch_page", side_effect=fetcher):
            visited = crawl("https://site.com/")

        assert visited == {"https://site.com/"}
        assert "https://ext.com/page" not in calls

    def test_follows_same_registrable_domain_across_subdomains(self):
        pages = {
            "https://site.com/": '<a href="https://blog.site.com/post">blog</a>',
            "https://blog.site.com/post": "<p>no links</p>",
        }
        fetcher, _ = _make_fetcher(pages)

        with patch("analysis.crawler.fetch_page", side_effect=fetcher):
            visited = crawl("https://site.com/")

        assert visited == {
            "https://site.com/",
            "https://blog.site.com/post",
        }

    def test_failed_fetch_page_still_counts_as_visited(self):
        # fetch_page returning None marks the URL visited but follows no links.
        with patch("analysis.crawler.fetch_page", return_value=None) as mock_fetch:
            visited = crawl("https://site.com/")

        assert visited == {"https://site.com/"}
        mock_fetch.assert_called_once()

    def test_terminates_on_cycles(self):
        # Two pages linking to each other: must not loop forever.
        pages = {
            "https://site.com/": '<a href="/a">a</a>',
            "https://site.com/a": '<a href="/">home</a>',
        }
        fetcher, calls = _make_fetcher(pages)

        with patch("analysis.crawler.fetch_page", side_effect=fetcher):
            visited = crawl("https://site.com/")

        assert visited == {"https://site.com/", "https://site.com/a"}
        assert len(calls) == 2  # each fetched once despite the cycle

    def test_equivalent_urls_collapse_via_normalization(self):
        # Home links to the same page three ways (trailing slash, fragment,
        # mixed case host); all normalize to one and get fetched once.
        pages = {
            "https://site.com/": (
                '<a href="/team/">slash</a>'
                '<a href="/team#roster">fragment</a>'
                '<a href="/team">plain</a>'
            ),
            "https://site.com/team": "<p>team</p>",
        }
        fetcher, calls = _make_fetcher(pages)

        with patch("analysis.crawler.fetch_page", side_effect=fetcher):
            visited = crawl("https://site.com/")

        assert visited == {"https://site.com/", "https://site.com/team"}
        assert calls.count("https://site.com/team") == 1