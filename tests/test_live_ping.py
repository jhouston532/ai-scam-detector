"""
Live smoke tests for src/utils/ping.py.

Unlike test_ping.py (fully mocked, offline, always run), this module makes
REAL network requests against well-known, stable websites. It exists to catch
problems the mocked suite can't see: TLS issues, a broken `requests` install,
redirect handling, or the Content-Type logic misbehaving against real servers.

These tests are marked `live` and are excluded from the default run. Run them
on demand with:

    pytest -m live

They import ping.py as `utils.ping`, so they rely on `pythonpath = src`
(see pytest.ini). If there's no working connection, the whole module is
skipped rather than failed.
"""
import pytest
import requests

from utils.ping import grab_html, ping

# Marks every test in this module as `live` so `-m "not live"` skips them.
pytestmark = pytest.mark.live

# Generous timeout: real networks are slower and more variable than mocks.
TIMEOUT = 15

# Common, reliable sites that return 200 + HTML for a plain GET.
# example.com is IANA-maintained specifically for this kind of use; the others
# are large, stable properties that tolerate a default requests User-Agent.
RELIABLE_SITES = [
    "https://example.com",
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://github.com",
]


@pytest.fixture(scope="session", autouse=True)
def _require_network():
    """
    Skip the whole live suite when there's no usable connection.

    Tries each reliable site in turn and proceeds as soon as one responds at
    all (any HTTP reply counts as "the network works"). Only if every host is
    unreachable do we skip — that way a single site being down doesn't disable
    the suite, but running offline won't produce misleading failures.
    """
    for url in RELIABLE_SITES:
        try:
            requests.get(url, timeout=TIMEOUT)
            return  # network is up; run the tests
        except requests.RequestException:
            continue
    pytest.skip("No network connection available for live tests")


@pytest.mark.parametrize("url", RELIABLE_SITES)
def test_ping_reaches_live_site(url):
    """ping() should get a 200 OK from each reliable site."""
    assert ping(url, timeout=TIMEOUT) is True


@pytest.mark.parametrize("url", RELIABLE_SITES)
def test_grab_html_returns_markup(url):
    """grab_html() should return real HTML for each reliable site."""
    html = grab_html(url, timeout=TIMEOUT)
    assert html is not None, f"expected HTML from {url}, got None"
    assert "<html" in html.lower(), f"response from {url} didn't look like HTML"


def test_ping_false_for_nonexistent_domain():
    """
    A domain that doesn't resolve should ping False, not raise.

    Uses a .invalid host, which RFC 6761 reserves as guaranteed-not-to-exist,
    so this never depends on some real site happening to be down.
    """
    assert ping("https://this-domain-does-not-exist.invalid", timeout=TIMEOUT) is False


def test_ping_false_for_404_path():
    """A real host returning a non-200 status should ping False."""
    assert ping("https://github.com/this-path-should-not-exist-xyz-404", timeout=TIMEOUT) is False