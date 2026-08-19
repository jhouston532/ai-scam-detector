"""
Unit tests for src/utils/ping.py

Run from the project root:

    pytest

These tests never touch the network: every call to ``requests.get`` is
mocked, so they're fast and deterministic. The import ``from utils.ping``
relies on ``pythonpath = src`` in pytest.ini.
"""
from unittest.mock import patch

import pytest
import requests

from utils.ping import (
    grab_html,
    ping,
    ping_main,
    ping_urls,
    read_from_csv_file,
)


class FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

    @property
    def ok(self):
        # Mirrors requests.Response.ok (True for status < 400).
        return self.status_code < 400


# ---------------------------------------------------------------------------
# ping
# ---------------------------------------------------------------------------
class TestPing:
    @patch("utils.ping.requests.get")
    def test_returns_true_on_200(self, mock_get):
        mock_get.return_value = FakeResponse(status_code=200)
        assert ping("https://example.com", timeout=5) is True

    @patch("utils.ping.requests.get")
    def test_forwards_url_and_timeout(self, mock_get):
        mock_get.return_value = FakeResponse(status_code=200)
        ping("https://example.com", timeout=7)
        mock_get.assert_called_once_with("https://example.com", timeout=7)

    @patch("utils.ping.requests.get")
    def test_returns_false_on_404(self, mock_get):
        mock_get.return_value = FakeResponse(status_code=404)
        assert ping("https://example.com", timeout=5) is False

    @patch("utils.ping.requests.get")
    def test_returns_false_on_500(self, mock_get):
        mock_get.return_value = FakeResponse(status_code=500)
        assert ping("https://example.com", timeout=5) is False

    @patch("utils.ping.requests.get")
    def test_returns_false_on_redirect_status(self, mock_get):
        # ping compares against 200 exactly, so a 301 is False even though
        # requests would normally follow it. Documents the strict check.
        mock_get.return_value = FakeResponse(status_code=301)
        assert ping("https://example.com", timeout=5) is False

    @patch("utils.ping.requests.get")
    def test_returns_false_on_timeout(self, mock_get):
        mock_get.side_effect = requests.Timeout("timed out")
        assert ping("https://example.com", timeout=1) is False

    @patch("utils.ping.requests.get")
    def test_returns_false_on_connection_error(self, mock_get):
        mock_get.side_effect = requests.ConnectionError("no route to host")
        assert ping("https://example.com", timeout=5) is False

    @patch("utils.ping.requests.get")
    def test_returns_false_on_generic_request_exception(self, mock_get):
        mock_get.side_effect = requests.RequestException("boom")
        assert ping("https://example.com", timeout=5) is False


# ---------------------------------------------------------------------------
# ping_urls
# ---------------------------------------------------------------------------
class TestPingUrls:
    @patch("utils.ping.ping")
    def test_maps_each_url_to_its_result(self, mock_ping):
        mock_ping.side_effect = lambda url, timeout: url.endswith("good")
        urls = ["https://a.good", "https://b.bad", "https://c.good"]
        assert ping_urls(urls, timeout=5) == {
            "https://a.good": True,
            "https://b.bad": False,
            "https://c.good": True,
        }

    @patch("utils.ping.ping")
    def test_empty_list_returns_empty_dict(self, mock_ping):
        assert ping_urls([], timeout=5) == {}
        mock_ping.assert_not_called()

    @patch("utils.ping.ping")
    def test_forwards_timeout_positionally(self, mock_ping):
        mock_ping.return_value = True
        ping_urls(["https://a.com"], timeout=9)
        mock_ping.assert_called_once_with("https://a.com", 9)

    @patch("utils.ping.ping")
    def test_duplicate_urls_collapse_to_one_key(self, mock_ping):
        mock_ping.return_value = True
        result = ping_urls(["https://a.com", "https://a.com"], timeout=5)
        assert result == {"https://a.com": True}


# ---------------------------------------------------------------------------
# read_from_csv_file
# ---------------------------------------------------------------------------
class TestReadFromCsvFile:
    @staticmethod
    def _write(tmp_path, content):
        path = tmp_path / "urls.csv"
        path.write_text(content, encoding="utf-8")
        return str(path)

    def test_reads_url_column(self, tmp_path):
        path = self._write(tmp_path, "url\nhttps://a.com\nhttps://b.com\n")
        assert read_from_csv_file(path) == ["https://a.com", "https://b.com"]

    def test_ignores_other_columns(self, tmp_path):
        content = "name,url,note\nAlice,https://a.com,hi\nBob,https://b.com,yo\n"
        path = self._write(tmp_path, content)
        assert read_from_csv_file(path) == ["https://a.com", "https://b.com"]

    def test_column_order_does_not_matter(self, tmp_path):
        content = "note,url\nhi,https://a.com\n"
        path = self._write(tmp_path, content)
        assert read_from_csv_file(path) == ["https://a.com"]

    def test_skips_rows_with_empty_url_field(self, tmp_path):
        content = "name,url\nAlice,https://a.com\nBob,\nCarol,https://c.com\n"
        path = self._write(tmp_path, content)
        assert read_from_csv_file(path) == ["https://a.com", "https://c.com"]

    def test_only_header_returns_empty_list(self, tmp_path):
        path = self._write(tmp_path, "url\n")
        assert read_from_csv_file(path) == []

    def test_missing_url_column_raises_value_error(self, tmp_path):
        path = self._write(tmp_path, "name,website\nAlice,https://a.com\n")
        with pytest.raises(ValueError):
            read_from_csv_file(path)

    def test_empty_file_raises_value_error(self, tmp_path):
        path = self._write(tmp_path, "")
        with pytest.raises(ValueError):
            read_from_csv_file(path)


# ---------------------------------------------------------------------------
# grab_html
# ---------------------------------------------------------------------------
class TestGrabHtml:
    @patch("utils.ping.requests.get")
    @patch("utils.ping.ping")
    def test_returns_text_for_html(self, mock_ping, mock_get):
        mock_ping.return_value = True
        mock_get.return_value = FakeResponse(
            status_code=200,
            text="<html>hi</html>",
            headers={"Content-Type": "text/html; charset=utf-8"},
        )
        assert grab_html("https://a.com", timeout=5) == "<html>hi</html>"

    @patch("utils.ping.requests.get")
    @patch("utils.ping.ping")
    def test_returns_none_when_ping_fails(self, mock_ping, mock_get):
        mock_ping.return_value = False
        assert grab_html("https://a.com", timeout=5) is None
        mock_get.assert_not_called()  # never fetches if the ping failed

    @patch("utils.ping.requests.get")
    @patch("utils.ping.ping")
    def test_returns_none_when_second_get_raises(self, mock_ping, mock_get):
        mock_ping.return_value = True
        mock_get.side_effect = requests.RequestException("boom")
        assert grab_html("https://a.com", timeout=5) is None

    @patch("utils.ping.requests.get")
    @patch("utils.ping.ping")
    def test_returns_none_when_not_ok(self, mock_ping, mock_get):
        mock_ping.return_value = True
        mock_get.return_value = FakeResponse(
            status_code=500, text="err", headers={"Content-Type": "text/html"}
        )
        assert grab_html("https://a.com", timeout=5) is None

    @patch("utils.ping.requests.get")
    @patch("utils.ping.ping")
    def test_returns_none_for_non_html_content(self, mock_ping, mock_get):
        mock_ping.return_value = True
        mock_get.return_value = FakeResponse(
            status_code=200,
            text='{"a": 1}',
            headers={"Content-Type": "application/json"},
        )
        assert grab_html("https://a.com", timeout=5) is None

    @patch("utils.ping.requests.get")
    @patch("utils.ping.ping")
    def test_returns_none_when_content_type_header_missing(self, mock_ping, mock_get):
        mock_ping.return_value = True
        mock_get.return_value = FakeResponse(status_code=200, text="hi", headers={})
        assert grab_html("https://a.com", timeout=5) is None

    @patch("utils.ping.requests.get")
    @patch("utils.ping.ping")
    def test_content_type_match_is_case_insensitive(self, mock_ping, mock_get):
        mock_ping.return_value = True
        mock_get.return_value = FakeResponse(
            status_code=200, text="<html></html>", headers={"Content-Type": "TEXT/HTML"}
        )
        assert grab_html("https://a.com", timeout=5) == "<html></html>"

    @patch("utils.ping.requests.get")
    @patch("utils.ping.ping")
    def test_xhtml_content_type_is_accepted(self, mock_ping, mock_get):
        # "application/xhtml+xml" contains the substring "html", so it passes.
        mock_ping.return_value = True
        mock_get.return_value = FakeResponse(
            status_code=200, text="<html/>", headers={"Content-Type": "application/xhtml+xml"}
        )
        assert grab_html("https://a.com", timeout=5) == "<html/>"


# ---------------------------------------------------------------------------
# ping_main
# ---------------------------------------------------------------------------
class TestPingMain:
    @patch("utils.ping.ping_urls")
    @patch("utils.ping.read_from_csv_file")
    def test_file_mode_reads_then_pings(self, mock_read, mock_ping_urls):
        mock_read.return_value = ["https://a.com", "https://b.com"]
        mock_ping_urls.return_value = {"https://a.com": True, "https://b.com": False}

        result = ping_main("file", "urls.csv", timeout=8)

        mock_read.assert_called_once_with("urls.csv")
        mock_ping_urls.assert_called_once_with(["https://a.com", "https://b.com"], 8)
        assert result == {"https://a.com": True, "https://b.com": False}

    @patch("utils.ping.ping")
    def test_single_target_mode(self, mock_ping):
        mock_ping.return_value = True
        result = ping_main("single", "https://a.com", timeout=8)
        mock_ping.assert_called_once_with("https://a.com", 8)
        assert result == {"https://a.com": True}

    @patch("utils.ping.ping")
    def test_unknown_mode_falls_back_to_single_target(self, mock_ping):
        mock_ping.return_value = False
        assert ping_main("whatever", "https://a.com") == {"https://a.com": False}

    @patch("utils.ping.ping")
    def test_default_timeout_is_15(self, mock_ping):
        mock_ping.return_value = True
        ping_main("single", "https://a.com")
        mock_ping.assert_called_once_with("https://a.com", 15)


# ---------------------------------------------------------------------------
# Integration: file mode wired end-to-end (only requests.get mocked)
# ---------------------------------------------------------------------------
class TestIntegration:
    @patch("utils.ping.requests.get")
    def test_file_mode_end_to_end(self, mock_get, tmp_path):
        csv_path = tmp_path / "urls.csv"
        csv_path.write_text("url\nhttps://a.com\nhttps://b.com\n", encoding="utf-8")

        def fake_get(url, timeout):
            return FakeResponse(status_code=200 if "a.com" in url else 404)

        mock_get.side_effect = fake_get

        result = ping_main("file", str(csv_path), timeout=5)
        assert result == {"https://a.com": True, "https://b.com": False}