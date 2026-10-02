"""Tests for the v5.1 fixes: shared probe client, HttpOnly cookies,
concurrent takeover matching.

Run with: python -m pytest tests/ -v
"""
import asyncio
import http.cookiejar as cookiejar
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.probe import cookie_is_httponly, probe_http
from core.takeover import match_takeover_signature


def make_cookie(name="sess", value="abc", httponly=False):
    c = cookiejar.Cookie(
        version=0, name=name, value=value,
        port=None, port_specified=False,
        domain="example.com", domain_specified=True, domain_initial_dot=False,
        path="/", path_specified=True,
        secure=False, expires=None, discard=True,
        comment=None, comment_url=None,
        rest={"HttpOnly": ""} if httponly else {},
        rfc2109=False,
    )
    return c


class TestCookieHttpOnly:
    """The old code did `"httponly" in str(cookie).lower()` which checks the
    name=value pair and could never see the flag. The helper must read the
    actual cookie attribute."""

    def test_httponly_detected(self):
        assert cookie_is_httponly(make_cookie(httponly=True)) is True

    def test_non_httponly(self):
        assert cookie_is_httponly(make_cookie(httponly=False)) is False

    def test_garbage_input_is_false(self):
        assert cookie_is_httponly(object()) is False


class TestTakeoverSignature:
    def test_github_match(self):
        m = match_takeover_signature("x.github.io")
        assert m is not None
        assert m["service"] == "github.io"
        assert m["fingerprints"]

    def test_heroku_match(self):
        m = match_takeover_signature("app.herokuapp.com")
        assert m["service"] == "herokuapp.com"

    def test_no_match(self):
        assert match_takeover_signature("cdn.example.net") is None

    def test_empty(self):
        assert match_takeover_signature("") is None
        assert match_takeover_signature(None) is None


class FakeResponse:
    def __init__(self):
        self.url = "https://sub.example.com/"
        self.status_code = 200
        self.headers = {"server": "nginx", "content-type": "text/html"}
        self.content = b"<html><head><title>Hi</title></head></html>"
        self.text = self.content.decode()
        self.history = []
        jar = cookiejar.CookieJar()
        jar.set_cookie(make_cookie(httponly=True))
        self.cookies = MagicMock()
        self.cookies.jar = list(jar)


class FakeClient:
    """Stands in for httpx.AsyncClient to prove probe_http reuses it."""

    def __init__(self):
        self.get_calls = 0
        self.closed = False

    async def get(self, url):
        self.get_calls += 1
        return FakeResponse()

    async def aclose(self):
        self.closed = True


class TestSharedProbeClient:
    def test_probe_http_reuses_passed_client(self):
        client = FakeClient()
        result = asyncio.run(probe_http("sub.example.com", client=client))
        assert result["alive"] is True
        assert client.get_calls >= 1
        # A client we passed in must NOT be closed by probe_http
        assert client.closed is False

    def test_probe_http_extracts_title_and_httponly(self):
        client = FakeClient()
        result = asyncio.run(probe_http("sub.example.com", client=client))
        assert result["title"] == "Hi"
        assert result["server"] == "nginx"
        assert result["cookies"][0]["httponly"] is True
