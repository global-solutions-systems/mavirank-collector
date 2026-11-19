"""HTTP transport to the ingest gateway (§19.4) and to Google's IP range lists.

* TLS verification is always on (system CA store or ``ca_file``); plain http only with
  ``allow_insecure_http`` for local development.
* Redirects are never followed (the bearer token must not travel to another host).
* Response bodies are size limited; the token never appears in errors or output.
"""
from __future__ import annotations

import email.utils
import json
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

from . import USER_AGENT, __version__

MAX_RESPONSE_BYTES = 1024 * 1024
MAX_RANGES_BYTES = 4 * 1024 * 1024
GOOGLE_HOST_PREFIX = "https://developers.google.com/"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def build_opener(ca_file: Optional[str] = None) -> urllib.request.OpenerDirector:
    context = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), _NoRedirect())


class IngestError(Exception):
    """Classified failure.

    ``kind``: ``auth`` (401/403, stop), ``defer`` (429/503/network: try again later),
    ``too_large`` (413: split the batch), ``client`` (415/422/other 4xx), ``server`` (5xx).
    """

    def __init__(self, kind: str, message: str, status: int = 0, code: Optional[str] = None,
                 retry_after: Optional[int] = None, body: Optional[dict] = None):
        super().__init__(message)
        self.kind = kind
        self.status = status
        self.code = code
        self.retry_after = retry_after
        self.body = body or {}


class Response:
    def __init__(self, status: int, headers: Dict[str, str], body: bytes):
        self.status = status
        self.headers = headers
        self.body = body

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8")) if self.body else None

    @property
    def date(self) -> Optional[float]:
        value = self.headers.get("date")
        if not value:
            return None
        try:
            return email.utils.parsedate_to_datetime(value).timestamp()
        except (TypeError, ValueError):
            return None


def _read_limited(resp, limit: int) -> bytes:
    body = resp.read(limit + 1)
    if len(body) > limit:
        raise IngestError("server", "response too large")
    return body


def parse_retry_after(value: Optional[str], default: int = 300) -> int:
    if not value:
        return default
    value = value.strip()
    if value.isdigit():
        return max(1, min(int(value), 6 * 3600))
    try:
        import time

        when = email.utils.parsedate_to_datetime(value).timestamp()
        return max(1, min(int(when - time.time()), 6 * 3600))
    except (TypeError, ValueError):
        return default


class HttpClient:
    def __init__(self, opener: urllib.request.OpenerDirector, timeout: float):
        self.opener = opener
        self.timeout = timeout

    def request(self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes] = None,
                limit: int = MAX_RESPONSE_BYTES) -> Response:
        req = urllib.request.Request(url, data=body, method=method, headers=dict(headers, **{"User-Agent": USER_AGENT}))
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                return Response(resp.status, {k.lower(): v for k, v in resp.headers.items()}, _read_limited(resp, limit))
        except urllib.error.HTTPError as exc:
            try:
                data = exc.read(MAX_RESPONSE_BYTES)
            except Exception:
                data = b""
            return Response(exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, data)
        except IngestError:
            raise
        except (urllib.error.URLError, OSError, ValueError) as exc:
            reason = getattr(exc, "reason", exc)
            raise IngestError("defer", f"connection failed: {reason}") from None


class IngestClient:
    def __init__(self, http: HttpClient, api_base: str, token: str):
        self.http = http
        self.base = api_base.rstrip("/")
        self._auth = "Bearer " + token

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": self._auth,
            "Accept": "application/json",
            "X-Mavirank-Collector": USER_AGENT,
        }

    def get_config(self, etag: Optional[str]) -> Tuple[Response, Optional[dict]]:
        """Returns ``(response, config)``; ``config`` is ``None`` for ``304``."""
        headers = self._headers()
        if etag:
            headers["If-None-Match"] = etag
        resp = self.http.request("GET", self.base + "/ingest/config", headers)
        if resp.status == 304:
            return resp, None
        if resp.status == 200:
            try:
                data = resp.json()
            except ValueError:
                raise IngestError("server", "config response is not JSON", 200) from None
            if not isinstance(data, dict):
                raise IngestError("server", "config response is not an object", 200)
            return resp, data
        raise classify(resp, "config")

    def post_logs(self, batch_id: str, gz_body: bytes) -> dict:
        headers = self._headers()
        headers.update({
            "Content-Type": "application/x-ndjson",
            "Content-Encoding": "gzip",
            "X-Mavirank-Batch-Id": batch_id,
        })
        resp = self.http.request("POST", self.base + "/ingest/logs", headers, gz_body)
        if resp.status == 200:
            try:
                data = resp.json()
            except ValueError:
                data = None
            return data if isinstance(data, dict) else {}
        raise classify(resp, "logs")


def classify(resp: Response, what: str) -> IngestError:
    try:
        body = resp.json()
    except ValueError:
        body = None
    body = body if isinstance(body, dict) else {}
    code = body.get("code") if isinstance(body.get("code"), str) else None
    detail = body.get("detail") or body.get("title") or ""
    label = f"{what}: HTTP {resp.status}" + (f" {code}" if code else "") + (f" ({detail})" if detail else "")
    if resp.status in (401, 403):
        reason = body.get("reason")
        if reason:
            label += f" reason={reason}"
        return IngestError("auth", label, resp.status, code, body=body)
    if resp.status in (429, 503):
        return IngestError("defer", label, resp.status, code, parse_retry_after(resp.headers.get("retry-after")), body)
    if resp.status == 413:
        return IngestError("too_large", label, resp.status, code, body=body)
    if resp.status in (502, 504) or resp.status >= 500:
        return IngestError("defer", label, resp.status, code, parse_retry_after(resp.headers.get("retry-after"), 300), body)
    return IngestError("client", label, resp.status, code, body=body)


def google_json_fetcher(http: HttpClient):
    """Fetcher for Google's range lists: fixed host, size limited."""

    def get_json(url: str) -> dict:
        if not url.startswith(GOOGLE_HOST_PREFIX):
            raise ValueError("unexpected host")
        resp = http.request("GET", url, {"Accept": "application/json"}, limit=MAX_RANGES_BYTES)
        if resp.status != 200:
            raise IngestError("server", f"HTTP {resp.status}", resp.status)
        return resp.json()

    return get_json


__all__ = ["HttpClient", "IngestClient", "IngestError", "build_opener", "google_json_fetcher", "__version__"]
