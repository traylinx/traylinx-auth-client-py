"""Bounded HTTPS transport. Never redirects or retries writes/credential exchanges."""
import json
import math
import threading
import time
from email.utils import parsedate_to_datetime
import requests
from .security import destination, MAX_RESPONSE
from .exceptions import ValidationError, NetworkError

class SecureSession(requests.Session):
    def __init__(self, timeout=30, max_retries=0, retry_delay=1):
        super().__init__()
        self.trust_env = False  # No implicit netrc authentication or proxy credentials.
        self.default_timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._transport_lock = threading.RLock()

    def get(self, url, **kwargs):
        kwargs.setdefault("allow_redirects", False)
        return super().get(url, **kwargs)

    def options(self, url, **kwargs):
        kwargs.setdefault("allow_redirects", False)
        return super().options(url, **kwargs)

    def request(self, method, url, **kwargs):
        destination(url)
        timeout = kwargs.pop("timeout", self.default_timeout)
        limit = kwargs.pop("response_limit", MAX_RESPONSE)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 300:
            raise ValidationError("Invalid request timeout")
        if kwargs.get("verify") is False or kwargs.get("allow_redirects") is True or kwargs.get("stream") is True:
            raise ValidationError("Unsafe transport option")
        for field in ("data", "json"):
            body = kwargs.get(field)
            if body is not None:
                if not isinstance(body, (str, bytes, dict, list, tuple)):
                    raise ValidationError("Streaming request bodies are unsupported")
                try:
                    size = len(body if isinstance(body, bytes) else (body if isinstance(body, str) else json.dumps(body)).encode())
                except (TypeError, ValueError):
                    raise ValidationError("Invalid request body") from None
                if size > MAX_RESPONSE:
                    raise ValidationError("Request body too large")
        deadline = time.monotonic() + timeout
        if not self._transport_lock.acquire(timeout=timeout):
            raise NetworkError("Transport deadline exceeded", error_code="TIMEOUT")
        try:
            attempt = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise NetworkError("Transport deadline exceeded", error_code="TIMEOUT")
                self.cookies.clear()
                try:
                    response = super().request(method, url, **dict(kwargs, timeout=(min(5, remaining), min(5, remaining)), allow_redirects=False, stream=True))
                    try:
                        if 300 <= response.status_code < 400:
                            raise NetworkError("Redirect refused", error_code="REDIRECT_REFUSED", status_code=response.status_code)
                        content = bytearray()
                        # One decoded byte at a time also catches slow-drip bodies;
                        # the underlying socket read timeout bounds a stalled read.
                        for chunk in response.iter_content(chunk_size=1):
                            if len(content) + len(chunk) > limit:
                                raise NetworkError("Response too large", error_code="RESPONSE_TOO_LARGE")
                            if time.monotonic() >= deadline:
                                raise NetworkError("Transport deadline exceeded", error_code="TIMEOUT")
                            content.extend(chunk)
                        response._content = bytes(content)
                        response._content_consumed = True
                    finally:
                        response.close()
                        self.cookies.clear()
                except requests.RequestException:
                    # No automatic retry after ambiguous transport failures.
                    raise
                if str(method).upper() not in {"GET", "HEAD"} or response.status_code not in {429, 500, 502, 503, 504} or attempt >= self.max_retries:
                    return response
                delay = min(2, self.retry_delay * 2**attempt)
                retry_after = response.headers.get("Retry-After")
                if retry_after:
                    try:
                        after = float(retry_after)
                    except ValueError:
                        try:
                            after = parsedate_to_datetime(retry_after).timestamp() - time.time()
                        except (ValueError, TypeError, OverflowError):
                            after = 0
                    if math.isfinite(after):
                        delay = max(delay, after)
                if delay >= deadline - time.monotonic():
                    return response
                time.sleep(max(0, delay))
                attempt += 1
        finally:
            self._transport_lock.release()
