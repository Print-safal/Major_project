from __future__ import annotations

import os
import re
import threading
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from collections import deque
from dataclasses import dataclass

from groq import APIConnectionError, APITimeoutError, Groq


@dataclass
class KeyState:
    alias: str
    secret: str
    disabled: bool = False
    unavailable_until: float = 0.0


class ProviderFailure(RuntimeError):
    def __init__(self, message, *, alias=None, aliases_used=None, retryable=False, attempts=0, status=None):
        super().__init__(message)
        self.alias, self.retryable, self.attempts, self.status = alias, retryable, attempts, status
        self.aliases_used = list(aliases_used or [])


def load_keys(env=None):
    env = os.environ if env is None else env
    keys = []
    for i in range(1, 20):
        alias = f"KEY_{i}"
        secret = env.get(f"GROQ_EVAL_KEY_{i}")
        enabled = env.get(f"GROQ_EVAL_KEY_{i}_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}
        if secret and enabled:
            keys.append(KeyState(alias, secret))
    if not keys and env.get("GROQ_API_KEY"):
        keys.append(KeyState("KEY_1", env["GROQ_API_KEY"]))
    return keys


def redact(text, keys=()):
    value = str(text or "")
    for key in keys:
        if key:
            value = value.replace(key, "[REDACTED]")
    return re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._-]+", r"\1[REDACTED]", value)


class RequestLimiter:
    def __init__(self, max_rpm=30, clock=time.monotonic, sleep=time.sleep):
        self.max_rpm, self.clock, self.sleep = max(1, int(max_rpm)), clock, sleep
        self.calls = deque()
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            now = self.clock()
            while self.calls and now - self.calls[0] >= 60:
                self.calls.popleft()
            if len(self.calls) >= self.max_rpm:
                self.sleep(max(0.0, 60 - (now - self.calls[0])))
                now = self.clock()
                while self.calls and now - self.calls[0] >= 60:
                    self.calls.popleft()
            self.calls.append(self.clock())


def _headers(exc):
    return getattr(getattr(exc, "response", None), "headers", {}) or {}


def _body_text(exc):
    body = getattr(exc, "body", None)
    response = getattr(exc, "response", None)
    response_body = getattr(response, "text", "") if response is not None else ""
    return f"{exc} {body} {response_body}".lower()


def _retry_after(exc, fallback):
    val = _headers(exc).get("retry-after")
    try:
        return max(0.0, float(val))
    except (TypeError, ValueError):
        try:
            return max(0.0, (parsedate_to_datetime(val) - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return fallback


class GroqKeyPool:
    """Conservative retries; unknown 429s stay on the same key."""
    def __init__(self, keys, *, max_retries=5, max_rpm=30, backoff_base=1.0,
                 client_factory=Groq, sleep=time.sleep, clock=time.monotonic, limiter=None):
        self.keys, self.max_retries, self.backoff_base = keys, max_retries, backoff_base
        self.client_factory, self.sleep, self.clock = client_factory, sleep, clock
        self.limiter = limiter or RequestLimiter(max_rpm, clock, sleep)
        self.clients = {}
        self.lock = threading.Lock()

    @property
    def aliases(self):
        return [k.alias for k in self.keys]

    def _client(self, key):
        with self.lock:
            if key.alias not in self.clients:
                self.clients[key.alias] = self.client_factory(api_key=key.secret)
            return self.clients[key.alias]

    def _choose(self, preferred=None):
        now = self.clock()
        candidates = [k for k in self.keys if not k.disabled and k.unavailable_until <= now]
        if preferred:
            for key in candidates:
                if key.alias == preferred:
                    return key
        return candidates[0] if candidates else None

    def call(self, request):
        if not self.keys:
            raise ProviderFailure("No enabled Groq API keys configured")
        retries, preferred, last_error, aliases_used = 0, None, None, []
        while retries <= self.max_retries:
            key = self._choose(preferred)
            if key is None:
                wait_for = min((max(0, k.unavailable_until - self.clock()) for k in self.keys if not k.disabled), default=None)
                if wait_for is None:
                    raise ProviderFailure("All configured API keys are unavailable", attempts=retries, aliases_used=aliases_used)
                self.sleep(wait_for)
                preferred = None
                continue
            preferred = key.alias
            self.limiter.wait()
            aliases_used.append(key.alias)
            try:
                response = request(self._client(key))
                return response, key.alias, retries, aliases_used
            except Exception as exc:
                last_error = exc
                status = getattr(exc, "status_code", None)
                body = _body_text(exc)
                msg = redact(exc, [k.secret for k in self.keys])
                if status == 429:
                    account_wide = any(x in body for x in ("billing", "organization quota", "org quota", "spend limit", "account quota", "insufficient_quota"))
                    if account_wide:
                        raise ProviderFailure(f"Account-wide quota or billing restriction: {msg}", alias=key.alias, aliases_used=aliases_used, status=status, attempts=retries) from exc
                    explicit_per_key = any(x in body for x in ("per key", "api key rate", "key-specific", "this key"))
                    delay = _retry_after(exc, self.backoff_base * (2 ** retries))
                    retries += 1
                    if explicit_per_key:
                        key.unavailable_until = self.clock() + max(delay, 0.05)
                        preferred = None
                    if retries > self.max_retries:
                        raise ProviderFailure(f"Rate limit retry budget exhausted: {msg}", alias=key.alias, aliases_used=aliases_used, retryable=True, status=status, attempts=retries) from exc
                    if not explicit_per_key:
                        self.sleep(delay)
                    continue
                if status in (401, 403):
                    if any(x in body for x in ("billing", "quota", "spend limit", "organization")):
                        raise ProviderFailure(f"Account-wide quota or billing restriction: {msg}", alias=key.alias, aliases_used=aliases_used, status=status, attempts=retries) from exc
                    key.disabled = True
                    if not any(not k.disabled for k in self.keys):
                        raise ProviderFailure(f"All configured keys rejected: {msg}", alias=key.alias, aliases_used=aliases_used, status=status, attempts=retries) from exc
                    preferred = None
                    retries += 1
                    continue
                transient = isinstance(exc, (APIConnectionError, APITimeoutError)) or status is not None and (status >= 500 or status in (408, 425))
                if not transient:
                    raise ProviderFailure(f"Permanent provider error: {msg}", alias=key.alias, aliases_used=aliases_used, status=status, attempts=retries) from exc
                delay = self.backoff_base * (2 ** retries)
                retries += 1
                if retries > self.max_retries:
                    raise ProviderFailure(f"Transient provider retry budget exhausted: {msg}", alias=key.alias, aliases_used=aliases_used, retryable=True, status=status, attempts=retries) from exc
                self.sleep(delay)
        raise ProviderFailure(f"Provider retries exhausted: {redact(last_error, [k.secret for k in self.keys])}", aliases_used=aliases_used, retryable=True, attempts=retries)
