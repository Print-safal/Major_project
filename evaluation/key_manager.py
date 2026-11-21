from __future__ import annotations

import os
import re
import threading
import time

from pathlib import Path
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from collections import deque
from dataclasses import dataclass

from dotenv import load_dotenv
from groq import APIConnectionError, APITimeoutError, Groq


# ============================================================
# API KEY STATE
# ============================================================

@dataclass
class KeyState:
    alias: str
    secret: str
    disabled: bool = False
    unavailable_until: float = 0.0


# ============================================================
# PROVIDER FAILURE
# ============================================================

class ProviderFailure(RuntimeError):

    def __init__(
        self,
        message,
        *,
        alias=None,
        aliases_used=None,
        retryable=False,
        attempts=0,
        status=None,
    ):
        super().__init__(message)

        self.alias = alias
        self.aliases_used = list(aliases_used or [])
        self.retryable = retryable
        self.attempts = attempts
        self.status = status


# ============================================================
# LOAD API KEYS
# ============================================================

def load_keys(env=None):
    """
    Load keys from evaluation/.env.local.

    Supports GROQ_EVAL_KEY_1 through GROQ_EVAL_KEY_19.

    Optional:
        GROQ_EVAL_KEY_i_ENABLED=true/false

    If env is supplied, it is used directly.
    """

    env_file = Path(__file__).resolve().parent / ".env.local"

    if env is None:
        load_dotenv(env_file, override=False)
        env = os.environ

    keys = []

    for i in range(1, 20):

        secret = env.get(f"GROQ_EVAL_KEY_{i}")

        enabled_value = env.get(
            f"GROQ_EVAL_KEY_{i}_ENABLED",
            "true",
        )

        enabled = str(enabled_value).strip().lower() not in {
            "0",
            "false",
            "no",
            "off",
        }

        if secret and secret.strip() and enabled:

            keys.append(
                KeyState(
                    alias=f"KEY_{i}",
                    secret=secret.strip(),
                )
            )

    # Backward compatibility.
    if not keys and env.get("GROQ_API_KEY"):

        keys.append(
            KeyState(
                alias="KEY_1",
                secret=env["GROQ_API_KEY"].strip(),
            )
        )

    return keys


# ============================================================
# REDACT API KEYS
# ============================================================

def redact(text, keys=()):

    value = str(text or "")

    for key in keys:
        if key:
            value = value.replace(key, "[REDACTED]")

    return re.sub(
        r"(?i)(bearer\s+)[A-Za-z0-9._-]+",
        r"\1[REDACTED]",
        value,
    )


# ============================================================
# REQUEST RATE LIMITER
# ============================================================

class RequestLimiter:

    def __init__(
        self,
        max_rpm=30,
        clock=time.monotonic,
        sleep=time.sleep,
    ):

        self.max_rpm = max(1, int(max_rpm))
        self.clock = clock
        self.sleep = sleep

        self.calls = deque()
        self.lock = threading.Lock()

    def wait(self):

        while True:

            wait_time = 0.0

            with self.lock:

                now = self.clock()

                # Remove requests older than 60 seconds.
                while (
                    self.calls
                    and now - self.calls[0] >= 60
                ):
                    self.calls.popleft()

                # A request slot is available.
                if len(self.calls) < self.max_rpm:

                    self.calls.append(now)
                    return

                # Calculate when the oldest request expires.
                wait_time = max(
                    0.01,
                    60 - (now - self.calls[0]),
                )

            # IMPORTANT:
            # Sleep outside the lock.
            # Other threads can access the limiter while
            # this thread is waiting.
            self.sleep(wait_time)

            # Loop again and recheck the rolling window.


# ============================================================
# ERROR HELPERS
# ============================================================

def _headers(exc):

    return (
        getattr(
            getattr(exc, "response", None),
            "headers",
            {},
        )
        or {}
    )


def _body_text(exc):

    body = getattr(exc, "body", None)

    response = getattr(exc, "response", None)

    response_body = (
        getattr(response, "text", "")
        if response is not None
        else ""
    )

    return f"{exc} {body} {response_body}".lower()


def _retry_after(exc, fallback):

    headers = _headers(exc)

    val = (
        headers.get("retry-after")
        or headers.get("Retry-After")
    )

    try:
        return max(0.0, float(val))

    except (TypeError, ValueError):

        try:
            retry_date = parsedate_to_datetime(val)

            return max(
                0.0,
                (
                    retry_date - datetime.now(timezone.utc)
                ).total_seconds(),
            )

        except (
            TypeError,
            ValueError,
            OverflowError,
        ):
            return fallback


# ============================================================
# QUOTA / ERROR CLASSIFICATION
# ============================================================

def _is_daily_token_limit(body):

    patterns = (
        "tokens per day",
        "token per day",
        "daily token limit",
        "daily tokens",
        "per-day token",
        "per day token",
        "tpd limit",
        "tpd quota",
    )

    return any(x in body for x in patterns)


def _is_account_wide_quota(body):

    patterns = (
        "billing",
        "organization quota",
        "org quota",
        "spend limit",
        "account quota",
        "insufficient_quota",
        "billing hard limit",
    )

    return any(x in body for x in patterns)


def _is_rate_limit(body):

    patterns = (
        "rate limit",
        "too many requests",
        "tokens per minute",
        "token per minute",
        "requests per minute",
        "requests per day",
        "rpm limit",
        "tpm limit",
        "rate_limit_exceeded",
    )

    return any(x in body for x in patterns)


def _is_oversized_request(status, body):

    if status == 413:
        return True

    patterns = (
        "request too large",
        "payload too large",
        "maximum context length",
        "context length exceeded",
        "too many tokens in the request",
    )

    return any(x in body for x in patterns)


# ============================================================
# GROQ KEY POOL
# ============================================================

class GroqKeyPool:
    """
    Groq API key manager.

    Features:
    1. Round-robin key selection.
    2. Automatic switching after HTTP 429.
    3. Daily token quota handling.
    4. Temporary rate-limit cooldowns.
    5. Invalid key handling.
    6. Connection and timeout retries.
    7. API key redaction.

    HTTP 413 errors are not retried with another key.
    """

    def __init__(
        self,
        keys,
        *,
        max_retries=5,
        max_rpm=30,
        backoff_base=2.0,
        cooldown_seconds=60,
        client_factory=Groq,
        sleep=time.sleep,
        clock=time.monotonic,
        limiter=None,
    ):

        self.keys = list(keys)

        self.max_retries = max(1, int(max_retries))
        self.backoff_base = float(backoff_base)
        self.cooldown_seconds = max(1, int(cooldown_seconds))

        self.client_factory = client_factory
        self.sleep = sleep
        self.clock = clock

        self.limiter = limiter or RequestLimiter(
            max_rpm=max_rpm,
            clock=clock,
            sleep=sleep,
        )

        self.clients = {}

        self.lock = threading.Lock()

        self.next_key_index = 0

    # --------------------------------------------------------
    # KEY ALIASES
    # --------------------------------------------------------

    @property
    def aliases(self):

        return [
            key.alias
            for key in self.keys
        ]

    # --------------------------------------------------------
    # CREATE / REUSE CLIENT
    # --------------------------------------------------------

    def _client(self, key):

        with self.lock:

            if key.alias not in self.clients:

                self.clients[key.alias] = self.client_factory(
                    api_key=key.secret
                )

            return self.clients[key.alias]

    # --------------------------------------------------------
    # ROUND-ROBIN KEY SELECTION
    # --------------------------------------------------------

    def _choose(self):

        with self.lock:

            if not self.keys:
                return None

            now = self.clock()

            total = len(self.keys)

            for offset in range(total):

                index = (
                    self.next_key_index + offset
                ) % total

                key = self.keys[index]

                if (
                    not key.disabled
                    and key.unavailable_until <= now
                ):

                    self.next_key_index = (
                        index + 1
                    ) % total

                    return key

            return None

    # --------------------------------------------------------
    # DISABLE KEY FOR CURRENT PROCESS
    # --------------------------------------------------------

    def _disable_key(self, key):

        with self.lock:
            key.disabled = True

    # --------------------------------------------------------
    # TEMPORARY COOLDOWN
    # --------------------------------------------------------

    def _cooldown_key(self, key, seconds):

        with self.lock:

            key.unavailable_until = (
                self.clock() + max(seconds, 1.0)
            )

    # --------------------------------------------------------
    # WAIT FOR AN AVAILABLE KEY
    # --------------------------------------------------------

    def _wait_for_key(self):

        with self.lock:

            active_keys = [
                key
                for key in self.keys
                if not key.disabled
            ]

            if not active_keys:
                return False

            now = self.clock()

            earliest = min(
                key.unavailable_until
                for key in active_keys
            )

            wait_time = max(
                0.0,
                earliest - now,
            )

        if wait_time > 0:

            print(
                f"\n[KEY MANAGER] All active keys "
                f"are cooling down. Waiting {wait_time:.1f}s."
            )

            self.sleep(wait_time)

        return True

    # --------------------------------------------------------
    # MAIN API CALL
    # --------------------------------------------------------

    def call(self, request):

        if not self.keys:

            raise ProviderFailure(
                "No enabled Groq API keys configured."
            )

        aliases_used = []

        last_error = None

        retries = 0

        max_attempts = self.max_retries + len(self.keys)

        while retries < max_attempts:

            key = self._choose()

            # -----------------------------------------------
            # NO AVAILABLE KEY
            # -----------------------------------------------

            if key is None:

                if not self._wait_for_key():
                    break

                continue

            # Wait for an available request slot.
            self.limiter.wait()

            aliases_used.append(key.alias)

            try:

                response = request(
                    self._client(key)
                )

                return (
                    response,
                    key.alias,
                    retries,
                    aliases_used,
                )

            except Exception as exc:

                last_error = exc

                status = getattr(
                    exc,
                    "status_code",
                    None,
                )

                body = _body_text(exc)

                safe_message = redact(
                    exc,
                    [
                        item.secret
                        for item in self.keys
                    ],
                )

                # ===========================================
                # HTTP 429: RATE LIMIT / QUOTA
                # ===========================================

                if status == 429:

                    # DAILY TOKEN QUOTA
                    if _is_daily_token_limit(body):

                        self._disable_key(key)

                        print(
                            f"\n[KEY ROTATION] {key.alias} "
                            "has exhausted its daily token quota."
                        )

                        print(
                            "[KEY ROTATION] This key is disabled "
                            "for the current process."
                        )

                        retries += 1
                        continue

                    # ACCOUNT-WIDE BILLING RESTRICTION
                    if _is_account_wide_quota(body):

                        raise ProviderFailure(
                            (
                                "Account-wide quota or billing "
                                f"restriction: {safe_message}"
                            ),
                            alias=key.alias,
                            aliases_used=aliases_used,
                            status=status,
                            attempts=retries,
                        ) from exc

                    # TEMPORARY RATE LIMIT
                    delay = _retry_after(
                        exc,
                        max(
                            self.cooldown_seconds,
                            self.backoff_base * (2 ** retries),
                        ),
                    )

                    self._cooldown_key(
                        key,
                        delay,
                    )

                    print(
                        f"\n[KEY ROTATION] {key.alias} "
                        f"received HTTP 429. "
                        f"Cooling down for {delay:.1f}s."
                    )

                    print(
                        "[KEY ROTATION] Trying another account."
                    )

                    retries += 1
                    continue

                # ===========================================
                # HTTP 413: REQUEST TOO LARGE
                # ===========================================

                if _is_oversized_request(status, body):

                    raise ProviderFailure(
                        (
                            "Request is too large for the "
                            "provider's limit. Switching API "
                            "keys will not fix this request. "
                            f"Details: {safe_message}"
                        ),
                        alias=key.alias,
                        aliases_used=aliases_used,
                        status=status,
                        attempts=retries,
                    ) from exc

                # ===========================================
                # HTTP 401 / 403: INVALID KEY
                # ===========================================

                if status in (401, 403):

                    self._disable_key(key)

                    print(
                        f"\n[KEY ROTATION] {key.alias} "
                        "was rejected. Disabling this key "
                        "for the current run."
                    )

                    retries += 1
                    continue

                # ===========================================
                # CONNECTION / SERVER ERRORS
                # ===========================================

                transient = (
                    isinstance(
                        exc,
                        (
                            APIConnectionError,
                            APITimeoutError,
                        ),
                    )
                    or (
                        status is not None
                        and (
                            status >= 500
                            or status in (408, 425)
                        )
                    )
                )

                if not transient:

                    raise ProviderFailure(
                        (
                            "Permanent provider error: "
                            f"{safe_message}"
                        ),
                        alias=key.alias,
                        aliases_used=aliases_used,
                        status=status,
                        attempts=retries,
                    ) from exc

                retries += 1

                if retries >= max_attempts:

                    raise ProviderFailure(
                        (
                            "Transient provider retry budget "
                            f"exhausted: {safe_message}"
                        ),
                        alias=key.alias,
                        aliases_used=aliases_used,
                        retryable=True,
                        status=status,
                        attempts=retries,
                    ) from exc

                delay = (
                    self.backoff_base
                    * (2 ** min(retries - 1, 6))
                )

                print(
                    f"\n[KEY MANAGER] Temporary connection/server "
                    f"error. Retrying in {delay:.1f}s."
                )

                self.sleep(delay)

        # ----------------------------------------------------
        # ALL KEYS EXHAUSTED OR UNAVAILABLE
        # ----------------------------------------------------

        raise ProviderFailure(
            (
                "No usable Groq API key remains, or the retry "
                "budget was exhausted. Last error: "
                f"{redact(last_error, [k.secret for k in self.keys])}"
            ),
            aliases_used=aliases_used,
            retryable=True,
            attempts=retries,
        )