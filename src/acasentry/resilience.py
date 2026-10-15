"""Retry, pagination and error translation helpers for live Azure calls.

Kept free of Azure imports so it can be unit tested with simple fakes.
"""

import random
import re
import time

RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504}
GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class AcasentryError(Exception):
    """User-facing error with an actionable message. Printed without a traceback."""


def status_of(exc):
    code = getattr(exc, "status_code", None)
    if code is None:
        code = getattr(getattr(exc, "response", None), "status_code", None)
    if code is None and isinstance(getattr(exc, "code", None), int):
        code = exc.code  # urllib.error.HTTPError (Microsoft Graph calls)
    return code


def error_code_of(exc):
    err = getattr(exc, "error", None)
    return (getattr(err, "code", None) or "") if err is not None else ""


def retry_after_seconds(exc):
    headers = (
        getattr(getattr(exc, "response", None), "headers", None)
        or getattr(exc, "headers", None)
        or {}
    )
    for key in ("retry-after-ms", "x-ms-retry-after-ms"):
        val = _get_header(headers, key)
        if val is not None:
            try:
                return max(0.0, float(val) / 1000.0)
            except ValueError:
                pass
    val = _get_header(headers, "retry-after")
    if val is not None:
        try:
            return max(0.0, float(val))
        except ValueError:
            return None  # HTTP-date form: fall back to backoff
    return None


def _get_header(headers, key):
    for k, v in dict(headers).items():
        if str(k).lower() == key:
            return v
    return None


def is_transient(exc):
    if status_of(exc) in RETRYABLE_STATUS:
        return True
    name = type(exc).__name__
    return name in {
        "ServiceRequestError",
        "ServiceResponseError",
        "ConnectionError",
        "TimeoutError",
    }


def call_with_retry(
    fn,
    *,
    max_attempts=5,
    base_delay=1.0,
    max_delay=30.0,
    sleep=time.sleep,
    jitter=random.random,
):
    """Call fn(); retry transient failures with bounded exponential backoff.

    Retry-After from the service is honored but capped at max_delay.
    """
    attempt = 0
    while True:
        attempt += 1
        try:
            return fn()
        except Exception as exc:
            if attempt >= max_attempts or not is_transient(exc):
                raise
            delay = retry_after_seconds(exc)
            if delay is None:
                delay = base_delay * (2 ** (attempt - 1)) + jitter() * base_delay
            sleep(min(delay, max_delay))


def list_all(make_pager, **retry_kwargs):
    """Fully iterate a paged list (e.g. azure ItemPaged), following every page.

    make_pager is a zero-arg callable returning a fresh iterable. If a transient
    error hits mid-iteration the listing restarts from the first page.
    """
    return call_with_retry(lambda: list(make_pager()), **retry_kwargs)


def validate_subscription(sub):
    if not sub:
        raise AcasentryError(
            "No subscription given. Pass --subscription <id> (see `az account list -o table`), "
            "or use --demo to try the tool without Azure."
        )
    if not GUID_RE.match(sub):
        raise AcasentryError(
            f"'{sub}' is not a valid subscription ID (expected a GUID). "
            "Find yours with `az account list -o table`."
        )
    return sub


def translate(exc, subscription=None):
    """Map an Azure SDK exception to an AcasentryError, or return None if unknown."""
    name = type(exc).__name__
    status = status_of(exc)
    code = error_code_of(exc)
    if name in {
        "CredentialUnavailableError",
        "ClientAuthenticationError",
    } and status not in (403,):
        return AcasentryError(
            "Not signed in to Azure. Run `az login` (and `az account set --subscription <id>`), "
            "or set AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET for a service principal. "
            f"Details: {_first_line(exc)}"
        )
    if code in {"SubscriptionNotFound", "InvalidSubscriptionId"} or (
        status == 404 and "subscription" in str(exc).lower()
    ):
        return AcasentryError(
            f"Subscription '{subscription}' was not found or is not visible to this identity. "
            "Check the ID with `az account list -o table`."
        )
    if status == 403 or code in {"AuthorizationFailed", "LinkedAuthorizationFailed"}:
        return AcasentryError(
            "Permission denied. The signed-in identity needs at least Reader on the subscription "
            "(and Contributor on the apps for --apply). "
            f"Details: {_first_line(exc)}"
        )
    if status == 401:
        return AcasentryError(
            "Azure rejected the credentials (401). Run `az login` again or check the tenant. "
            f"Details: {_first_line(exc)}"
        )
    if status in RETRYABLE_STATUS:
        return AcasentryError(
            f"Azure kept returning HTTP {status} after retries. Try again later. "
            f"Details: {_first_line(exc)}"
        )
    return None


def _first_line(exc):
    text = str(exc).strip().splitlines()
    return text[0][:300] if text else type(exc).__name__
