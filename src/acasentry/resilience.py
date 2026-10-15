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
    return is_connection_error(exc)


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
    if is_connection_error(exc):
        return AcasentryError(
            "Could not reach Azure (connection failed or timed out). Check your network, "
            "proxy settings (HTTPS_PROXY / NO_PROXY) and DNS, then retry. "
            f"Details: {_first_line(exc)}"
        )
    if status == 412:
        return AcasentryError(
            "The app changed while acasentry was updating it (412 precondition failed). "
            "This request changed nothing; re-run to plan against the current state. "
            f"Details: {_first_line(exc)}"
        )
    if status == 404:
        return AcasentryError(
            "Azure resource not found (404). Check the app name, --resource-group and "
            f"--subscription. Details: {_first_line(exc)}"
        )
    if status == 400:
        return AcasentryError(
            "Azure rejected the request (400 Bad Request). Check the command arguments "
            "(app, resource group, CIDRs) and that the Microsoft.App resource provider is "
            f"registered in the subscription. Details: {_first_line(exc)}"
        )
    if status == 409:
        return AcasentryError(
            "Azure reported a conflict (409), usually another operation in progress on the "
            f"resource. Wait for it to finish, then retry. Details: {_first_line(exc)}"
        )
    if status is not None and is_azure_error(exc):
        return AcasentryError(
            f"Azure returned HTTP {status}. Check the command arguments and permissions, "
            f"then retry. Details: {_first_line(exc)}"
        )
    if is_azure_error(exc):
        return AcasentryError(
            f"Azure SDK error ({name}). Check the command arguments, sign-in and network, "
            f"then retry. Details: {_first_line(exc)}"
        )
    return None


def is_azure_error(exc):
    """True for exceptions defined by the Azure SDK (azure.core, azure.identity, azure.mgmt)."""
    return any((c.__module__ or "").startswith("azure.") for c in type(exc).__mro__)


CONNECTION_ERROR_NAMES = {"ServiceRequestError", "ServiceResponseError", "URLError"}


def is_connection_error(exc):
    """Network-level failures: Azure SDK transport errors, urllib URLError, and the
    builtin ConnectionError / TimeoutError family. HTTP errors with a status are excluded."""
    if status_of(exc) is not None:
        return False
    if isinstance(exc, (ConnectionError, TimeoutError)):
        return True
    return any(c.__name__ in CONNECTION_ERROR_NAMES for c in type(exc).__mro__)


def first_line(exc):
    """First line of an exception message, max 300 chars; the class name if empty."""
    return _first_line(exc)


def _first_line(exc):
    text = str(exc).strip().splitlines()
    return text[0][:300] if text else type(exc).__name__
