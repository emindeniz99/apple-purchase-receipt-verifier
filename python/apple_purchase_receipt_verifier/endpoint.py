"""``Verifier.verify_receipt_endpoint``: a local stand-in for Apple's
deprecated verifyReceipt endpoint (docs/design/0.7-api.md §3). Same request
body, same response body, same status codes, but verified offline against
the pinned roots instead of by calling Apple. Fields that exist only in
Apple's server-side database, such as ``latest_receipt_info`` and
``pending_renewal_info``, are not produced. Like Apple's endpoint, it checks
no bundle id: the caller compares ``receipt["bundle_id"]``.
"""

import json
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from cryptography import x509

from . import _bounded_json, apple_status
from ._errors import VerificationError
from ._utf8 import utf8_exceeds
from .environment import Environment
from .reason import Reason
from .receipt import verify_receipt
from .receipt_payload import InAppPurchase, ReceiptPayload

#: Ceiling on the request body, in UTF-8 bytes: 3 MiB, Apple's own limit. A
#: larger body fails as ``TOO_LARGE`` (status 21002) before it is parsed.
MAX_REQUEST_BYTES = 3145728

_PACIFIC = ZoneInfo("America/Los_Angeles")
_LEADING_WHITESPACE = " \t\r\n"


def _status_for_reason(reason: Reason) -> int:
    if reason in (Reason.MALFORMED, Reason.TOO_LARGE):
        return apple_status.MALFORMED_RECEIPT_DATA
    if reason in (
        Reason.INVALID_SIGNATURE,
        Reason.UNTRUSTED_CHAIN,
        Reason.INVALID_CERTIFICATE,
        Reason.INVALID_CERTIFICATE_PURPOSE,
    ):
        return apple_status.RECEIPT_NOT_AUTHENTICATED
    return apple_status.INTERNAL_DATA_ACCESS_ERROR


def _receipt_data(request_json: "str | None") -> str:
    """The ``receipt-data`` string of a request body.

    The whole object is read, so a body that breaks after ``receipt-data``
    is still refused, and the last ``receipt-data`` wins, as it would in a
    dict. Anything after the object is not read. ``password`` and
    ``exclude-old-transactions`` are read (by being ignored)."""
    if request_json is None:
        raise VerificationError(Reason.MALFORMED, "request body is empty")
    if utf8_exceeds(request_json, MAX_REQUEST_BYTES):
        raise VerificationError(
            Reason.TOO_LARGE, f"request body exceeds the maximum of {MAX_REQUEST_BYTES} bytes"
        )
    if _bounded_json.exceeds_bounds(request_json):
        raise VerificationError(Reason.MALFORMED, "request body is nested too deeply")
    try:
        parsed, _end = json.JSONDecoder().raw_decode(request_json.lstrip(_LEADING_WHITESPACE))
    except ValueError as e:
        raise VerificationError(Reason.MALFORMED, "request body is not valid JSON") from e
    if not isinstance(parsed, dict):
        raise VerificationError(Reason.MALFORMED, "request body is not a JSON object")
    receipt_data = parsed.get("receipt-data")
    if not isinstance(receipt_data, str) or not receipt_data:
        raise VerificationError(Reason.MALFORMED, "receipt-data is missing or not a string")
    return receipt_data


def _status_for_environment(environment: Environment, receipt: ReceiptPayload) -> int:
    # A receipt whose receipt_type is missing or unknown counts as
    # non-production, failing closed.
    production_receipt = (
        Environment.from_receipt_type(receipt.receipt_type) == Environment.PRODUCTION
    )
    if environment == Environment.PRODUCTION and not production_receipt:
        return apple_status.SANDBOX_RECEIPT_ON_PRODUCTION
    if environment == Environment.SANDBOX and production_receipt:
        return apple_status.PRODUCTION_RECEIPT_ON_SANDBOX
    return apple_status.OK


def _put(target: "dict[str, object]", key: str, value: object) -> None:
    if value is not None:
        target[key] = value


def _apple_dates(target: "dict[str, object]", prefix: str, epoch_ms: "int | None") -> None:
    """Apple's three date renderings: ``x`` (GMT), ``x_ms``, ``x_pst``."""
    if epoch_ms is None:
        return
    utc = datetime.fromtimestamp(epoch_ms / 1000.0, tz=timezone.utc)
    target[prefix] = utc.strftime("%Y-%m-%d %H:%M:%S") + " Etc/GMT"
    target[prefix + "_ms"] = str(epoch_ms)
    target[prefix + "_pst"] = (
        utc.astimezone(_PACIFIC).strftime("%Y-%m-%d %H:%M:%S") + " America/Los_Angeles"
    )


def _in_app_json(purchase: InAppPurchase) -> "dict[str, object]":
    entry: dict[str, object] = {}
    _put(entry, "quantity", None if purchase.quantity is None else str(purchase.quantity))
    _put(entry, "product_id", purchase.product_id)
    _put(entry, "transaction_id", purchase.transaction_id)
    _put(entry, "original_transaction_id", purchase.original_transaction_id)
    _apple_dates(entry, "purchase_date", purchase.purchase_date_ms)
    _apple_dates(entry, "original_purchase_date", purchase.original_purchase_date_ms)
    _apple_dates(entry, "expires_date", purchase.expires_date_ms)
    _apple_dates(entry, "cancellation_date", purchase.cancellation_date_ms)
    # Apple omits the key when attribute 1711 is 0, as it does for consumables.
    if purchase.web_order_line_item_id:
        entry["web_order_line_item_id"] = str(purchase.web_order_line_item_id)
    if purchase.is_trial_period is not None:
        entry["is_trial_period"] = "true" if purchase.is_trial_period else "false"
    if purchase.is_in_intro_offer_period is not None:
        entry["is_in_intro_offer_period"] = "true" if purchase.is_in_intro_offer_period else "false"
    return entry


def _receipt_json(receipt: ReceiptPayload, request_date_ms: int) -> "dict[str, object]":
    out: dict[str, object] = {}
    _put(out, "receipt_type", receipt.receipt_type)
    # Apple echoes attribute 1 under both names (its response reference
    # defines adam_id as "See app_item_id") and as JSON numbers, not as the
    # strings the in-app integers are rendered with.
    _put(out, "adam_id", receipt.app_item_id)
    _put(out, "app_item_id", receipt.app_item_id)
    _put(out, "bundle_id", receipt.bundle_id)
    _put(out, "application_version", receipt.application_version)
    _put(out, "download_id", receipt.download_id)
    _put(out, "version_external_identifier", receipt.version_external_identifier)
    _put(out, "original_application_version", receipt.original_application_version)
    _apple_dates(out, "receipt_creation_date", receipt.receipt_creation_date_ms)
    _apple_dates(out, "request_date", request_date_ms)
    _apple_dates(out, "original_purchase_date", receipt.original_purchase_date_ms)
    _apple_dates(out, "expiration_date", receipt.expiration_date_ms)
    out["in_app"] = [_in_app_json(p) for p in receipt.in_app]
    return out


def _render(
    status: int,
    environment: "Environment | None" = None,
    receipt: "ReceiptPayload | None" = None,
    request_date_ms: "int | None" = None,
) -> str:
    if (
        status != apple_status.OK
        or receipt is None
        or environment is None
        or request_date_ms is None
    ):
        return json.dumps({"status": status}, separators=(",", ":"))
    body = {
        "status": apple_status.OK,
        "environment": environment.value,
        "receipt": _receipt_json(receipt, request_date_ms),
    }
    return json.dumps(body, separators=(",", ":"))


def verify_receipt_endpoint(
    environment: Environment,
    request_json: "str | None",
    roots: "Sequence[x509.Certificate]",
    clock: Callable[[], int],
) -> str:
    """Handles one verifyReceipt request body and returns the response body
    Apple would return, as a JSON string. Never raises."""
    try:
        receipt = verify_receipt(_receipt_data(request_json), roots, clock)
    except VerificationError as e:
        return _render(_status_for_reason(e.reason))
    except Exception:
        return _render(apple_status.INTERNAL_DATA_ACCESS_ERROR)
    status = _status_for_environment(environment, receipt)
    if status != apple_status.OK:
        return _render(status)
    return _render(apple_status.OK, environment, receipt, clock())
