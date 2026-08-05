"""Drop-in local replacement for Apple's deprecated ``verifyReceipt``
endpoint: same request body, same response body shape, same status codes —
but verified offline against the pinned Apple root instead of by calling
Apple. Field-by-field fidelity and the unavoidable gaps (fields that only
exist in Apple's server-side subscription database, like
``latest_receipt_info`` / ``pending_renewal_info``) are documented in
COMPARISON.md.

Like Apple's endpoint, this does NOT check the bundle id — the caller
compares ``receipt["bundle_id"]``, exactly as with the real endpoint."""

import base64
import binascii
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional
from zoneinfo import ZoneInfo

from .exceptions import Reason, VerificationError
from .receipt import AppReceipt, InAppPurchase, verify_receipt_core

STATUS_OK = 0
#: Malformed request or receipt-data property.
STATUS_MALFORMED = 21002
#: Receipt could not be authenticated.
STATUS_NOT_AUTHENTICATED = 21003
#: Sandbox receipt sent to the production environment.
STATUS_SANDBOX_RECEIPT_ON_PRODUCTION = 21007
#: Production receipt sent to the sandbox environment.
STATUS_PRODUCTION_RECEIPT_ON_SANDBOX = 21008
#: Internal error.
STATUS_INTERNAL = 21009

_PACIFIC = ZoneInfo("America/Los_Angeles")


class VerifyReceiptEndpoint:
    """One instance emulates one environment (drives 21007/21008 routing).

    :param trusted_roots: pinned roots
        (production: :func:`apple_purchase_verifier.apple_receipt_roots`)
    :param environment: ``"Production"`` or ``"Sandbox"``
    """

    def __init__(self, trusted_roots, environment: str):
        roots = list(trusted_roots)
        if not roots:
            raise ValueError("trusted_roots must not be empty")
        if environment not in ("Production", "Sandbox"):
            raise ValueError("environment must be 'Production' or 'Sandbox'")
        self._roots = roots
        self._production = environment == "Production"

    def verify_receipt(self, request_body: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        """Handles one verifyReceipt request body. Never raises — like the
        real endpoint, failures are reported through ``status``."""
        receipt_data = request_body.get("receipt-data") if isinstance(request_body, Mapping) \
            else None
        if not isinstance(receipt_data, str) or not receipt_data:
            return {"status": STATUS_MALFORMED}
        try:
            der = base64.b64decode(receipt_data)
        except (binascii.Error, ValueError):
            return {"status": STATUS_MALFORMED}
        try:
            fields = verify_receipt_core(der, self._roots)
        except VerificationError as e:
            if e.reason == Reason.INVALID_RECEIPT_FORMAT:
                return {"status": STATUS_MALFORMED}
            return {"status": STATUS_NOT_AUTHENTICATED}
        except Exception:
            return {"status": STATUS_INTERNAL}

        # 21007/21008 environment routing from the receipt_type attribute.
        # Production types are exactly "Production" and "ProductionVPP";
        # everything else ("ProductionSandbox", "ProductionVPPSandbox",
        # "Xcode", or a missing attribute) fails closed as non-production.
        production_receipt = fields.receipt_type in ("Production", "ProductionVPP")
        if self._production and not production_receipt:
            return {"status": STATUS_SANDBOX_RECEIPT_ON_PRODUCTION}
        if not self._production and production_receipt:
            return {"status": STATUS_PRODUCTION_RECEIPT_ON_SANDBOX}
        return {
            "status": STATUS_OK,
            "environment": "Production" if self._production else "Sandbox",
            "receipt": _receipt_json(fields, datetime.now(timezone.utc)),
        }


def _receipt_json(fields: AppReceipt, request_date: datetime) -> Dict[str, Any]:
    receipt: Dict[str, Any] = {}
    _put(receipt, "receipt_type", fields.receipt_type)
    _put(receipt, "bundle_id", fields.bundle_id)
    _put(receipt, "application_version", fields.app_version)
    _put(receipt, "original_application_version", fields.original_app_version)
    _apple_dates(receipt, "receipt_creation_date", fields.creation_date)
    _apple_dates(receipt, "request_date", request_date)
    _apple_dates(receipt, "original_purchase_date", fields.original_purchase_date)
    _apple_dates(receipt, "expiration_date", fields.expiration_date)
    receipt["in_app"] = [_in_app_json(p) for p in fields.in_app_purchases]
    return receipt


def _in_app_json(purchase: InAppPurchase) -> Dict[str, Any]:
    entry: Dict[str, Any] = {}
    _put(entry, "quantity", _str_or_none(purchase.quantity))
    _put(entry, "product_id", purchase.product_id)
    _put(entry, "transaction_id", purchase.transaction_id)
    _put(entry, "original_transaction_id", purchase.original_transaction_id)
    _apple_dates(entry, "purchase_date", purchase.purchase_date)
    _apple_dates(entry, "original_purchase_date", purchase.original_purchase_date)
    _apple_dates(entry, "expires_date", purchase.expires_date)
    _apple_dates(entry, "cancellation_date", purchase.cancellation_date)
    _put(entry, "web_order_line_item_id", _str_or_none(purchase.web_order_line_item_id))
    if purchase.is_in_intro_offer_period is not None:
        entry["is_in_intro_offer_period"] = \
            "true" if purchase.is_in_intro_offer_period == 1 else "false"
    return entry


def _str_or_none(value: Optional[int]) -> Optional[str]:
    return None if value is None else str(value)


def _put(target: Dict[str, Any], key: str, value: Any) -> None:
    if value is not None:
        target[key] = value


def _apple_dates(target: Dict[str, Any], prefix: str, date: Optional[datetime]) -> None:
    """Apple's three date renderings: ``x`` (GMT), ``x_ms``, ``x_pst``."""
    if date is None:
        return
    utc = date.astimezone(timezone.utc)
    target[prefix] = utc.strftime("%Y-%m-%d %H:%M:%S") + " Etc/GMT"
    target[prefix + "_ms"] = str(int(utc.timestamp() * 1000))
    target[prefix + "_pst"] = \
        utc.astimezone(_PACIFIC).strftime("%Y-%m-%d %H:%M:%S") + " America/Los_Angeles"
