"""Drop-in local replacement for Apple's deprecated ``verifyReceipt``
endpoint: same request body, same response body shape, same status codes —
but verified offline against the pinned Apple root instead of by calling
Apple. Field-by-field fidelity and the unavoidable gaps (fields that only
exist in Apple's server-side subscription database, like
``latest_receipt_info`` / ``pending_renewal_info``) are documented in
COMPARISON.md.

Like Apple's endpoint, this does NOT check the bundle id — the caller
compares ``receipt["bundle_id"]``, exactly as with the real endpoint."""

import json
import time
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timezone
from typing import Any, NoReturn
from zoneinfo import ZoneInfo

from cryptography import x509

from ._receipt_base64 import decode_receipt_base64
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
_ENDPOINT_ENVIRONMENTS = ("Production", "Sandbox")
_ENVIRONMENT_ERROR = "environment must be 'Production' or 'Sandbox'"


class VerifyReceiptResult:
    """The outcome of one :class:`VerifyReceiptEndpoint` call: the Apple
    status, the verified receipt or the reason there is none, and the
    Apple-shaped response, rendered only when asked for.

    Exactly one of :attr:`receipt` and :attr:`failure_reason` is not
    ``None``. The receipt is kept whenever its bytes verified, including when
    the endpoint's own environment answers 21007 or 21008, so a caller can
    re-render for the other environment with :meth:`to_json` without
    verifying twice. The status is always recomputed from the receipt's own
    ``receipt_type``, so no render answers 0 for a receipt from the wrong
    environment.

    Immutable, and only the endpoint creates one: calling the class raises
    ``TypeError``, so a caller cannot build a result carrying status 0. Each
    environment's response is rendered once, the first time it is asked for,
    and reused after that. The :class:`AppReceipt` in :attr:`receipt` is the
    library's ordinary mutable object; changing it after a render does not
    change that render.
    """

    __slots__ = (
        "_environment",
        "_failure_cause",
        "_failure_reason",
        "_receipt",
        "_rendered",
        "_request_date",
    )

    _environment: str
    _receipt: AppReceipt | None
    _failure_reason: str | None
    _failure_cause: Exception | None
    _request_date: datetime
    _rendered: dict[str, str]

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("VerifyReceiptResult is created by VerifyReceiptEndpoint only")

    @classmethod
    def _create(
        cls,
        environment: str,
        receipt: AppReceipt | None,
        failure_reason: str | None,
        failure_cause: Exception | None,
        request_date: datetime,
    ) -> "VerifyReceiptResult":
        result = object.__new__(cls)
        object.__setattr__(result, "_environment", environment)
        object.__setattr__(result, "_receipt", receipt)
        object.__setattr__(result, "_failure_reason", failure_reason)
        object.__setattr__(result, "_failure_cause", failure_cause)
        object.__setattr__(result, "_request_date", request_date)
        object.__setattr__(result, "_rendered", {})
        return result

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise AttributeError(f"VerifyReceiptResult is immutable; cannot set {name!r}")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError(f"VerifyReceiptResult is immutable; cannot delete {name!r}")

    def __repr__(self) -> str:
        return (
            f"VerifyReceiptResult(status={self.status}, verified={self.verified}, "
            f"failure_reason={self._failure_reason!r}, request_date={self._request_date!r})"
        )

    @property
    def status(self) -> int:
        """The Apple status for the endpoint's own environment."""
        return self._status(self._environment)

    @property
    def verified(self) -> bool:
        """Whether the receipt bytes verified: ``True`` exactly when
        :attr:`receipt` is set. That includes 21007 and 21008, where the
        receipt verified and only its environment differs from the
        endpoint's, so this is not the same check as ``status == 0``.
        ``status == 0`` asks whether this endpoint's environment accepts the
        receipt; ``verified`` asks whether it verified at all, which is what
        to check before reading :attr:`receipt` or re-rendering for the
        other environment."""
        return self._receipt is not None

    @property
    def receipt(self) -> AppReceipt | None:
        """The verified receipt, or ``None`` when verification failed.
        Present for 21007 and 21008 too."""
        return self._receipt

    @property
    def failure_reason(self) -> str | None:
        """Why there is no receipt, a :class:`Reason` value; ``None``
        exactly when :attr:`receipt` is set."""
        return self._failure_reason

    @property
    def failure_cause(self) -> Exception | None:
        """The unexpected exception behind :attr:`Reason.INTERNAL_ERROR`;
        ``None`` for every other outcome."""
        return self._failure_cause

    @property
    def request_date(self) -> datetime:
        """The instant rendered as ``request_date`` (UTC), fixed when the
        call was made."""
        return self._request_date

    def to_response(self, environment: str | None = None) -> dict[str, Any]:
        """The response body as a new dict on each call. With no argument,
        the endpoint's own environment; with ``"Production"`` or
        ``"Sandbox"``, what an endpoint of that environment would answer for
        the same receipt at the same :attr:`request_date`. A production
        receipt answers 0 on Production and 21008 on Sandbox; any other
        receipt answers 21007 on Production and 0 on Sandbox; a failed result
        answers its own status on both.

        :raises ValueError: for any other environment, as the endpoint's
            constructor does
        """
        result: dict[str, Any] = json.loads(self.to_json(environment))
        return result

    def to_json(self, environment: str | None = None) -> str:
        """:meth:`to_response` serialized as the JSON response body, byte
        for byte what :meth:`VerifyReceiptEndpoint.verify_receipt_json`
        answers.

        :raises ValueError: for an environment other than ``"Production"``
            or ``"Sandbox"``
        """
        target = self._environment if environment is None else environment
        rendered = self._rendered.get(target)
        if rendered is None:
            rendered = json.dumps(self._render(target), separators=(",", ":"))
            self._rendered[target] = rendered
        return rendered

    def _render(self, environment: str) -> dict[str, Any]:
        status = self._status(environment)
        if status != STATUS_OK or self._receipt is None:
            return {"status": status}
        return {
            "status": STATUS_OK,
            "environment": environment,
            "receipt": _receipt_json(self._receipt, self._request_date),
        }

    def _status(self, environment: str) -> int:
        if environment not in _ENDPOINT_ENVIRONMENTS:
            raise ValueError(_ENVIRONMENT_ERROR)
        if self._receipt is None:
            if self._failure_reason in (Reason.MALFORMED_REQUEST, Reason.INVALID_RECEIPT_FORMAT):
                return STATUS_MALFORMED
            if self._failure_reason == Reason.INTERNAL_ERROR:
                return STATUS_INTERNAL
            return STATUS_NOT_AUTHENTICATED
        # 21007/21008 environment routing from the receipt_type attribute.
        # Production types are exactly "Production" and "ProductionVPP";
        # everything else ("ProductionSandbox", "ProductionVPPSandbox",
        # "Xcode", or a missing attribute) fails closed as non-production.
        # "Xcode" is listed for completeness only: an Xcode-generated
        # receipt is not Apple-signed, so it fails chain verification with
        # 21003 and never gets here.
        production_receipt = self._receipt.receipt_type in ("Production", "ProductionVPP")
        if environment == "Production" and not production_receipt:
            return STATUS_SANDBOX_RECEIPT_ON_PRODUCTION
        if environment == "Sandbox" and production_receipt:
            return STATUS_PRODUCTION_RECEIPT_ON_SANDBOX
        return STATUS_OK


class VerifyReceiptEndpoint:
    """One instance emulates one environment (drives 21007/21008 routing).

    :param trusted_roots: pinned roots
        (production: :func:`apple_purchase_receipt_verifier.apple_receipt_roots`)
    :param environment: ``"Production"`` or ``"Sandbox"``
    :param clock: source of "now" for the ``request_date`` fields, as a
        zero-argument callable returning epoch seconds — same shape and
        default as :class:`~apple_purchase_receipt_verifier.JwsVerifier`'s
        ``clock``. Optional; omitted, the system clock is used and behaviour
        is unchanged. Apple stamps ``request_date`` with the time the request
        was answered, which is wall-clock by definition, so the seam covers
        it too; nothing else in a response moves with time (every other date
        comes off the signed receipt).

    No method raises on any request input: failures come back as a
    :class:`VerifyReceiptResult` with a status and a
    :attr:`~VerifyReceiptResult.failure_reason`. :meth:`verify_receipt_result`
    and :meth:`verify_receipt_data` also take a keyword-only ``now``, a
    timezone-aware ``datetime`` that becomes ``request_date`` in place of the
    clock. It reaches ``request_date`` and nothing else: certificate validity
    never sees it. A naive ``now`` raises ``ValueError``, since it names no
    instant.
    """

    def __init__(
        self,
        trusted_roots: "Iterable[x509.Certificate]",
        environment: str,
        clock: Callable[[], float] | None = None,
    ) -> None:
        roots = list(trusted_roots)
        if not roots:
            raise ValueError("trusted_roots must not be empty")
        if environment not in _ENDPOINT_ENVIRONMENTS:
            raise ValueError(_ENVIRONMENT_ERROR)
        self._roots = roots
        self._environment = environment
        self._clock = time.time if clock is None else clock

    def verify_receipt_result(
        self,
        request: Mapping[str, Any] | str | bytes | None,
        *,
        now: datetime | None = None,
    ) -> VerifyReceiptResult:
        """Handles one verifyReceipt request: a request body already decoded
        to a mapping, or the raw JSON text an HTTP framework hands over.

        A body that is not a JSON object (unparseable, ``null``, an array, a
        scalar), or a ``receipt-data`` that is missing, empty or not a
        string, fails with :attr:`Reason.MALFORMED_REQUEST`, status 21002.
        Apple has no status code for "that wasn't JSON"; 21002 ("The data in
        the receipt-data property was malformed or missing") is the closest.
        """
        at = self._request_date(now)
        if isinstance(request, (str, bytes, bytearray)):
            return self._from_json(request, at)
        return self._from_mapping(request, at)

    def verify_receipt_data(
        self, receipt_data: str | None, *, now: datetime | None = None
    ) -> VerifyReceiptResult:
        """Verifies a bare base64 receipt, the value a request body carries
        as ``receipt-data``, with no envelope around it. ``None`` or an empty
        string fails with :attr:`Reason.MALFORMED_REQUEST`, as a missing
        ``receipt-data`` does."""
        return self._verify(receipt_data, self._request_date(now))

    def verify_receipt_json(self, body: str) -> str:
        """Handles one verifyReceipt request body in its raw wire form: the
        JSON request body in, the JSON response body out, so an HTTP
        framework's body can be piped straight through without a DTO in
        between. The same as ``verify_receipt_result(body).to_json()``.

        Output is deterministic: dicts preserve insertion order, so equal
        inputs serialize to equal bytes. Key order is not part of the JSON
        contract."""
        return self._from_json(body, self._request_date(None)).to_json()

    def _request_date(self, now: datetime | None) -> datetime:
        if now is None:
            return datetime.fromtimestamp(self._clock(), timezone.utc)
        if now.utcoffset() is None:
            raise ValueError("now must be a timezone-aware datetime")
        return now.astimezone(timezone.utc)

    def _failed(self, reason: str, at: datetime) -> VerifyReceiptResult:
        return VerifyReceiptResult._create(self._environment, None, reason, None, at)

    def _from_json(self, body: object, at: datetime) -> VerifyReceiptResult:
        try:
            parsed = json.loads(body)  # type: ignore[arg-type]
        except (ValueError, TypeError, RecursionError):
            # RecursionError is a body nested too deep to parse: still a body
            # that could not be read.
            return self._failed(Reason.MALFORMED_REQUEST, at)
        if not isinstance(parsed, dict):
            return self._failed(Reason.MALFORMED_REQUEST, at)
        return self._from_mapping(parsed, at)

    def _from_mapping(self, request: object, at: datetime) -> VerifyReceiptResult:
        try:
            receipt_data = request.get("receipt-data") if isinstance(request, Mapping) else None
        except Exception as e:
            return VerifyReceiptResult._create(
                self._environment, None, Reason.INTERNAL_ERROR, e, at
            )
        return self._verify(receipt_data, at)

    def _verify(self, receipt_data: object, at: datetime) -> VerifyReceiptResult:
        """The one verification path every entry point ends in. ``at`` only
        becomes ``request_date``: certificate validity is judged inside
        :func:`verify_receipt_core`, which takes no time input."""
        try:
            if not isinstance(receipt_data, str) or not receipt_data:
                return self._failed(Reason.MALFORMED_REQUEST, at)
            der = decode_receipt_base64(receipt_data)
            receipt = verify_receipt_core(der, self._roots)
        except VerificationError as e:
            return self._failed(e.reason, at)
        except Exception as e:
            return VerifyReceiptResult._create(
                self._environment, None, Reason.INTERNAL_ERROR, e, at
            )
        return VerifyReceiptResult._create(self._environment, receipt, None, None, at)


def _receipt_json(fields: AppReceipt, request_date: datetime) -> dict[str, Any]:
    receipt: dict[str, Any] = {}
    _put(receipt, "receipt_type", fields.receipt_type)
    # Apple echoes attribute 1 under both names — its response reference
    # defines adam_id as "See app_item_id" — and as JSON numbers, not as the
    # strings the in-app integers are rendered with.
    _put(receipt, "adam_id", fields.app_item_id)
    _put(receipt, "app_item_id", fields.app_item_id)
    _put(receipt, "bundle_id", fields.bundle_id)
    _put(receipt, "application_version", fields.app_version)
    _put(receipt, "download_id", fields.download_id)
    _put(receipt, "version_external_identifier", fields.version_external_identifier)
    _put(receipt, "original_application_version", fields.original_app_version)
    _apple_dates(receipt, "receipt_creation_date", fields.creation_date)
    _apple_dates(receipt, "request_date", request_date)
    _apple_dates(receipt, "original_purchase_date", fields.original_purchase_date)
    _apple_dates(receipt, "expiration_date", fields.expiration_date)
    receipt["in_app"] = [_in_app_json(p) for p in fields.in_app_purchases]
    return receipt


def _in_app_json(purchase: InAppPurchase) -> dict[str, Any]:
    entry: dict[str, Any] = {}
    _put(entry, "quantity", _str_or_none(purchase.quantity))
    _put(entry, "product_id", purchase.product_id)
    _put(entry, "transaction_id", purchase.transaction_id)
    _put(entry, "original_transaction_id", purchase.original_transaction_id)
    _apple_dates(entry, "purchase_date", purchase.purchase_date)
    _apple_dates(entry, "original_purchase_date", purchase.original_purchase_date)
    _apple_dates(entry, "expires_date", purchase.expires_date)
    _apple_dates(entry, "cancellation_date", purchase.cancellation_date)
    _put(entry, "web_order_line_item_id", _str_or_none(purchase.web_order_line_item_id))
    if purchase.is_trial_period is not None:
        entry["is_trial_period"] = "true" if purchase.is_trial_period == 1 else "false"
    if purchase.is_in_intro_offer_period is not None:
        entry["is_in_intro_offer_period"] = (
            "true" if purchase.is_in_intro_offer_period == 1 else "false"
        )
    return entry


def _str_or_none(value: int | None) -> str | None:
    return None if value is None else str(value)


def _put(target: dict[str, Any], key: str, value: Any) -> None:
    if value is not None:
        target[key] = value


def _apple_dates(target: dict[str, Any], prefix: str, date: datetime | None) -> None:
    """Apple's three date renderings: ``x`` (GMT), ``x_ms``, ``x_pst``."""
    if date is None:
        return
    utc = date.astimezone(timezone.utc)
    target[prefix] = utc.strftime("%Y-%m-%d %H:%M:%S") + " Etc/GMT"
    target[prefix + "_ms"] = str(int(utc.timestamp() * 1000))
    target[prefix + "_pst"] = (
        utc.astimezone(_PACIFIC).strftime("%Y-%m-%d %H:%M:%S") + " America/Los_Angeles"
    )
