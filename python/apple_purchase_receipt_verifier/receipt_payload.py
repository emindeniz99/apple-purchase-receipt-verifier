"""The decoded payload of a verified legacy app receipt (docs/design/0.7-api.md
§1). Frozen dataclasses: immutable, with public constructors so callers can
build payloads by hand in their own tests.

Names are the keys of Apple's verifyReceipt response, so these classes,
:meth:`ReceiptPayload.to_json` and Apple's documentation share one
vocabulary. Each attribute's docstring names its receipt attribute type.
``None`` means the attribute was absent (or, for a date, did not parse); the
library invents no values. Dates are epoch milliseconds, UTC; a receipt date
is an RFC 3339 date-time, its fraction truncated to the millisecond.

Nothing here has been checked against anything: the bundle id, environment
and purchases are whatever Apple signed, and deciding whether to accept them
is the caller's job. :attr:`ReceiptPayload.environment` and
:attr:`JsonPayload.environment` state the environment the verifier read;
the device-hash check is
``SHA-1(device_id + opaque_value + bundle_id_bytes)`` compared with
:attr:`ReceiptPayload.sha1_hash`.
"""

import base64
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType

from .environment import Environment


def _id(value: "int | None") -> "str | None":
    """A 64-bit id as a decimal string, so JavaScript readers do not round it."""
    return None if value is None else str(value)


def _base64(value: "bytes | None") -> "str | None":
    return None if value is None else base64.b64encode(value).decode("ascii")


def _attributes_json(attributes: "Mapping[int, Sequence[bytes]]") -> "dict[str, list[str]]":
    return {
        str(k): [base64.b64encode(v).decode("ascii") for v in attributes[k]]
        for k in sorted(attributes)
    }


def _frozen_attributes(
    attributes: "Mapping[int, Sequence[bytes]]",
) -> "MappingProxyType[int, tuple[bytes, ...]]":
    return MappingProxyType({k: tuple(v) for k, v in attributes.items()})


@dataclass(frozen=True)
class InAppPurchase:
    """One in-app purchase from a legacy app receipt (attribute 17)."""

    #: Attribute 1701.
    quantity: "int | None" = None
    #: Attribute 1702.
    product_id: "str | None" = None
    #: Attribute 1703.
    transaction_id: "str | None" = None
    #: Attribute 1704.
    purchase_date_ms: "int | None" = None
    #: Attribute 1705.
    original_transaction_id: "str | None" = None
    #: Attribute 1706.
    original_purchase_date_ms: "int | None" = None
    #: Attribute 1708, set for subscriptions.
    expires_date_ms: "int | None" = None
    #: Attribute 1711.
    web_order_line_item_id: "int | None" = None
    #: Attribute 1712, set when Apple support refunded the purchase.
    cancellation_date_ms: "int | None" = None
    #: Attribute 1713: 0 is ``False``, any other value ``True``.
    is_trial_period: "bool | None" = None
    #: Attribute 1719: 0 is ``False``, any other value ``True``.
    is_in_intro_offer_period: "bool | None" = None
    #: Raw value octets of the attribute types not modelled above, by type,
    #: in receipt order, so a field Apple adds later is not lost.
    unknown_attributes: "Mapping[int, Sequence[bytes]]" = field(
        default_factory=lambda: MappingProxyType({})
    )

    #: Attribute 1720, as a decimal string.
    cancellation_reason: "str | None" = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "unknown_attributes", _frozen_attributes(self.unknown_attributes))

    def _json_value(self) -> "dict[str, object]":
        return {
            "quantity": self.quantity,
            "product_id": self.product_id,
            "transaction_id": self.transaction_id,
            "purchase_date_ms": self.purchase_date_ms,
            "original_transaction_id": self.original_transaction_id,
            "original_purchase_date_ms": self.original_purchase_date_ms,
            "expires_date_ms": self.expires_date_ms,
            "web_order_line_item_id": _id(self.web_order_line_item_id),
            "cancellation_date_ms": self.cancellation_date_ms,
            **(
                {}
                if self.cancellation_reason is None
                else {"cancellation_reason": self.cancellation_reason}
            ),
            "is_trial_period": self.is_trial_period,
            "is_in_intro_offer_period": self.is_in_intro_offer_period,
            "unknown_attributes": _attributes_json(self.unknown_attributes),
        }


@dataclass(frozen=True)
class ReceiptPayload:
    """A verified legacy app receipt. Only receipts returned by
    :func:`~.verifier.Verifier.verify_receipt` should be trusted."""

    #: Attribute 0, such as ``Production`` or ``ProductionSandbox``.
    receipt_type: "str | None" = None
    #: Attribute 1, the app's App Store item id; zero in sandbox receipts.
    app_item_id: "int | None" = None
    #: Attribute 2, decoded.
    bundle_id: "str | None" = None
    #: Attribute 2, the value octets exactly as they sit in the receipt:
    #: input to the device hash.
    bundle_id_bytes: "bytes | None" = None
    #: Attribute 3.
    application_version: "str | None" = None
    #: Attribute 4, the value octets: input to the device hash.
    opaque_value: "bytes | None" = None
    #: Attribute 5, the value octets: the device hash itself.
    sha1_hash: "bytes | None" = None
    #: Attribute 12, when Apple created the receipt.
    receipt_creation_date_ms: "int | None" = None
    #: Attribute 15.
    download_id: "int | None" = None
    #: Attribute 16.
    version_external_identifier: "int | None" = None
    #: Attribute 17, one entry per purchase, in receipt order.
    in_app: "Sequence[InAppPurchase]" = field(default_factory=tuple)
    #: Attribute 18.
    original_purchase_date_ms: "int | None" = None
    #: Attribute 32, the pre-order date. Keyword-only, so a payload built
    #: with positional arguments keeps meaning what it meant.
    preorder_date_ms: "int | None" = field(default=None, kw_only=True)
    #: Attribute 19, the version the user originally purchased.
    original_application_version: "str | None" = None
    #: Attribute 21, set only on receipts that expire (volume purchase).
    expiration_date_ms: "int | None" = None
    #: Raw value octets of the attribute types not modelled above, by type,
    #: in receipt order, so a field Apple adds later is not lost. The
    #: attribute's ``version`` integer is not kept.
    unknown_attributes: "Mapping[int, Sequence[bytes]]" = field(
        default_factory=lambda: MappingProxyType({})
    )
    #: The environment :attr:`receipt_type` names, as the verifier read it:
    #: ``Production`` and ``ProductionVPP`` are
    #: :attr:`~.environment.Environment.PRODUCTION`, ``ProductionSandbox``
    #: and ``ProductionVPPSandbox`` :attr:`~.environment.Environment.SANDBOX`,
    #: anything else (``Xcode``, a missing value) ``None``. It states what
    #: Apple's value means and decides nothing; :meth:`to_json` does not
    #: write it. A payload built by hand states the one it is given.
    environment: "Environment | None" = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "in_app", tuple(self.in_app))
        object.__setattr__(self, "unknown_attributes", _frozen_attributes(self.unknown_attributes))

    def to_json(self) -> str:
        """This payload as JSON. It holds the full purchase data; the caller
        decides what to write where. Every port writes the same value (the
        bytes may differ): snake_case keys, dates as numbers with a ``_ms``
        suffix, 64-bit ids (``app_item_id``,
        ``download_id``, ``version_external_identifier``,
        ``web_order_line_item_id``) as strings, bytes as padded standard
        base64 and ``null`` for a missing value. Non-ASCII is escaped, so
        the text is ASCII and therefore valid UTF-8."""
        value = {
            "receipt_type": self.receipt_type,
            "app_item_id": _id(self.app_item_id),
            "bundle_id": self.bundle_id,
            "bundle_id_bytes": _base64(self.bundle_id_bytes),
            "application_version": self.application_version,
            "opaque_value": _base64(self.opaque_value),
            "sha1_hash": _base64(self.sha1_hash),
            "receipt_creation_date_ms": self.receipt_creation_date_ms,
            "download_id": _id(self.download_id),
            "version_external_identifier": _id(self.version_external_identifier),
            "in_app": [p._json_value() for p in self.in_app],
            "original_purchase_date_ms": self.original_purchase_date_ms,
            "preorder_date_ms": self.preorder_date_ms,
            "original_application_version": self.original_application_version,
            "expiration_date_ms": self.expiration_date_ms,
            "unknown_attributes": _attributes_json(self.unknown_attributes),
        }
        return json.dumps(value, separators=(",", ":"), allow_nan=False)


@dataclass(frozen=True)
class JsonPayload:
    """A verified StoreKit 2 / App Store Server JWS payload."""

    #: The verified payload, unchanged: the exact UTF-8 text the JWS's
    #: payload segment decoded to.
    json: str
    #: The environment the payload names, as the verifier read it: from the
    #: first of the three places Apple documents that is present, the
    #: top-level ``environment`` (a transaction, renewal info),
    #: ``data.environment`` (an App Store Server Notification V2) and
    #: ``summary.environment`` (a summary notification). ``Production`` is
    #: :attr:`~.environment.Environment.PRODUCTION` and ``Sandbox``
    #: :attr:`~.environment.Environment.SANDBOX`; anything else there
    #: (``Xcode``, ``LocalTesting``, a value that is not a string), or none of
    #: the three, is ``None``. A payload built by hand states the one it is
    #: given; nothing reads it from :attr:`json`.
    environment: "Environment | None" = None
