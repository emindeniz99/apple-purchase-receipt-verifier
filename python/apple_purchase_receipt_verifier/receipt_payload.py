"""The decoded payload of a verified legacy app receipt (docs/design/0.7-api.md
§1). Frozen dataclasses: immutable, with public constructors so callers can
build payloads by hand in their own tests.

Names are the keys of Apple's verifyReceipt response, so these classes,
:meth:`ReceiptPayload.to_json` and Apple's documentation share one
vocabulary. Each attribute's docstring names its receipt attribute type.
``None`` means the attribute was absent (or, for a date, did not parse); the
library invents no values. Dates are epoch milliseconds, UTC; receipts carry
whole seconds, so they end in ``000``.

Nothing here has been checked against anything: the bundle id, environment
and purchases are whatever Apple signed, and deciding whether to accept them
is the caller's job. :meth:`~.environment.Environment.from_receipt_type`
reads :attr:`ReceiptPayload.receipt_type`; the device-hash check is
``SHA-1(device_id + opaque_value + bundle_id_bytes)`` compared with
:attr:`ReceiptPayload.sha1_hash`.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType

from . import _canonical_json


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

    def __post_init__(self) -> None:
        object.__setattr__(self, "unknown_attributes", _frozen_attributes(self.unknown_attributes))

    def _write_json(self) -> str:
        writer = (
            _canonical_json.ObjectWriter()
            .number("quantity", self.quantity)
            .string("product_id", self.product_id)
            .string("transaction_id", self.transaction_id)
            .number("purchase_date_ms", self.purchase_date_ms)
            .string("original_transaction_id", self.original_transaction_id)
            .number("original_purchase_date_ms", self.original_purchase_date_ms)
            .number("expires_date_ms", self.expires_date_ms)
            .id_("web_order_line_item_id", self.web_order_line_item_id)
            .number("cancellation_date_ms", self.cancellation_date_ms)
            .bool_("is_trial_period", self.is_trial_period)
            .bool_("is_in_intro_offer_period", self.is_in_intro_offer_period)
            .attributes("unknown_attributes", self.unknown_attributes)
        )
        return writer.build()


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

    def __post_init__(self) -> None:
        object.__setattr__(self, "in_app", tuple(self.in_app))
        object.__setattr__(self, "unknown_attributes", _frozen_attributes(self.unknown_attributes))

    def to_json(self) -> str:
        """This payload as canonical JSON, for logging and storage. Every
        port writes the same bytes: keys in declaration order, snake_case
        names, dates as numbers with a ``_ms`` suffix, 64-bit ids
        (``app_item_id``, ``download_id``, ``version_external_identifier``,
        ``web_order_line_item_id``) as strings, bytes as padded standard
        base64, ``null`` for a missing value, no whitespace, only the
        escapes JSON requires, and non-ASCII characters raw."""
        in_app_json = "[" + ",".join(p._write_json() for p in self.in_app) + "]"
        writer = (
            _canonical_json.ObjectWriter()
            .string("receipt_type", self.receipt_type)
            .id_("app_item_id", self.app_item_id)
            .string("bundle_id", self.bundle_id)
            .bytes_("bundle_id_bytes", self.bundle_id_bytes)
            .string("application_version", self.application_version)
            .bytes_("opaque_value", self.opaque_value)
            .bytes_("sha1_hash", self.sha1_hash)
            .number("receipt_creation_date_ms", self.receipt_creation_date_ms)
            .id_("download_id", self.download_id)
            .id_("version_external_identifier", self.version_external_identifier)
            .raw("in_app", in_app_json)
            .number("original_purchase_date_ms", self.original_purchase_date_ms)
            .string("original_application_version", self.original_application_version)
            .number("expiration_date_ms", self.expiration_date_ms)
            .attributes("unknown_attributes", self.unknown_attributes)
        )
        return writer.build()


@dataclass(frozen=True)
class JsonPayload:
    """A verified StoreKit 2 / App Store Server JWS payload."""

    #: The verified payload, unchanged: the exact UTF-8 text the JWS's
    #: payload segment decoded to.
    json: str
