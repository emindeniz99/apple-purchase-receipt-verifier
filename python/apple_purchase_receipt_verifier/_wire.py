"""Reads the JSON ``aprv.wasm`` answers with and builds the one JSON it takes
(docs/rust-core/ARCHITECTURE.md section 4, docs/design/0.7-api.md "Our
JSON"). Mapping only: the module has already decided every verdict, and a
value that does not have the shape the contract gives is a fault of the
module, never a verdict.
"""

import base64
import json
from collections.abc import Callable, Iterable
from typing import Any, TypeVar

from .reason import Reason
from .receipt_payload import InAppPurchase, JsonPayload, ReceiptPayload
from .result import Failure, VerificationResult

T = TypeVar("T")


class ResultShapeError(Exception):
    """The module's answer is not the JSON the contract describes."""


def init_config(roots: "Iterable[bytes]") -> bytes:
    """``init``'s argument: ``{"roots":["<base64 DER>", ...]}``. An empty list
    means the Apple roots compiled into the module."""
    encoded = [base64.b64encode(der).decode("ascii") for der in roots]
    return json.dumps({"roots": encoded}, separators=(",", ":")).encode("ascii")


def check_init(answer: str) -> "str | None":
    """``None`` when ``init`` accepted the roots, else its refusal message."""
    value = _object(answer)
    if value.get("ok") is True:
        return None
    if value.get("ok") is False and isinstance(value.get("message"), str):
        return str(value["message"])
    raise ResultShapeError("init answered neither ok nor a refusal")


def init_accepted(answer: str) -> bool:
    """Whether ``answer`` is ``init`` taking the roots."""
    try:
        return check_init(answer) is None
    except ResultShapeError:
        return False


def _object(text: str) -> "dict[str, Any]":
    try:
        value = json.loads(text)
    except ValueError as error:
        raise ResultShapeError("the answer is not JSON") from error
    if not isinstance(value, dict):
        raise ResultShapeError("the answer is not a JSON object")
    return value


def _string(value: object) -> "str | None":
    if value is None or isinstance(value, str):
        return value
    raise ResultShapeError("expected a string or null")


def _number(value: object) -> "int | None":
    if value is None or (isinstance(value, int) and not isinstance(value, bool)):
        return value
    raise ResultShapeError("expected an integer or null")


def _flag(value: object) -> "bool | None":
    if value is None or isinstance(value, bool):
        return value
    raise ResultShapeError("expected a boolean or null")


def _id(value: object) -> "int | None":
    """A 64-bit id, sent as a decimal string so no reader rounds it."""
    text = _string(value)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError as error:
        raise ResultShapeError("expected a decimal id") from error


def _octets(value: object) -> "bytes | None":
    text = _string(value)
    if text is None:
        return None
    try:
        return base64.b64decode(text, validate=True)
    except ValueError as error:
        raise ResultShapeError("expected padded base64") from error


def _unknown(value: object) -> "dict[int, tuple[bytes, ...]]":
    """``{"<decimal type>": ["<base64>", ...]}`` in receipt order."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ResultShapeError("expected an object of unknown attributes")
    out: dict[int, tuple[bytes, ...]] = {}
    for key, values in value.items():
        if not isinstance(values, list):
            raise ResultShapeError("expected a list of attribute values")
        try:
            out[int(key)] = tuple(_required_octets(v) for v in values)
        except ValueError as error:
            raise ResultShapeError("expected a decimal attribute type") from error
    return out


def _required_octets(value: object) -> bytes:
    octets = _octets(value)
    if octets is None:
        raise ResultShapeError("expected base64, not null")
    return octets


def _in_app(value: object) -> InAppPurchase:
    if not isinstance(value, dict):
        raise ResultShapeError("expected an in-app purchase object")
    return InAppPurchase(
        quantity=_number(value.get("quantity")),
        product_id=_string(value.get("product_id")),
        transaction_id=_string(value.get("transaction_id")),
        purchase_date_ms=_number(value.get("purchase_date_ms")),
        original_transaction_id=_string(value.get("original_transaction_id")),
        original_purchase_date_ms=_number(value.get("original_purchase_date_ms")),
        expires_date_ms=_number(value.get("expires_date_ms")),
        web_order_line_item_id=_id(value.get("web_order_line_item_id")),
        cancellation_date_ms=_number(value.get("cancellation_date_ms")),
        is_trial_period=_flag(value.get("is_trial_period")),
        is_in_intro_offer_period=_flag(value.get("is_in_intro_offer_period")),
        unknown_attributes=_unknown(value.get("unknown_attributes")),
    )


def _receipt_payload(value: object) -> ReceiptPayload:
    if not isinstance(value, dict):
        raise ResultShapeError("expected a receipt payload object")
    in_app = value.get("in_app")
    if in_app is not None and not isinstance(in_app, list):
        raise ResultShapeError("expected a list of in-app purchases")
    return ReceiptPayload(
        receipt_type=_string(value.get("receipt_type")),
        app_item_id=_id(value.get("app_item_id")),
        bundle_id=_string(value.get("bundle_id")),
        bundle_id_bytes=_octets(value.get("bundle_id_bytes")),
        application_version=_string(value.get("application_version")),
        opaque_value=_octets(value.get("opaque_value")),
        sha1_hash=_octets(value.get("sha1_hash")),
        receipt_creation_date_ms=_number(value.get("receipt_creation_date_ms")),
        download_id=_id(value.get("download_id")),
        version_external_identifier=_id(value.get("version_external_identifier")),
        in_app=tuple(_in_app(p) for p in in_app or ()),
        original_purchase_date_ms=_number(value.get("original_purchase_date_ms")),
        original_application_version=_string(value.get("original_application_version")),
        expiration_date_ms=_number(value.get("expiration_date_ms")),
        unknown_attributes=_unknown(value.get("unknown_attributes")),
    )


def _failure(value: "dict[str, Any]") -> Failure:
    token, message = value.get("reason"), value.get("message")
    if not isinstance(token, str) or not isinstance(message, str):
        raise ResultShapeError("a failure without a reason and a message")
    try:
        reason = Reason(token)
    except ValueError as error:
        raise ResultShapeError("a reason outside the eight of 0.7") from error
    return Failure(reason, message)


def _result(text: str, payload: "Callable[[object], T]") -> "VerificationResult[T]":
    value = _object(text)
    verified = value.get("verified")
    if verified is True and "payload" in value:
        return VerificationResult(payload=payload(value["payload"]))
    if verified is False:
        return VerificationResult(failure=_failure(value))
    raise ResultShapeError("the answer is neither a payload nor a failure")


def receipt_result(text: str) -> "VerificationResult[ReceiptPayload]":
    return _result(text, _receipt_payload)


def _signed_payload(value: object) -> JsonPayload:
    if not isinstance(value, str):
        raise ResultShapeError("the signed payload is not a JSON string")
    return JsonPayload(json=value)


def signed_data_result(text: str) -> "VerificationResult[JsonPayload]":
    return _result(text, _signed_payload)


def endpoint_answer(text: str) -> str:
    """The endpoint's answer, Apple's response JSON, is handed on byte for
    byte; it is only checked to be a JSON object with an integer ``status``."""
    status = _object(text).get("status")
    if not isinstance(status, int) or isinstance(status, bool):
        raise ResultShapeError("the endpoint answer has no integer status")
    return text
