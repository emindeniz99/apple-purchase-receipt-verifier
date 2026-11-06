"""Reads the JSON ``aprv.wasm`` answers with and builds the one JSON it takes
(docs/rust-core/ARCHITECTURE.md section 4, docs/design/0.7-api.md "Our
JSON"). Mapping only: the module has already decided every verdict, and a
value that does not have the shape the contract gives is a fault of the
module, never a verdict.
"""

import base64
import json
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar

from .environment import Environment
from .reason import Reason
from .receipt_payload import InAppPurchase, JsonPayload, ReceiptPayload
from .result import Failure, VerificationResult

T = TypeVar("T")


class ResultShapeError(Exception):
    """The module's answer is not the JSON the contract describes."""


def _base64(values: "Iterable[bytes]") -> "list[str]":
    return [base64.b64encode(value).decode("ascii") for value in values]


def init_config(
    roots: "Iterable[bytes] | None",
    revocation_lists: "Iterable[bytes]" = (),
    revocation_issuers: "Iterable[bytes]" = (),
    distrust: "Iterable[tuple[str, str]]" = (),
) -> bytes:
    """``init``'s argument: ``{"roots":["<base64>", ...]}``, each root's DER or
    PEM bytes, with no ``roots`` member for ``None``, the Apple roots compiled
    into the module; then each revocation setting that is not empty:
    ``revocation_lists`` and ``revocation_issuers`` as base64,
    ``distrust`` as ``[{"issuer":...,"serial":...}]`` with the strings as
    given. With nothing set it is ``{}``."""
    config: dict[str, object] = {}
    if roots is not None:
        config["roots"] = _base64(roots)
    lists, issuers = _base64(revocation_lists), _base64(revocation_issuers)
    entries = [{"issuer": issuer, "serial": serial} for issuer, serial in distrust]
    if lists:
        config["revocation_lists"] = lists
    if issuers:
        config["revocation_issuers"] = issuers
    if entries:
        config["distrust"] = entries
    return json.dumps(config, separators=(",", ":")).encode("ascii")


def _max_input_bytes(value: "dict[str, Any]") -> int:
    """The ``max_input_bytes`` of an accepting answer, a positive integer.
    An answer without one comes from a module of another ABI version."""
    limit = value.get("max_input_bytes")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise ResultShapeError("init accepted the roots but stated no max_input_bytes")
    return limit


_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def read_init(answer: str) -> "str | tuple[tuple[str, ...], datetime | None]":
    """``init``'s refusal message, or, when it accepted the configuration,
    the revocation state its answer states: ``revocation_urls``, a list of
    strings, and ``revocation_valid_until_ms``, epoch milliseconds or
    ``null``, as a UTC ``datetime`` or ``None``. An accepting answer without
    ``max_input_bytes`` and both of those comes from a module of another
    version."""
    value = _object(answer)
    if value.get("ok") is False and isinstance(value.get("message"), str):
        return str(value["message"])
    if value.get("ok") is not True:
        raise ResultShapeError("init answered neither ok nor a refusal")
    _max_input_bytes(value)
    urls = value.get("revocation_urls")
    if not isinstance(urls, list) or not all(isinstance(url, str) for url in urls):
        raise ResultShapeError("init accepted the configuration but stated no revocation_urls")
    until = value.get("revocation_valid_until_ms")
    stated = "revocation_valid_until_ms" in value
    if not stated or (
        until is not None and (not isinstance(until, int) or isinstance(until, bool))
    ):
        raise ResultShapeError(
            "init accepted the configuration but stated no revocation_valid_until_ms"
        )
    try:
        valid_until = None if until is None else _EPOCH + timedelta(milliseconds=until)
    except OverflowError as error:
        raise ResultShapeError("revocation_valid_until_ms is outside the datetime range") from error
    return tuple(urls), valid_until


def init_accepted(answer: str) -> "int | None":
    """The ``max_input_bytes`` of ``init`` taking the roots: the most bytes
    of one input the module needs. ``None`` for a refusal or an answer of
    another shape."""
    try:
        value = _object(answer)
        return _max_input_bytes(value) if value.get("ok") is True else None
    except ResultShapeError:
        return None


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
        cancellation_reason=_number(value.get("cancellation_reason")),
        is_trial_period=_flag(value.get("is_trial_period")),
        is_in_intro_offer_period=_flag(value.get("is_in_intro_offer_period")),
        unknown_attributes=_unknown(value.get("unknown_attributes")),
    )


def _receipt_payload(value: object, environment: "Environment | None") -> ReceiptPayload:
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
        preorder_date_ms=_number(value.get("preorder_date_ms")),
        original_application_version=_string(value.get("original_application_version")),
        expiration_date_ms=_number(value.get("expiration_date_ms")),
        unknown_attributes=_unknown(value.get("unknown_attributes")),
        environment=environment,
    )


def _failure(value: "dict[str, Any]") -> Failure:
    token, message = value.get("reason"), value.get("message")
    if not isinstance(token, str) or not isinstance(message, str):
        raise ResultShapeError("a failure without a reason and a message")
    try:
        reason = Reason(token)
    except ValueError as error:
        raise ResultShapeError("a reason this package does not know") from error
    return Failure(reason, message)


def _environment(value: "dict[str, Any]") -> "Environment | None":
    """The ``environment`` member beside a verified payload: ``Production``,
    ``Sandbox`` or ``null``. Missing, or anything else, is not the contract."""
    if "environment" not in value:
        raise ResultShapeError("a verified answer without an environment")
    environment = value["environment"]
    if environment is None:
        return None
    if isinstance(environment, str):
        try:
            return Environment(environment)
        except ValueError:
            pass
    raise ResultShapeError("an environment other than Production, Sandbox or null")


def _result(
    text: str, payload: "Callable[[object, Environment | None], T]"
) -> "VerificationResult[T]":
    value = _object(text)
    verified = value.get("verified")
    if verified is True and "payload" in value:
        return VerificationResult(payload=payload(value["payload"], _environment(value)))
    if verified is False:
        return VerificationResult(failure=_failure(value))
    raise ResultShapeError("the answer is neither a payload nor a failure")


def receipt_result(text: str) -> "VerificationResult[ReceiptPayload]":
    return _result(text, _receipt_payload)


def _signed_payload(value: object, environment: "Environment | None") -> JsonPayload:
    if not isinstance(value, str):
        raise ResultShapeError("the signed payload is not a JSON string")
    return JsonPayload(json=value, environment=environment)


def signed_data_result(text: str) -> "VerificationResult[JsonPayload]":
    return _result(text, _signed_payload)


def endpoint_answer(text: str) -> str:
    """The endpoint's answer, Apple's response JSON, is handed on byte for
    byte; it is only checked to be a JSON object with an integer ``status``."""
    status = _object(text).get("status")
    if not isinstance(status, int) or isinstance(status, bool):
        raise ResultShapeError("the endpoint answer has no integer status")
    return text
