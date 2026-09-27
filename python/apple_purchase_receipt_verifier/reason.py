"""Why verification failed — the 0.7 API (docs/design/0.7-api.md). The same
values, with the same meaning, in every port."""

import enum


class Reason(enum.Enum):
    """Match on the enum member, never on ``.value`` alone, and never persist
    an ordinal: the set may grow between 0.x releases."""

    #: The base64, ASN.1, CMS or JWS structure is broken, or a structural
    #: bound was exceeded (JSON nesting deeper than 64, more than 10 embedded
    #: certificates, more than 4 SignerInfos). Decided before any signature
    #: is checked.
    MALFORMED = "MALFORMED"
    #: The input is over a fixed size cap: 3,145,728 UTF-8 bytes for a
    #: receipt or an endpoint request body, 262,144 for a JWS. Decided before
    #: anything is decoded.
    TOO_LARGE = "TOO_LARGE"
    #: The signature does not match the signed content.
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    #: The certificate chain does not reach a pinned root, or is longer than
    #: six certificates.
    UNTRUSTED_CHAIN = "UNTRUSTED_CHAIN"
    #: A certificate the check depends on does not decode, or is expired or
    #: not yet valid at the signing instant.
    INVALID_CERTIFICATE = "INVALID_CERTIFICATE"
    #: A certificate that chains to a pinned root but is of the wrong kind:
    #: the leaf lacks Apple's signing marker OID or the intermediate lacks
    #: Apple's WWDR marker OID.
    INVALID_CERTIFICATE_PURPOSE = "INVALID_CERTIFICATE_PURPOSE"
    #: The signature and chain verified, so the payload bytes are Apple's,
    #: but they do not parse. ``Failure.cause`` carries the parser's
    #: exception. Deterministic for the same input: alert, do not retry.
    UNREADABLE_PAYLOAD = "UNREADABLE_PAYLOAD"
    #: The library itself failed before it could decide. ``Failure.cause``
    #: carries the exception. Deterministic for the same input: alert, do
    #: not retry.
    INTERNAL_ERROR = "INTERNAL_ERROR"
