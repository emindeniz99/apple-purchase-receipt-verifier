"""The ``status`` codes Apple documents for its verifyReceipt endpoint, so
callers do not write ``21007`` by hand.

:func:`~.verifier.Verifier.verify_receipt_endpoint` returns only
:data:`OK`, :data:`MALFORMED_RECEIPT_DATA`, :data:`RECEIPT_NOT_AUTHENTICATED`,
:data:`SANDBOX_RECEIPT_ON_PRODUCTION`, :data:`PRODUCTION_RECEIPT_ON_SANDBOX`
and :data:`INTERNAL_DATA_ACCESS_ERROR`. Its 21009 is deterministic for the
same input, so alert on it rather than retry. It never returns
:data:`SERVER_UNAVAILABLE` or the 21100-21199 range, which mean Apple's own
servers failed and invite a retry.
"""

#: The receipt is valid.
OK = 0
#: The request was not an HTTP POST.
REQUEST_NOT_POST = 21000
#: No longer sent by the App Store.
NO_LONGER_SENT = 21001
#: The ``receipt-data`` property was malformed or missing.
MALFORMED_RECEIPT_DATA = 21002
#: The receipt could not be authenticated.
RECEIPT_NOT_AUTHENTICATED = 21003
#: The shared secret does not match the one on file for the account.
SHARED_SECRET_MISMATCH = 21004
#: The receipt server was temporarily unable to provide the receipt.
SERVER_UNAVAILABLE = 21005
#: The receipt is valid but the subscription has expired (iOS 6-style
#: receipts only).
SUBSCRIPTION_EXPIRED = 21006
#: A sandbox receipt was sent to the production environment.
SANDBOX_RECEIPT_ON_PRODUCTION = 21007
#: A production receipt was sent to the sandbox environment.
PRODUCTION_RECEIPT_ON_SANDBOX = 21008
#: Internal data access error.
INTERNAL_DATA_ACCESS_ERROR = 21009
#: The user account cannot be found or has been deleted.
ACCOUNT_NOT_FOUND = 21010
#: First code of the 21100-21199 range of Apple's internal data access errors.
INTERNAL_DATA_ACCESS_ERROR_RANGE_FIRST = 21100
#: Last code of the 21100-21199 range of Apple's internal data access errors.
INTERNAL_DATA_ACCESS_ERROR_RANGE_LAST = 21199
