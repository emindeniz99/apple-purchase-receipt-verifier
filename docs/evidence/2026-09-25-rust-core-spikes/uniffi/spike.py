import base64, time
from aprv_uniffi import ReceiptVerifier, JwsVerifier, Environment, VerifyError, Reason
F = "../../../../fixtures"
rd = lambda p: open(f"{F}/{p}", "rb").read()
# 1. generated receipt, fixture root
v = ReceiptVerifier("com.example.app", [rd("generated/receipt-root.der")])
r = v.verify(rd("generated/receipt.der"))
print("receipt ok:", r.bundle_id, r.app_version, r.receipt_type, r.creation_date_ms, len(r.in_app_purchases), r.opaque_value.hex())
# 2. genuine Apple G5 sandbox receipt, default (pinned Apple) roots, keyword default arg
g = ReceiptVerifier(bundle_id="dev.bonzer.weeka.app")
b64 = "".join(rd("public-receipts/receipt-sandbox-g5.b64").decode().split())
t = time.perf_counter(); n = 200
for _ in range(n): r = g.verify_base64(b64)
print("genuine g5 ok:", r.bundle_id, len(r.in_app_purchases), f"{(time.perf_counter()-t)/n*1e6:.0f} us/op incl. FFI")
# 3. wrong bundle id -> typed exception
try:
    ReceiptVerifier("com.other.app", [rd("generated/receipt-root.der")]).verify(rd("generated/receipt.der"))
except VerifyError.Verification as e:
    print("error ok:", type(e).__name__, e.reason, "|", e.detail)
# 4. JWS
j = JwsVerifier("com.example.app", [Environment.SANDBOX], None, [rd("generated/jws-root.der")])
p = j.verify_transaction(rd("generated/transaction.jws").decode().strip())
print("jws ok:", p.product_id, p.transaction_id, p.signed_date, len(p.claims_json))
try:
    JwsVerifier("com.example.app", [Environment.PRODUCTION], None, [rd("generated/jws-root.der")]).verify_transaction(rd("generated/transaction.jws").decode().strip())
except VerifyError.Verification as e:
    print("env error ok:", e.reason)
# 5. bad config
try:
    ReceiptVerifier("x", [b"not a cert"])
except VerifyError.Config as e:
    print("config error ok:", e.detail)
print(ReceiptVerifier.__init__.__doc__)
