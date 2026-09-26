from aprv_uniffi_remote import verify_base64, VerifyError, Reason
b = "".join(open("$REPO/fixtures/public-receipts/receipt-sandbox-g5.b64").read().split())
r = verify_base64("dev.bonzer.weeka.app", b); print("ok:", r.bundle_id, r.creation_date_ms, r.in_app_purchase_count)
try: verify_base64("x.y", b)
except VerifyError.Verification as e: print("error ok:", e.reason)
