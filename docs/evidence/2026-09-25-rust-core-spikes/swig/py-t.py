import aprv
b = "".join(open("$REPO/fixtures/public-receipts/receipt-sandbox-g5.b64").read().split())
print("python:", aprv.verify_receipt_base64(aprv.aprv_verifier_new_receipt("dev.bonzer.weeka.app"), b)[:40])
try: aprv.verify_receipt_base64(aprv.aprv_verifier_new_receipt("x.y"), b)
except ValueError as e: print("python error ok:", e)
