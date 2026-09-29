import aprv
print("version:", aprv.aprv_version())
r = aprv.AprvResult()
v = aprv.aprv_verifier_new_receipt("dev.bonzer.weeka.app")
b64 = "".join(open("../../../../fixtures/public-receipts/receipt-sandbox-g5.b64").read().split())
status = aprv.aprv_verify_receipt_base64(v, b64, r)
print("status:", status, "json starts:", (r.json or "")[:60])
