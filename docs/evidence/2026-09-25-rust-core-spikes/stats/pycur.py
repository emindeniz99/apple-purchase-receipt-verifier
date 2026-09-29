import time
from apple_purchase_receipt_verifier import ReceiptVerifier, JwsVerifier, apple_receipt_roots
from cryptography import x509
F="$REPO/fixtures/"
b64="".join(open(F+"public-receipts/receipt-sandbox-g5.b64").read().split())
v=ReceiptVerifier(apple_receipt_roots(),"dev.bonzer.weeka.app")
for _ in range(30): v.verify(b64)
t=time.perf_counter(); n=200
for _ in range(n): r=v.verify(b64)
print("pypi 0.6.0 receipt g5", round((time.perf_counter()-t)/n*1e6), "us/op")
root=x509.load_der_x509_certificate(open(F+"generated/jws-root.der","rb").read())
j=JwsVerifier([root],"com.example.app",{"Sandbox"})
s=open(F+"generated/transaction.jws").read().strip()
for _ in range(30): j.verify_transaction(s)
t=time.perf_counter(); n=500
for _ in range(n): j.verify_transaction(s)
print("pypi 0.6.0 jws", round((time.perf_counter()-t)/n*1e6), "us/op")
