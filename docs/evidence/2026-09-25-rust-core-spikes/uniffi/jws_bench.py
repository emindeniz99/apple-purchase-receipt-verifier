import time
from aprv_uniffi import JwsVerifier, Environment
F="../../../../fixtures/"
j = JwsVerifier("com.example.app", [Environment.SANDBOX], None, [open(F+"generated/jws-root.der","rb").read()])
s = open(F+"generated/transaction.jws").read().strip()
for _ in range(50): j.verify_transaction(s)
t=time.perf_counter(); n=500
for _ in range(n): j.verify_transaction(s)
print("native (uniffi/python) jws", round((time.perf_counter()-t)/n*1e6), "us/op")
