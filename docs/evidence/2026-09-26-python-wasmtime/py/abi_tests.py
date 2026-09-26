#!/usr/bin/env python3
"""Spike only (2026-09-26). The ABI v1 round's 33 mandatory ABI tests
(js/abi-tests.mjs) on wasmtime-py through the facade, plus the facade's own
trap and lifetime behaviour. Every trap is caught, the instance discarded,
and a fresh instance must then verify g5.

    python abi_tests.py calls-cases.jsonl
"""
import base64
import json
import sys

import wasmtime

import aprv_wasm
from aprv_wasm import OP, Verifier, _Instance

calls = {c["id"]: c for c in (json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip())}
G5 = base64.b64decode(calls["receipt/verify-genuine-sandbox-g5-against-apple-roots"]["input"])
JWS_CALL = calls["transaction/verify-shared-sandbox"]
JWS = base64.b64decode(JWS_CALL["input"])
passed = failed = 0


def ok(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
    else:
        failed += 1
    print(f"{'PASS' if cond else 'FAIL'} {name}{': ' + detail if detail else ''}")


def attempt(f):
    i = _Instance()
    try:
        return "ok", f(i)
    except wasmtime.Trap as e:
        return "trap", f"Trap: {e.message.splitlines()[0]} (code {e.trap_code})"
    except aprv_wasm.AbiMismatchError as e:
        return "error", str(e)
    except Exception as e:  # noqa: BLE001
        return "error", f"{type(e).__name__}: {e}"


def g5_verifies():
    return json.loads(_Instance().invoke(OP["VERIFY_RECEIPT"], G5))["verified"] is True


def traps_then_recovers(name, f):
    kind, msg = attempt(f)
    after = g5_verifies()
    ok(name, kind == "trap" and after, f"{kind} ({msg}); fresh instance verifies g5: {after}")


def raw(i, name, *args):
    return i.exports[name](i.store, *args)


def with_handle(i):
    p = raw(i, "aprv_alloc", 4)
    return raw(i, "aprv_call", 1, OP["VERIFY_RECEIPT"], p, 4)


dec = json.loads
ok("aprv_abi_version() == 1", raw(_Instance(), "aprv_abi_version") == 1)
k, v = attempt(lambda i: dec(i.invoke(OP["VERIFY_RECEIPT"], G5)))
ok("aprv_call(1, VERIFY_RECEIPT, genuine g5) verifies", k == "ok" and v["verified"] is True and v["payload"]["bundleId"] == "dev.bonzer.weeka.app",
   f"bundleId {v['payload']['bundleId'] if k == 'ok' else v}")
k, v = attempt(lambda i: dec(i.invoke(JWS_CALL["op"], JWS)))
ok("aprv_call(1, VERIFY_SIGNED_DATA (test anchors), shared-sandbox JWS) verifies; payloadJson is the exact signed JSON and parses to payload",
   k == "ok" and v["verified"] is True and json.loads(v["payloadJson"]) == v["payload"], f"payloadJson {len(v['payloadJson']) if k == 'ok' else v} chars")
traps_then_recovers("aprv_call(0, garbage op, invalid ptr, absurd len) fails hard", lambda i: raw(i, "aprv_call", 0, 0x7FFFFFFF, -16, 0x7FFFFFFF))
traps_then_recovers("aprv_call(2, garbage op, invalid ptr, absurd len) fails hard", lambda i: raw(i, "aprv_call", 2, 0x7FFFFFFF, -16, 0x7FFFFFFF))
k, msg = attempt(lambda i: i.invoke(OP["VERIFY_RECEIPT"], G5, abi_version=2))
ok("bridge reports a version mismatch as an ABI error, never verified=false", k == "error" and "APRV Wasm ABI mismatch: module=1, caller=2" in msg, msg)


def mismatch_runs_nothing(i):
    before = dict(aprv_wasm.IMPORT_CALLS)
    frames = None
    try:
        raw(i, "aprv_call", 3, 1, 0, 0)
    except wasmtime.Trap as e:
        frames = [f.func_name for f in e.frames]
    return {k: aprv_wasm.IMPORT_CALLS[k] - before[k] for k in before}, frames


k, v = attempt(mismatch_runs_nothing)
ok("a version mismatch runs nothing (no host import called; the trap is in aprv_call itself)",
   k == "ok" and set(v[0].values()) == {0} and v[1] == ["aprv_call"], f"import calls during the call: {v[0]}, trap frames: {v[1]}" if k == "ok" else str(v))
for op in (0, 5, 99, 255, 256, 261, -1):
    traps_then_recovers(f"unknown operation {op} fails hard", lambda i, op=op: raw(i, "aprv_call", 1, op, raw(i, "aprv_alloc", 4), 4))
traps_then_recovers("null input pointer with a length fails hard", lambda i: raw(i, "aprv_call", 1, OP["VERIFY_RECEIPT"], 0, 10))
traps_then_recovers("input beyond linear memory fails hard", lambda i: raw(i, "aprv_call", 1, OP["VERIFY_RECEIPT"], i.memory.data_len(i.store) - 4, 16))
traps_then_recovers("input range that overflows u32 fails hard", lambda i: raw(i, "aprv_call", 1, OP["VERIFY_RECEIPT"], -16, 0x20))
k, v = attempt(lambda i: dec(i.invoke(OP["VERIFY_RECEIPT"], b"")))
ok("empty input is a verification failure value", k == "ok" and v["verified"] is False and v["reason"] == "INVALID_RECEIPT_FORMAT", json.dumps(v))
k, v = attempt(lambda i: [raw(i, "aprv_alloc", 0x7FFFFFFF), raw(i, "aprv_alloc", 0x7FFFFFF0), dec(i.invoke(OP["VERIFY_RECEIPT"], G5))["verified"]])
ok("absurd aprv_alloc lengths return 0, and the instance keeps working", k == "ok" and v == [0, 0, True], json.dumps(v))
for name, f in [
    ("aprv_result_ptr(0)", lambda i: raw(i, "aprv_result_ptr", 0)),
    ("aprv_result_len(12345)", lambda i: raw(i, "aprv_result_len", 12345)),
    ("aprv_result_free(0)", lambda i: raw(i, "aprv_result_free", 0)),
    ("aprv_result_free(never issued)", lambda i: raw(i, "aprv_result_free", 7)),
]:
    traps_then_recovers(f"invalid handle: {name} fails hard", f)


def double_free(i):
    h = with_handle(i)
    raw(i, "aprv_result_free", h)
    raw(i, "aprv_result_free", h)


def uaf(export):
    def f(i):
        h = with_handle(i)
        raw(i, "aprv_result_free", h)
        raw(i, export, h)
    return f


traps_then_recovers("double free fails hard", double_free)
traps_then_recovers("use after free (result_ptr) fails hard", uaf("aprv_result_ptr"))
traps_then_recovers("use after free (result_len) fails hard", uaf("aprv_result_len"))


def reuse(i):
    hs = [with_handle(i), with_handle(i), with_handle(i)]
    raw(i, "aprv_result_free", hs[1])
    return hs, with_handle(i)


k, v = attempt(reuse)
ok("freed handles are reused and live ones stay valid", k == "ok" and v[1] == v[0][1], json.dumps(v))
k, v = attempt(lambda i: dec(i.invoke(OP["VERIFY_RECEIPT"], b"not a receipt")))
ok("garbage receipt -> verified=false value", k == "ok" and v["verified"] is False, json.dumps(v))
k, v = attempt(lambda i: dec(i.invoke(OP["VERIFY_SIGNED_DATA"], b"\xff\xfe.")))
ok("non-UTF-8 JWS -> verified=false INVALID_JWS_FORMAT", k == "ok" and v["verified"] is False and v["reason"] == "INVALID_JWS_FORMAT", json.dumps(v))
k, v = attempt(lambda i: dec(i.invoke(OP["ENDPOINT_SANDBOX"], b'{"receipt-data": ')))
ok("malformed endpoint request JSON -> Apple status 21002 value", k == "ok" and v.get("status") == 21002, json.dumps(v))
try:
    json.loads(b'{"verified":tru')
    msg = ""
except ValueError as e:
    msg = f"{type(e).__name__}: {e}"
ok("malformed result JSON is a host decode error (internal failure), not a verdict", msg.startswith("JSONDecodeError"), msg)


def ownership(i):
    a = i.invoke(OP["VERIFY_RECEIPT"], G5)
    snap = bytes(a)
    for n in range(5):
        i.invoke(OP["VERIFY_RECEIPT"], b"x" * (n + 1))
    return type(a).__name__, snap == a


k, v = attempt(ownership)
ok("a result is a host-owned copy (unchanged after later calls reuse guest memory)", k == "ok" and v == ("bytes", True), str(v))


def growth(i):
    for _ in range(200):
        i.invoke(OP["VERIFY_RECEIPT"], G5)
    m1 = i.memory.data_len(i.store)
    for _ in range(2000):
        i.invoke(OP["VERIFY_RECEIPT"], G5)
    return [m1, i.memory.data_len(i.store)]


k, v = attempt(growth)
ok("no growth of linear memory over 2,000 more calls", k == "ok" and v[0] == v[1], json.dumps(v))

# The facade's own contract on top of the raw ABI.
fv = Verifier()
try:
    fv.call(OP["VERIFY_RECEIPT"], G5, abi_version=2)
    kind = "none"
except aprv_wasm.AbiMismatchError as e:
    kind = str(e)
ok("facade: a version mismatch raises AbiMismatchError", "module=1, caller=2" in kind, kind)
try:
    fv.call(99, b"")
    kind = "none"
except aprv_wasm.WasmTrapError as e:
    kind = f"WasmTrapError: {str(e).splitlines()[0]}"
ok("facade: an unknown operation raises WasmTrapError (internal failure)", kind.startswith("WasmTrapError"), kind)
ok("facade: after a trap the next call runs on a fresh instance and verifies", fv.verify_receipt(G5.decode())["verified"] is True and fv.traps == 1, f"traps {fv.traps}")
r = fv.verify_receipt("not base64!")
ok("facade: a verification failure is a value", r == {"message": "receipt-data is not valid base64", "reason": "INVALID_RECEIPT_FORMAT", "verified": False}, json.dumps(r))
print(f"summary: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
