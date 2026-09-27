#!/usr/bin/env python3
"""Spike only (2026-09-27, round 9). Drives a native host (../wasmi-host or
../wamr-host) over its line protocol, so one corpus runner and one ABI test
suite serve every engine, and the timing stays inside the native host.

    driver.py calls CALLS.jsonl -- HOST ARGV...     rows in the Node runner's format (stdout)
    driver.py tests CASES.jsonl -- HOST ARGV...     the 37 ABI and facade tests, then isolation checks

HOST ARGV is e.g. `aprv-wasmi2-auto serve aprv-abi1.wasm --mode lazy`, or
`inproc:aprv_wamr` for the Python ctypes facade in this process.

Protocol (little-endian): a one-byte command, its arguments; the reply is a
status byte (0 ok, 1 trap, 2 error), a u32 length and the payload.
  n                               new instance (instantiate, _initialize, version check) -> u32 id
  d id                            drop an instance
  r id u8 len name u8 n i32*n     call an export with i32 arguments -> u8 count, i32 results
  i id abi op u32 len bytes       the full ABI v1 call lifecycle -> result bytes (a host-owned copy)
  m id                            linear memory size in bytes -> u32
  c                               process-wide import call counts -> u64 clock, u64 random
  e                               engine label
  q                               quit

A request that gets no reply within TIMEOUT seconds kills the host's
process group and exits 3 with the name of the step that hung.
"""
import base64
import json
import os
import select
import signal
import struct
import subprocess
import sys

TIMEOUT = float(os.environ.get("APRV_STEP_TIMEOUT", "300"))
OP = {"VERIFY_RECEIPT": 1, "VERIFY_SIGNED_DATA": 2, "ENDPOINT_PRODUCTION": 3, "ENDPOINT_SANDBOX": 4}
CURRENT = {"step": "start-up"}


class Trap(Exception):
    """The instance trapped."""


class HostError(Exception):
    """The host reported an error that is not a trap (e.g. aprv_alloc returned 0)."""


class AbiMismatchError(RuntimeError):
    pass


class WasmTrapError(RuntimeError):
    pass


class Host:
    def __init__(self, argv):
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, start_new_session=True)
        self.fd = self.p.stdout.fileno()

    def _read(self, n):
        buf = b""
        while len(buf) < n:
            ready, _, _ = select.select([self.fd], [], [], TIMEOUT)
            if not ready:
                self.hang()
            chunk = os.read(self.fd, n - len(buf))
            if not chunk:
                raise HostError(f"host exited (status {self.p.poll()}) during: {CURRENT['step']}")
            buf += chunk
        return buf

    def hang(self):
        os.killpg(self.p.pid, signal.SIGKILL)
        print(f"HANG: no reply in {TIMEOUT:.0f} s during: {CURRENT['step']}; host process group killed", flush=True)
        sys.exit(3)

    def req(self, payload):
        self.p.stdin.write(payload)
        self.p.stdin.flush()
        status, n = struct.unpack("<BI", self._read(5))
        body = self._read(n) if n else b""
        if status == 1:
            raise Trap(body.decode("utf-8", "replace"))
        if status == 2:
            raise HostError(body.decode("utf-8", "replace"))
        return body

    def new(self):
        return struct.unpack("<I", self.req(b"n"))[0]

    def drop(self, i):
        self.req(b"d" + struct.pack("<I", i))

    def raw(self, i, name, *args):
        nb = name.encode()
        body = self.req(b"r" + struct.pack("<IB", i, len(nb)) + nb + struct.pack("<B", len(args)) + b"".join(struct.pack("<i", a) for a in args))
        vals = struct.unpack(f"<{body[0]}i", body[1:])
        return vals[0] if vals else None

    def invoke(self, i, abi, op, data):
        return self.req(b"i" + struct.pack("<IiiI", i, abi, op, len(data)) + data)

    def mem_len(self, i):
        return struct.unpack("<I", self.req(b"m" + struct.pack("<I", i)))[0]

    def import_calls(self):
        c, r = struct.unpack("<QQ", self.req(b"c"))
        return {"aprv.clock_now_ms": c, "aprv.random_get": r}

    def label(self):
        return self.req(b"e").decode()

    def close(self):
        try:
            self.p.stdin.write(b"q")
            self.p.stdin.close()
        except BrokenPipeError:
            pass
        self.p.wait(timeout=30)


class InProc:
    """The same operations as Host, in process, over py/aprv_wamr's ctypes
    facade (APRV_LIBIWASM, APRV_MODULE): `-- inproc:aprv_wamr`."""

    def __init__(self):
        import aprv_wamr
        self.m = aprv_wamr
        self.h = aprv_wamr.InProcHost()

    def _wrap(self, f, *a):
        try:
            return f(*a)
        except (self.m._Trap, self.m.AbiMismatchError) as e:
            raise Trap(str(e)) from None
        except MemoryError as e:
            raise HostError(str(e)) from None

    def new(self):
        return self.h.new()

    def drop(self, i):
        self.h.drop(i)

    def raw(self, i, name, *args):
        return self._wrap(self.h.raw, i, name, *args)

    def invoke(self, i, abi, op, data):
        return self._wrap(self.h.invoke, i, abi, op, data)

    def mem_len(self, i):
        return self.h.mem_len(i)

    def import_calls(self):
        return self.h.import_calls()

    def label(self):
        return self.h.label()

    def close(self):
        self.h.close()


class Instance:
    """The shape of round 7's facade _Instance, over the protocol."""

    def __init__(self, host):
        self.host = host
        self.id = host.new()
        self.module_version = host.raw(self.id, "aprv_abi_version")

    def invoke(self, operation, data, abi_version=1):
        try:
            return self.host.invoke(self.id, abi_version, operation, bytes(data))
        except Trap:
            if abi_version != self.module_version:
                raise AbiMismatchError(f"APRV Wasm ABI mismatch: module={self.module_version}, caller={abi_version}") from None
            raise

    def raw(self, name, *args):
        return self.host.raw(self.id, name, *args)

    def mem_len(self):
        return self.host.mem_len(self.id)

    def drop(self):
        self.host.drop(self.id)


class Verifier:
    """Round 7's facade contract: a trap discards the instance; the next call starts fresh."""

    def __init__(self, host):
        self.host = host
        self._inst = Instance(host)
        self.traps = 0

    def call(self, operation, data, abi_version=1):
        if self._inst is None:
            self._inst = Instance(self.host)
        try:
            return self._inst.invoke(operation, bytes(data), abi_version)
        except (Trap, HostError) as e:
            self._inst.drop()
            self._inst = None
            self.traps += 1
            raise WasmTrapError(str(e)) from None
        except AbiMismatchError:
            self._inst.drop()
            self._inst = None
            raise

    def verify_receipt(self, receipt_data):
        data = receipt_data.encode() if isinstance(receipt_data, str) else bytes(receipt_data)
        return json.loads(self.call(OP["VERIFY_RECEIPT"], data))


def dump(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def run_calls(path, host):
    v = Verifier(host)
    rows = traps = 0
    out = sys.stdout
    for line in open(path, encoding="utf-8"):
        if not line.strip():
            continue
        c = json.loads(line)
        rows += 1
        CURRENT["step"] = f"row {c['id']}"
        if "op" not in c:
            out.write(dump({"id": c["id"], "map": c["map"]}) + "\n")
            continue
        try:
            res = v.call(c["op"], base64.b64decode(c["input"]))
            out.write(dump({"id": c["id"], "out": res.decode("utf-8")}) + "\n")
        except (WasmTrapError, AbiMismatchError) as e:
            traps += 1
            out.write(dump({"id": c["id"], "trap": str(e)}) + "\n")
    print(json.dumps({"host": host.label(), "rows": rows, "traps": traps}), file=sys.stderr)


def run_tests(path, host):
    """Round 7's py/abi_tests.py, test for test, over the protocol. One
    deviation: neither Wasmi nor WAMR exposes a trap backtrace through the
    API used here, so the "the trap is in aprv_call itself" half of the
    version-mismatch test is checked as: the trap surfaces from the raw
    aprv_call invocation and no host import ran."""
    calls = {c["id"]: c for c in (json.loads(l) for l in open(path, encoding="utf-8") if l.strip())}
    G5 = base64.b64decode(calls["receipt/verify-genuine-sandbox-g5-against-apple-roots"]["input"])
    JWS_CALL = calls["transaction/verify-shared-sandbox"]
    JWS = base64.b64decode(JWS_CALL["input"])
    res = {"passed": 0, "failed": 0}
    dec = json.loads

    def ok(name, cond, detail=""):
        res["passed" if cond else "failed"] += 1
        print(f"{'PASS' if cond else 'FAIL'} {name}{': ' + detail if detail else ''}", flush=True)

    def attempt(f):
        i = Instance(host)
        try:
            return "ok", f(i)
        except Trap as e:
            return "trap", f"Trap: {str(e).splitlines()[0]}"
        except AbiMismatchError as e:
            return "error", str(e)
        except Exception as e:  # noqa: BLE001
            return "error", f"{type(e).__name__}: {e}"
        finally:
            i.drop()

    def g5_verifies():
        i = Instance(host)
        try:
            return dec(i.invoke(OP["VERIFY_RECEIPT"], G5))["verified"] is True
        finally:
            i.drop()

    def traps_then_recovers(name, f):
        CURRENT["step"] = f"test: {name}"
        kind, msg = attempt(f)
        after = g5_verifies()
        ok(name, kind == "trap" and after, f"{kind} ({msg}); fresh instance verifies g5: {after}")

    def with_handle(i):
        p = i.raw("aprv_alloc", 4)
        return i.raw("aprv_call", 1, OP["VERIFY_RECEIPT"], p, 4)

    def step(name):
        CURRENT["step"] = f"test: {name}"
        return name

    i0 = Instance(host)
    ok(step("aprv_abi_version() == 1"), i0.raw("aprv_abi_version") == 1)
    i0.drop()
    k, v = attempt(lambda i: dec(i.invoke(OP["VERIFY_RECEIPT"], G5)))
    ok(step("aprv_call(1, VERIFY_RECEIPT, genuine g5) verifies"), k == "ok" and v["verified"] is True and v["payload"]["bundleId"] == "dev.bonzer.weeka.app",
       f"bundleId {v['payload']['bundleId'] if k == 'ok' else v}")
    k, v = attempt(lambda i: dec(i.invoke(JWS_CALL["op"], JWS)))
    ok(step("aprv_call(1, VERIFY_SIGNED_DATA (test anchors), shared-sandbox JWS) verifies; payloadJson is the exact signed JSON and parses to payload"),
       k == "ok" and v["verified"] is True and json.loads(v["payloadJson"]) == v["payload"], f"payloadJson {len(v['payloadJson']) if k == 'ok' else v} chars")
    traps_then_recovers("aprv_call(0, garbage op, invalid ptr, absurd len) fails hard", lambda i: i.raw("aprv_call", 0, 0x7FFFFFFF, -16, 0x7FFFFFFF))
    traps_then_recovers("aprv_call(2, garbage op, invalid ptr, absurd len) fails hard", lambda i: i.raw("aprv_call", 2, 0x7FFFFFFF, -16, 0x7FFFFFFF))
    k, msg = attempt(lambda i: i.invoke(OP["VERIFY_RECEIPT"], G5, abi_version=2))
    ok(step("bridge reports a version mismatch as an ABI error, never verified=false"), k == "error" and "APRV Wasm ABI mismatch: module=1, caller=2" in msg, msg)

    def mismatch_runs_nothing(i):
        before = host.import_calls()
        where = None
        try:
            i.raw("aprv_call", 3, 1, 0, 0)
        except Trap as e:
            where = f"raw aprv_call trapped: {str(e).splitlines()[0]}"
        after = host.import_calls()
        return {k: after[k] - before[k] for k in before}, where

    k, v = attempt(mismatch_runs_nothing)
    ok(step("a version mismatch runs nothing (no host import called; the trap is in aprv_call itself)"),
       k == "ok" and set(v[0].values()) == {0} and v[1] is not None, f"import calls during the call: {v[0]}; {v[1]}; frames: not exposed by this host's API" if k == "ok" else str(v))
    for op in (0, 5, 99, 255, 256, 261, -1):
        traps_then_recovers(f"unknown operation {op} fails hard", lambda i, op=op: i.raw("aprv_call", 1, op, i.raw("aprv_alloc", 4), 4))
    traps_then_recovers("null input pointer with a length fails hard", lambda i: i.raw("aprv_call", 1, OP["VERIFY_RECEIPT"], 0, 10))
    traps_then_recovers("input beyond linear memory fails hard", lambda i: i.raw("aprv_call", 1, OP["VERIFY_RECEIPT"], i.mem_len() - 4, 16))
    traps_then_recovers("input range that overflows u32 fails hard", lambda i: i.raw("aprv_call", 1, OP["VERIFY_RECEIPT"], -16, 0x20))
    k, v = attempt(lambda i: dec(i.invoke(OP["VERIFY_RECEIPT"], b"")))
    ok(step("empty input is a verification failure value"), k == "ok" and v["verified"] is False and v["reason"] == "INVALID_RECEIPT_FORMAT", json.dumps(v))
    k, v = attempt(lambda i: [i.raw("aprv_alloc", 0x7FFFFFFF), i.raw("aprv_alloc", 0x7FFFFFF0), dec(i.invoke(OP["VERIFY_RECEIPT"], G5))["verified"]])
    ok(step("absurd aprv_alloc lengths return 0, and the instance keeps working"), k == "ok" and v == [0, 0, True], json.dumps(v))
    for name, f in [
        ("aprv_result_ptr(0)", lambda i: i.raw("aprv_result_ptr", 0)),
        ("aprv_result_len(12345)", lambda i: i.raw("aprv_result_len", 12345)),
        ("aprv_result_free(0)", lambda i: i.raw("aprv_result_free", 0)),
        ("aprv_result_free(never issued)", lambda i: i.raw("aprv_result_free", 7)),
    ]:
        traps_then_recovers(f"invalid handle: {name} fails hard", f)

    def double_free(i):
        h = with_handle(i)
        i.raw("aprv_result_free", h)
        i.raw("aprv_result_free", h)

    def uaf(export):
        def f(i):
            h = with_handle(i)
            i.raw("aprv_result_free", h)
            i.raw(export, h)
        return f

    traps_then_recovers("double free fails hard", double_free)
    traps_then_recovers("use after free (result_ptr) fails hard", uaf("aprv_result_ptr"))
    traps_then_recovers("use after free (result_len) fails hard", uaf("aprv_result_len"))

    def reuse(i):
        hs = [with_handle(i), with_handle(i), with_handle(i)]
        i.raw("aprv_result_free", hs[1])
        return hs, with_handle(i)

    k, v = attempt(reuse)
    ok(step("freed handles are reused and live ones stay valid"), k == "ok" and v[1] == v[0][1], json.dumps(v))
    k, v = attempt(lambda i: dec(i.invoke(OP["VERIFY_RECEIPT"], b"not a receipt")))
    ok(step("garbage receipt -> verified=false value"), k == "ok" and v["verified"] is False, json.dumps(v))
    k, v = attempt(lambda i: dec(i.invoke(OP["VERIFY_SIGNED_DATA"], b"\xff\xfe.")))
    ok(step("non-UTF-8 JWS -> verified=false INVALID_JWS_FORMAT"), k == "ok" and v["verified"] is False and v["reason"] == "INVALID_JWS_FORMAT", json.dumps(v))
    k, v = attempt(lambda i: dec(i.invoke(OP["ENDPOINT_SANDBOX"], b'{"receipt-data": ')))
    ok(step("malformed endpoint request JSON -> Apple status 21002 value"), k == "ok" and v.get("status") == 21002, json.dumps(v))
    try:
        json.loads(b'{"verified":tru')
        msg = ""
    except ValueError as e:
        msg = f"{type(e).__name__}: {e}"
    ok(step("malformed result JSON is a host decode error (internal failure), not a verdict"), msg.startswith("JSONDecodeError"), msg)

    def ownership(i):
        a = i.invoke(OP["VERIFY_RECEIPT"], G5)
        snap = bytes(a)
        for n in range(5):
            i.invoke(OP["VERIFY_RECEIPT"], b"x" * (n + 1))
        return type(a).__name__, snap == a

    k, v = attempt(ownership)
    ok(step("a result is a host-owned copy (unchanged after later calls reuse guest memory)"), k == "ok" and v == ("bytes", True), str(v))

    def growth(i):
        for _ in range(200):
            i.invoke(OP["VERIFY_RECEIPT"], G5)
        m1 = i.mem_len()
        for _ in range(2000):
            i.invoke(OP["VERIFY_RECEIPT"], G5)
        return [m1, i.mem_len()]

    CURRENT["step"] = "test: no growth of linear memory over 2,000 more calls"
    k, v = attempt(growth)
    ok("no growth of linear memory over 2,000 more calls", k == "ok" and v[0] == v[1], json.dumps(v))

    fv = Verifier(host)
    try:
        fv.call(OP["VERIFY_RECEIPT"], G5, abi_version=2)
        kind = "none"
    except AbiMismatchError as e:
        kind = str(e)
    ok(step("facade: a version mismatch raises AbiMismatchError"), "module=1, caller=2" in kind, kind)
    try:
        fv.call(99, b"")
        kind = "none"
    except WasmTrapError as e:
        kind = f"WasmTrapError: {str(e).splitlines()[0]}"
    ok(step("facade: an unknown operation raises WasmTrapError (internal failure)"), kind.startswith("WasmTrapError"), kind)
    ok(step("facade: after a trap the next call runs on a fresh instance and verifies"), fv.verify_receipt(G5.decode())["verified"] is True and fv.traps == 1, f"traps {fv.traps}")
    r = fv.verify_receipt("not base64!")
    ok(step("facade: a verification failure is a value"), r == {"message": "receipt-data is not valid base64", "reason": "INVALID_RECEIPT_FORMAT", "verified": False}, json.dumps(r))
    print(f"summary: {res['passed']} passed, {res['failed']} failed", flush=True)

    # Isolation (not part of the 37): instances share one engine and module.
    iso = {"passed": 0, "failed": 0}

    def iso_ok(name, cond, detail):
        iso["passed" if cond else "failed"] += 1
        print(f"{'PASS' if cond else 'FAIL'} isolation: {name}: {detail}", flush=True)

    CURRENT["step"] = "isolation: a trap in one instance"
    a, b = Instance(host), Instance(host)
    before = dec(b.invoke(OP["VERIFY_RECEIPT"], G5))["verified"]
    try:
        a.raw("aprv_call", 1, 99, a.raw("aprv_alloc", 4), 4)
        trapped = False
    except Trap:
        trapped = True
    after = dec(b.invoke(OP["VERIFY_RECEIPT"], G5))["verified"]
    iso_ok("a trap in one instance leaves another untouched", trapped and before and after, f"trapped {trapped}; other instance verifies before {before}, after {after}")
    a.drop()
    CURRENT["step"] = "isolation: out-of-range input"
    try:
        b.raw("aprv_call", 1, OP["VERIFY_RECEIPT"], b.mem_len() - 2, 8)
        kind = "no trap"
    except Trap as e:
        kind = "trap: " + str(e).splitlines()[0]
    c = Instance(host)
    fresh = dec(c.invoke(OP["VERIFY_RECEIPT"], G5))["verified"]
    iso_ok("the host process survives an instance trap on out-of-range input; a new instance verifies", kind.startswith("trap") and fresh, f"{kind}; new instance verifies {fresh}")
    b.drop()
    c.drop()
    print(f"isolation summary: {iso['passed']} passed, {iso['failed']} failed", flush=True)
    return res["failed"] + iso["failed"]


def main():
    sep = sys.argv.index("--")
    cmd, path, argv = sys.argv[1], sys.argv[2], sys.argv[sep + 1:]
    host = InProc() if argv == ["inproc:aprv_wamr"] else Host(argv)
    try:
        if cmd == "calls":
            sys.stdout.reconfigure(encoding="utf-8")
            run_calls(path, host)
            failed = 0
        elif cmd == "tests":
            failed = run_tests(path, host)
        else:
            raise SystemExit(f"unknown command {cmd}")
    finally:
        host.close()
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
