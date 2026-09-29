#!/usr/bin/env python3
"""Task 2 criterion "bounded memory", end to end: the payloads of
py/memory.py wrapped in a CMS SignedData that OpenSSL parses (sha256
SignerInfo, no certificates, a one-byte signature), so the verifier runs
its pre-trust creation-date read over the whole attribute SET and then
fails ("signer certificate not embedded"). Measured through the C ABI
(native .so, via run_rust.py) and through Route C on Node (run.mjs --host
trap), one fresh process per measurement, peak RSS from ru_maxrss.

    python3 memory_cms.py <out dir> <payload dir from memory.py> <run_rust.py> <repo> <run.mjs> \\
        so:<label>=<dir with .so>... wasm:<label>=<module.wasm>...

A receipt at the 3,145,728-byte cap holds a payload a little under it.
"""
import base64
import json
import os
import resource
import subprocess
import sys

CAP = 3_145_728


def length(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag, body):
    return bytes([tag]) + length(len(body)) + body


OID_SIGNED = bytes.fromhex("06092a864886f70d010702")
OID_DATA = bytes.fromhex("06092a864886f70d010701")
SHA256 = tlv(0x30, bytes.fromhex("0609608648016503040201") + b"\x05\x00")
RSA = tlv(0x30, bytes.fromhex("06092a864886f70d010101") + b"\x05\x00")


def cms(payload):
    signer = tlv(0x30, tlv(0x02, b"\x01") + tlv(0x30, tlv(0x30, b"") + tlv(0x02, b"\x01")) + SHA256 + RSA + tlv(0x04, b"\x00"))
    signed = tlv(0x30, tlv(0x02, b"\x01") + tlv(0x31, SHA256) + tlv(0x30, OID_DATA + tlv(0xA0, tlv(0x04, payload))) + tlv(0x31, signer))
    return tlv(0x30, OID_SIGNED + tlv(0xA0, signed))


def child_rss(cmd):
    pid = os.fork()
    if pid == 0:
        r = subprocess.run(cmd, capture_output=True, text=True)
        rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        line = (r.stdout.strip().splitlines() or ["?"])[-1]
        with open(os.environ["APRV_MEM_OUT"], "w") as f:
            json.dump({"rss": rss, "row": line[:160]}, f)
        os._exit(0)
    os.waitpid(pid, 0)
    return json.load(open(os.environ["APRV_MEM_OUT"]))


def main():
    out, payload_dir, run_rust, repo, run_mjs = sys.argv[1:6]
    targets = sys.argv[6:]
    os.makedirs(out, exist_ok=True)
    os.environ["APRV_MEM_OUT"] = os.path.join(out, "last.json")
    print("# receipt (payload) | receipt bytes | runner | peak RSS KiB | row")
    for name in ("tiny", "flat-node-cap", "flat-max", "in-app-max"):
        payload = open(os.path.join(payload_dir, name), "rb").read()
        # Trim flat payloads so the whole receipt fits the cap.
        der = cms(payload)
        if len(der) > CAP:
            # Rebuild with fewer attributes: flat payloads are SET { 12-byte attrs }.
            body_len = len(payload) - (len(der) - CAP) - 16
            count = body_len // 12
            attr = bytes.fromhex("300a0202270f020101040100")
            while True:
                if name == "flat-max":
                    payload = tlv(0x31, attr * count)
                else:
                    payload = tlv(0x31, tlv(0x30, tlv(0x02, b"\x11") + tlv(0x02, b"\x01") + tlv(0x04, tlv(0x31, attr * count))))
                der = cms(payload)
                if len(der) <= CAP:
                    break
                count -= 1
        assert len(der) <= CAP, (name, len(der))
        row = {"id": f"memory/{name}", "kind": "receipt", "options": json.dumps({"bundleId": "com.example.app", "roots": None}),
               "input": base64.b64encode(der).decode()}
        req = os.path.join(out, f"{name}.jsonl")
        with open(req, "w") as f:
            f.write(json.dumps(row) + "\n")
        for target in targets:
            kind, rest = target.split(":", 1)
            label, path = rest.split("=", 1)
            if kind == "so":
                cmd = [sys.executable, run_rust, repo, path, req]
            else:
                cmd = ["node", run_mjs, "--host", "trap", path, req]
            m = child_rss(cmd)
            print(f"{name} | {len(der)} | {label} | {m['rss']} | {m['row']}", flush=True)


if __name__ == "__main__":
    main()
