#!/bin/sh
# Spike only (2026-09-29, round 13). Counts the host code each host needs
# for the four calls and the one import: the non-blank, non-comment lines
# between a host's "(hand-written) begin" and "end" markers, leaving out
# lines marked "test hook". Runtime set-up outside the markers (engine,
# compile, instantiate) is what any ABI needs and is not counted, except
# where the markers enclose it (noted per row). Generated code is counted
# separately, from the files the generators wrote into $S.
#   count.sh > results/count.txt
set -u
. "$(dirname "$0")/env.sh"
code() { grep -v 'test hook' | grep -v '^[[:space:]]*$' | grep -v '^[[:space:]]*\(//\|#\|\*\|/\*\)' | wc -l | tr -d ' '; }
region() { awk '/\(hand-written\) begin/{on=1; next} /\(hand-written\) end/{on=0} on' "$FE/$1" | code; }
# lines from the first match of $2 to the next line that is exactly $3 (one function)
fn() { awk -v a="$2" -v b="$3" 'index($0, a){on=1} on{print} on && $0==b{exit}' "$FE/$1" | code; }
row() { printf '%-44s %4s lines  %s\n' "$1" "$2" "$3"; }
echo "# host lines, $(date -u +%F) (non-blank, non-comment)"
echo "## hand-rolled canonical ABI (core module, no component support): the whole marked region"
row "wazero (Go)" "$(region hosts/wazero/main.go)" "Guest type, random-get import, signature table, lower, Call"
row "Endive (Java)" "$(region hosts/endive/src/main/java/spike/aprv/cabi/AprvCabi.java)" "fields, random-get import, instance builder (5 lines), signature table, lower, call"
row "WasmKit (Swift)" "$(region hosts/wasmkit/Sources/aprv-cabi/Cabi.swift)" "error type, random-get import, instantiate, bounds-checked read/write (WasmKit aborts on OOB), signature table, lower, call"
echo "## of which the generic lowering helper and the call"
row "wazero (Go): sigs + lower + Call" "$(( 1 + $(fn hosts/wazero/main.go 'func (g *Guest) lower(' '}') + $(fn hosts/wazero/main.go 'func (g *Guest) Call(' '}') ))" ""
row "Endive (Java): SIGS + lower + call" "$(( $(fn hosts/endive/src/main/java/spike/aprv/cabi/AprvCabi.java 'private static final java.util.Map<String, String> SIGS' '            "init", "b", "verify-receipt", "db", "verify-signed-data", "db", "verify-receipt-endpoint", "wdb");') + $(fn hosts/endive/src/main/java/spike/aprv/cabi/AprvCabi.java '    long[] lower(' '    }') + $(fn hosts/endive/src/main/java/spike/aprv/cabi/AprvCabi.java '    public String call(' '    }') ))" ""
row "WasmKit (Swift): sigs + lower + call" "$(( $(fn hosts/wasmkit/Sources/aprv-cabi/Cabi.swift '    static let sigs' '                                              "verify-signed-data": ["d", "b"], "verify-receipt-endpoint": ["w", "d", "b"]]') + $(fn hosts/wasmkit/Sources/aprv-cabi/Cabi.swift '    func lower(' '    }') + $(fn hosts/wasmkit/Sources/aprv-cabi/Cabi.swift '    func call(' '    }') ))" ""
echo "## typed hosts (component): the whole marked region"
row "jco (Node, Deno, Bun), generated glue" "$(region hosts/jco/run-calls.mjs)" "glue import, core-module loader, random-get"
row "wasmtime-py, run-time typed" "$(region hosts/wasmtime-py/run_calls.py)" "instantiate, export lookup, call, random-get"
row "Rust Wasmtime 49, bindgen!" "$(region hosts/wasmtime-rs/src/main.rs)" "bindgen! call, random-get (Host trait), linker, Guest (store + instantiate)"
echo "## generated code"
[ -f "$S/jco/out/aprv.js" ] && row "jco 1.35.0: aprv.js" "$(wc -l < "$S/jco/out/aprv.js" | tr -d ' ')" "all lines; $(wc -c < "$S/jco/out/aprv.js" | tr -d ' ') bytes (plus aprv.d.ts and two small core shim modules)"
[ -f "$S/wt/aprv-bindgen.rs" ] && row "Wasmtime bindgen! (rustfmt-ed)" "$(code < "$S/wt/aprv-bindgen.rs")" "$(wc -l < "$S/wt/aprv-bindgen.rs" | tr -d ' ') lines in all; $(wc -c < "$S/wt/aprv-bindgen.rs" | tr -d ' ') bytes"
row "wasmtime-py" "0" "no generator: types come from the component at run time"
