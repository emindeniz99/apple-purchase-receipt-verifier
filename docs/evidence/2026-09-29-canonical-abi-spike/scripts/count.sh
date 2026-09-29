#!/bin/sh
# Spike only (2026-09-29, round 12). Counts the host code each host needs
# for the four string->string calls and the one import: the non-blank,
# non-comment lines between a host's "(hand-written) begin" and "end"
# markers, leaving out lines marked "test hook". Runtime set-up outside the
# markers (engine, compile, instantiate) is what any ABI needs and is not
# counted, except where the markers enclose it (noted per row).
#   count.sh > results/count.txt
FE="$(cd "$(dirname "$0")/.." && pwd)"
code() { grep -v 'test hook' | grep -v '^[[:space:]]*$' | grep -v '^[[:space:]]*\(//\|#\|\*\|/\*\)' | wc -l | tr -d ' '; }
region() { awk '/\(hand-written\) begin/{on=1; next} /\(hand-written\) end/{on=0} on' "$FE/$1" | code; }
# lines from the first match of $2 to the next line that is exactly $3 (the function body)
fn() { awk -v a="$2" -v b="$3" 'index($0, a){on=1} on{print} on && $0==b{exit}' "$FE/$1" | code; }
row() { printf '%-40s %3s lines  %s\n' "$1" "$2" "$3"; }
echo "# hand-written host lines, $(date -u +%F) (non-blank, non-comment)"
echo "## the whole marked region"
row "wazero (Go), canonical ABI by hand" "$(region hosts/wazero/main.go)" "Guest type, random-get import, Call"
row "Endive (Java), canonical ABI by hand" "$(region hosts/endive/src/main/java/spike/aprv/cabi/AprvCabi.java)" "fields, random-get import, instance builder (5 lines), call"
row "jco (Node), generated bindings" "$(region hosts/jco/run-calls.mjs)" "glue import, core-module loader, random-get"
row "wasmtime-py, wasmtime.component" "$(region hosts/wasmtime-py/run_calls.py)" "instantiate, export lookup, call, random-get"
echo "## the string->string call alone (argument in, result out, post-return)"
row "wazero (Go): Guest.Call" "$(fn hosts/wazero/main.go 'func (g *Guest) Call(' '}')" "with error returns"
row "Endive (Java): call" "$(fn hosts/endive/src/main/java/spike/aprv/cabi/AprvCabi.java 'public String call(' '    }')" "traps surface as exceptions"
row "jco (Node)" "0" "a generated function: verify.verifyReceipt(nowMs, text)"
row "wasmtime-py: Aprv.call" "$(fn hosts/wasmtime-py/run_calls.py '    def call(self' '        return self.f[fn](self.store, *args)')" "a runtime-typed call; the runtime runs post-return"
