#!/bin/sh
# Posts every variant in $1 to $2 (an Apple verifyReceipt URL) and prints
# the file name and Apple's status code only. Nothing else of the answer is
# kept: even a sandbox answer carries the receipt's purchase records.
set -eu
dir=$1
url=$2
for f in "$dir"/*.b64; do
  status=$(node -e 'const fs=require("fs");process.stdout.write(JSON.stringify({"receipt-data":fs.readFileSync(process.argv[1],"ascii").trim()}))' "$f" \
    | curl -sS -m 60 -X POST "$url" -H 'Content-Type: application/json' --data-binary @- \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(String(JSON.parse(s).status)))')
  printf '%s\t%s\n' "$(basename "$f" .b64)" "$status"
done
