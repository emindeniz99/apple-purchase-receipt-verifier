package main

import (
	"fmt"
	"os"
	"strings"

	"spike/aprv"
)

func main() {
	raw, _ := os.ReadFile("../../../../../fixtures/public-receipts/receipt-sandbox-g5.b64")
	b := strings.Join(strings.Fields(string(raw)), "")
	fmt.Println("go:", aprv.Verify_receipt_base64(aprv.Aprv_verifier_new_receipt("dev.bonzer.weeka.app"), b)[:40])
	defer func() { fmt.Println("go error ok:", recover()) }()
	aprv.Verify_receipt_base64(aprv.Aprv_verifier_new_receipt("x.y"), b)
}
