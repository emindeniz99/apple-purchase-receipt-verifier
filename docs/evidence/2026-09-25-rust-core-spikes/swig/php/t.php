<?php
$b = preg_replace('/\s/', '', file_get_contents("../../../../../fixtures/public-receipts/receipt-sandbox-g5.b64"));
echo "php " . PHP_VERSION . ": " . substr(verify_receipt_base64(aprv_verifier_new_receipt("dev.bonzer.weeka.app"), $b), 0, 40) . "\n";
try { verify_receipt_base64(aprv_verifier_new_receipt("x.y"), $b); } catch (Throwable $e) { echo "php error ok: " . get_class($e) . " " . $e->getMessage() . "\n"; }
