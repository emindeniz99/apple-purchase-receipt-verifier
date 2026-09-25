require_relative "aprv"
b = File.read("../../../../../fixtures/public-receipts/receipt-sandbox-g5.b64").gsub(/\s/, "")
puts "ruby: " + Aprv.verify_receipt_base64(Aprv.aprv_verifier_new_receipt("dev.bonzer.weeka.app"), b)[0,40]
begin; Aprv.verify_receipt_base64(Aprv.aprv_verifier_new_receipt("x.y"), b); rescue ArgumentError => e; puts "ruby error ok: #{e.message}"; end
