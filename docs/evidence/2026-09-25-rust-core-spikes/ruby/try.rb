require_relative "aprv_uniffi"
b64 = File.read("../../../../fixtures/public-receipts/receipt-sandbox-g5.b64").gsub(/\s/, "")
v = AprvUniffi::ReceiptVerifier.new("dev.bonzer.weeka.app", nil)
r = v.verify_base64(b64)
puts "ruby #{RUBY_VERSION}: receipt ok #{r.bundle_id} IAPs=#{r.in_app_purchases.length}"
begin
  AprvUniffi::ReceiptVerifier.new("com.other.app", nil).verify_base64(b64)
rescue => e
  puts "error ok: #{e.class}: #{e.message[0,70]}"
end
e = AprvUniffi::VerifyReceiptEndpoint.new(AprvUniffi::Environment::PRODUCTION, nil)
res = e.verify_receipt_result("{\"receipt-data\":\"#{b64}\"}")
puts "endpoint #{res.status} toJsonIn: #{res.to_json_in(AprvUniffi::Environment::SANDBOX)[0,50]}..."
