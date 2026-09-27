# The whole C ABI on one page, from Elixir: a StoreKit 2 transaction
# verified against the fixture root that signed it, and the genuine sandbox
# receipt verified against the three bundled Apple roots.
#
#   mix run example.exs
#
# The same two verifications rust/ffi/examples/cpp/example.cpp does, against
# the same three files, so the two outputs can be compared line for line.

repository = Path.expand("../../../..", __DIR__)

root = File.read!(Path.join(repository, "fixtures/generated/jws-root.der"))
jws = File.read!(Path.join(repository, "fixtures/generated/transaction.jws"))
receipt = File.read!(Path.join(repository, "fixtures/generated/receipt-b64/01-genuine.txt"))

IO.puts("apple-purchase-receipt-verifier #{AppleReceiptExample.version()}\n")

show = fn what, outcome ->
  case outcome do
    {:ok, payload} ->
      IO.puts("#{what}: status 0")
      IO.puts(inspect(payload, limit: :infinity, pretty: true) <> "\n")
      0

    {:error, reason, body} ->
      IO.puts("#{what}: #{inspect(reason)}")
      IO.puts(inspect(body) <> "\n")
      1
  end
end

{:ok, fixture_verifier} = AppleReceiptExample.verifier(roots: [root])
failures = show.("transaction", AppleReceiptExample.verify_signed_data(fixture_verifier, jws))

{:ok, apple_verifier} = AppleReceiptExample.verifier()
failures = failures + show.("receipt", AppleReceiptExample.verify_receipt(apple_verifier, receipt))

# Nothing is released by hand: both verifiers are references, and the garbage
# collector runs the destructor that calls aprv_verifier_free.
if failures != 0, do: System.halt(1)
