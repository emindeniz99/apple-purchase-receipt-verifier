# frozen_string_literal: true

# The gem's machinery is made of private constants of its module, so
# `ApplePurchaseReceiptVerifier::Runtime` is a NameError outside the gem. The
# white-box tests reach each one by name here.
module Internals
  Runtime = ApplePurchaseReceiptVerifier.const_get(:Runtime)
  Guest = ApplePurchaseReceiptVerifier.const_get(:Guest)
  InstancePool = ApplePurchaseReceiptVerifier.const_get(:InstancePool)
  Wire = ApplePurchaseReceiptVerifier.const_get(:Wire)
  RootsRejected = ApplePurchaseReceiptVerifier.const_get(:RootsRejected)
end
