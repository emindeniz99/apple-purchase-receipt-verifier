use lib "."; use aprv;
open(my $f, "<", "../../../../../fixtures/public-receipts/receipt-sandbox-g5.b64"); local $/; my $b = <$f>; $b =~ s/\s//g;
print "perl: ", substr(aprv::verify_receipt_base64(aprv::aprv_verifier_new_receipt("dev.bonzer.weeka.app"), $b), 0, 40), "\n";
eval { aprv::verify_receipt_base64(aprv::aprv_verifier_new_receipt("x.y"), $b) }; print "perl error ok: $@" if $@;
