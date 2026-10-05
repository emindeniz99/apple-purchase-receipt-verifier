// Appended to rust/tests/receipt_signer_algorithms.rs to see which OpenSSL
// error each signed-attribute test meets: OpenSSL's own CMS_verify, signer
// certificate not path-checked. Not part of the suite.
#[test]
fn openssl_attribute_diagnostic() {
    use openssl::cms::{CMSOptions, CmsContentInfo};
    use openssl::stack::Stack;
    use openssl::x509::X509;
    let pki = pki();
    let cases: Vec<(&str, Vec<Vec<u8>>)> = vec![
        ("control", vec![content_type(&[ID_DATA]), message_digest(1)]),
        (
            "ct twice",
            vec![
                content_type(&[ID_DATA]),
                content_type(&[ID_DATA]),
                message_digest(1),
            ],
        ),
        (
            "ct two values",
            vec![content_type(&[ID_DATA, ID_SIGNED_DATA]), message_digest(1)],
        ),
        (
            "md two values",
            vec![content_type(&[ID_DATA]), message_digest(2)],
        ),
        ("empty", vec![]),
    ];
    for (label, attrs) in cases {
        let der = receipt_with_signed_attrs(&pki, &attrs);
        let mut cms = CmsContentInfo::from_der(&der).unwrap();
        let mut certs = Stack::new().unwrap();
        for c in &pki.certificates {
            certs.push(X509::from_der(c).unwrap()).unwrap();
        }
        let r = cms.verify(
            Some(&certs),
            None,
            None,
            None,
            CMSOptions::NO_SIGNER_CERT_VERIFY,
        );
        eprintln!(
            "DIAG {label}: {:?}",
            r.map_err(|e| e
                .errors()
                .iter()
                .map(|x| x.reason().unwrap_or("?").to_owned())
                .collect::<Vec<_>>())
        );
    }
}
