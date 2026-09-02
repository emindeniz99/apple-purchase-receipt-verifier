# Changelog

## [0.3.0](https://github.com/emindeniz99/apple-purchase-receipt-verifier/compare/v0.2.2...v0.3.0) (2026-09-02)


### Features

* **endpoint:** accept and answer the raw verifyReceipt JSON body ([d6e2853](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/d6e2853555c78180ae58bd140d9e8497ca2fddc2))


### Bug Fixes

* **endpoint:** correct the wire-contract account and close two parity gaps ([88857f9](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/88857f91b2a13c5bfea687f2ee5cd7e6b1796475))

## [0.2.2](https://github.com/emindeniz99/apple-purchase-receipt-verifier/compare/v0.2.1...v0.2.2) (2026-09-01)


### Build & Dependencies

* **deps:** Bump github.com/apple/swift-asn1 from 1.6.0 to 1.7.1 ([b9c1ace](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/b9c1acefc74b2b2e9baf5f22d570d5bd5872de7d))
* **deps:** Bump github.com/apple/swift-asn1 from 1.6.0 to 1.7.1 ([8d65812](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/8d65812ea257f77d7d738aceb88d9b2754df6fd3))
* **deps:** Bump github.com/apple/swift-certificates ([23a2e52](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/23a2e526fdb0efbce01b742cfc81a06747a5639d))
* **deps:** Bump github.com/apple/swift-certificates from 1.18.0 to 1.19.4 ([37ff90c](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/37ff90c8cfb0c155b2a6b36074e96ae071680055))

## [0.2.1](https://github.com/emindeniz99/apple-purchase-receipt-verifier/compare/v0.2.0...v0.2.1) (2026-09-01)


### Bug Fixes

* **ci:** fail the root watch with a diagnosis when the PKI page changes shape ([3fc8674](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/3fc86741f238dd1c5b0a6626b66bf54b8e8e8dc1))
* **ci:** scope the new-root check to the PKI page's root section ([c56496e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/c56496e5eceeecbdcbc402ea33194d898afa4105))
* **receipt:** cap embedded certificates and bound attribute integers ([8b954df](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/8b954df5c80b530749d787f0d2e91de82e0874a0))
* **receipt:** contain a receipt date that overflows epoch millis ([d88d98d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/d88d98dec469cb20e5c4c84e35222691b6b5d156))
* **receipt:** keep hostile input behind the declared exception type ([b626782](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/b6267826a5a5963ca6c913d7cbc74d665b4fa022))
* **release:** build node before publishing so the tarball has code in it ([61bee39](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/61bee399e806957c7eef2427e3da818daee21467))
* **swift:** stop a single receipt byte from killing the process ([feb8acd](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/feb8acdb68b63b365cdff74e82e0e4f98f6dda52))
* **swift:** walk one signature-selected path instead of searching the bag ([4ba160a](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/4ba160a7af612c444f6ee1d4012004bb4c27c798))


### Build & Dependencies

* **deps:** Bump actions/setup-java from 5.7.0 to 6.0.0 ([33aab6d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/33aab6dc85be187087296d398d7803d3b4f22503))
* **deps:** Bump actions/setup-java from 5.7.0 to 6.0.0 ([d2766d7](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/d2766d79a64e673a67143a220812203f2156814d))
* **deps:** Bump com.fasterxml.jackson.core:jackson-databind from 2.22.1 to 2.22.2 in /java ([b0fc796](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/b0fc79662edab85e9339a77495857857ef3aeea1))
* **deps:** Bump com.fasterxml.jackson.core:jackson-databind in /java ([18ce6bc](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/18ce6bc9f58bdb2b2b2a0462844b1d3afd542d85))
* **swift:** require Swift 6.1, which the swift-crypto fix pulls in ([ea62fad](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/ea62fad5fadfd1c5c6b6f433f587271bea3b6c4a))

## [0.2.0](https://github.com/emindeniz99/apple-purchase-receipt-verifier/compare/v0.1.1...v0.2.0) (2026-08-15)


### Features

* **certs:** pin all three published Apple roots, adding Apple Root CA - G2 ([00e191b](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/00e191ba5623b0b91622778ffc330f06298685d0))


### Bug Fixes

* **ci:** detect newly published Apple roots, not just pinned-cert changes ([715f473](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/715f47345d011eed10c941791d0c91bcb2f84acf))

## [0.1.1](https://github.com/emindeniz99/apple-purchase-receipt-verifier/compare/v0.1.0...v0.1.1) (2026-08-15)


### chore

* cut the 0.1.1 dependency and packaging release ([fae768f](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/fae768fef9811b189075c589894560a528095273))


### Build & Dependencies

* **deps-dev:** Bump org.apache.maven.plugins:maven-compiler-plugin ([8c14fe7](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/8c14fe7b821b96f16a94b1231400066135e69d28))
* **deps-dev:** Bump org.apache.maven.plugins:maven-compiler-plugin from 3.13.0 to 3.15.0 in /java ([a3f4547](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/a3f45478d1911ebc8070ab9a08bb705275639d99))
* **deps-dev:** Bump org.apache.maven.plugins:maven-gpg-plugin from 3.2.7 to 3.2.8 in /java ([126b9b2](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/126b9b25d8f8d3827d7ee641a8085c8fdc18888d))
* **deps-dev:** Bump org.apache.maven.plugins:maven-gpg-plugin in /java ([e0bc114](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/e0bc114f94cb7f51fd168d9fbc6a5f7a5b987af9))
* **deps-dev:** Bump org.apache.maven.plugins:maven-javadoc-plugin ([b261790](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/b261790182dec1eb2fe55e20179467f8e077ed78))
* **deps-dev:** Bump org.apache.maven.plugins:maven-javadoc-plugin from 3.11.2 to 3.12.0 in /java ([bdb2077](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/bdb207741dacf267f66192939fef015754e0f0d2))
* **deps-dev:** Bump org.apache.maven.plugins:maven-source-plugin ([549e41f](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/549e41f6b5b581279d927ae6f9caa84358f2acfa))
* **deps-dev:** Bump org.apache.maven.plugins:maven-source-plugin from 3.3.1 to 3.4.0 in /java ([6f91f9d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/6f91f9d452c0963a787f04581a19ef89c131b728))
* **deps-dev:** Bump org.junit.jupiter:junit-jupiter from 5.11.4 to 5.14.4 in /java ([20dfff7](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/20dfff79616d67c02fba830e780cbbbf7e9425ee))
* **deps-dev:** Bump org.junit.jupiter:junit-jupiter in /java ([2fdbe8e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/2fdbe8e68259796996c7f48ebe01bcdec37c6d18))
* **deps:** Bump com.fasterxml.jackson.core:jackson-databind from 2.18.2 to 2.22.1 in /java ([9967efd](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/9967efd1de04f6ca106660635e574c5f379d6445))
* **deps:** Bump com.fasterxml.jackson.core:jackson-databind in /java ([cdb723c](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/cdb723c06bb6c6210dcd7dc367964fb5a2d45256))
* **deps:** Bump org.apache.maven.plugins:maven-surefire-plugin ([ade8f4e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/ade8f4e1236c7a77340f7a55c7768f1e50805996))
* **deps:** Bump org.apache.maven.plugins:maven-surefire-plugin from 3.5.2 to 3.5.6 in /java ([9c9460d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/9c9460d25a013a2494bd37a8d6b127a7285a6ea6))
* **deps:** Bump org.bouncycastle:bcpkix-jdk18on from 1.80 to 1.85 in /java ([4518370](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/4518370dd6e4d0a383578ca8aeefc0b194cc5ebf))
* **deps:** Bump org.bouncycastle:bcpkix-jdk18on in /java ([e5c4b45](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/e5c4b453bfde1713712eab67d7c6a754771d69b2))
* **node:** type against the Node 20 engines floor, not latest Node ([7aa178e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7aa178e87d67bc154bcb624815451ad18a34e9be))
