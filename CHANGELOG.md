# Changelog

## [0.4.0](https://github.com/emindeniz99/apple-purchase-receipt-verifier/compare/v0.3.0...v0.4.0) (2026-09-05)


### Features

* **dotnet:** add the C# port ([344a611](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/344a61172be2f30717c9b510692e1be075a11cf9))
* **fixtures:** make cases.json the normative cross-language contract ([afff3e0](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/afff3e005e89fa31ec86ee4f4986b75f395c9580))
* **go:** add the Go port ([4e9fa65](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/4e9fa6522cb455bd0c9b1e6ae073ebc81e2c489b))
* **java:** make the verifiers' notion of now injectable ([beaf62d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/beaf62d447ccb747b217ef0248ad349296284970))
* **node:** add a WebCrypto entry point for edge runtimes ([d49eef0](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/d49eef0a3dccd5d2431c82eab16a26952b3b04a4))
* **node:** make the verifiers' notion of now injectable ([af20123](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/af20123ac7053712c34e14133d19f2ead81dde8b))
* **php:** add the PHP port ([e0f3ac0](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/e0f3ac0bc9e84b6a8c380e49d063271fb80ed3ae))
* **python:** make the verifiers' notion of now injectable ([891e448](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/891e448bbbe91c36aef1047ee29fac947bd032b7))
* **ruby:** add the Ruby port ([3f49798](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/3f497980eee9d2d1ae55819e036d5b778accbe66))
* **rust:** add the Rust port ([9eae263](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/9eae2637853f9ab0a48ff67dcf2e3f991cd3d3de))
* **swift:** make the verifiers' notion of now injectable ([5f27e5c](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/5f27e5ce3c0cc5d2c7f93b6a6ea7385f7b1f3b1d))


### Bug Fixes

* **dotnet:** judge the receipt signer certificate before the platform CMS decoder ([4fac89b](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/4fac89ba3615812fe7203e67bc17529f13a6a5ce))
* **dotnet:** parse x5c[2], and read the receipt signer strictly ([65f228d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/65f228d459779f560ab4bfb6b44e5e08848f31b6))
* **dotnet:** read a whole extnValue, and let a readable non-RSA signer key be a signature verdict ([ba38caf](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/ba38caf3876bd9282300f7aa09f183e7304ed935))
* **dotnet:** refuse an x5c certificate carrying one extension twice ([a967de9](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/a967de9a5f02987610c9f89efb39ba23959d1032))
* **dotnet:** type the x5c entries and refuse a certificate it cannot read ([691e400](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/691e400578c943692051370672873b15d21ed57f))
* **go:** match the malformed entry's identity before blaming it ([ce05086](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/ce05086a8accdffce262660e46aca2bb5b7260b6))
* **go:** parse x5c[2], and name the signer before blaming the receipt ([7534f82](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7534f822dbea5337e5e6b67e772e521a667fbe5b))
* **go:** read a date claim's value, not the spelling of its literal ([be76865](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/be76865ea5056a9a7165f072d610d907c22c49c0))
* **go:** refuse a signing date that does not fit an int64 ([1350509](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/135050910990b6415cd176683fcfb82f481a331b))
* **go:** scope the system-trust premise to where a root can be planted ([a01168a](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/a01168afc209a57367b57d4c4384aeb18c11dc7e))
* **java:** reject an empty or non-object JWS segment instead of throwing NPE ([d930be4](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/d930be467fe4f1667ad8472ae1b75b0ef5c85c2e))
* **java:** report a defective receipt signer as a certificate defect ([30067ef](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/30067efae4450e603ffb9443355853cd004b1ca0))
* **java:** require the JWS header and payload to be JSON objects ([b59f02e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/b59f02e3c101a68c8a7eaa05d17404006c141c39))
* **java:** state the chain length bound and count self-issued intermediates ([ea06db7](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/ea06db7a2b4b3571b1cf6e65c0eaad23b4cb293e))
* **java:** type the x5c entries and refuse an unrepresentable signing date ([6d6d707](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/6d6d707ea4f22bea52814c2136b51e4c9bb4bde5))
* **node:** import certificate keys as JWK so the web build works on Fastly ([15c1193](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/15c1193a546c201a8e49a65bfce737ceaf029a25))
* **node:** inline the Apple roots so bundled runtimes can use them ([82c0cb6](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/82c0cb68579cc6db72b41d5dd2f464d53fbe9317))
* **node:** parse x5c[2], and read the receipt signer strictly ([c9ef2ec](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/c9ef2ec19111471db3e2df72981f0c69ed6f9dd5))
* **node:** pass the ES256 key to verify() as SPKI DER so workerd accepts it ([7246a4a](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7246a4a273dfca3ce055516ee07929076dee0e75))
* **node:** refuse an x5c certificate carrying one extension twice ([d436a87](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/d436a87ec2f3aee4b55b0c80d77b9739436f259b))
* **node:** reject an x5c certificate whose version or key it cannot read ([9b2cf72](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/9b2cf72450d6519a6a27e81af99eab5cc104dee8))
* **node:** scope the web build's key check to the keys it builds ([47fb817](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/47fb81781e2be179f010d9f04a4102d021ac6556))
* **php:** make the committed cs-fixer config actually runnable ([23c2747](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/23c27475b7bcccb45203708eaf392dc62d030d1f))
* **php:** parse x5c[2], and blame the signer rather than the receipt ([3109113](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/3109113cc88dc85f44d994933ecae51c37ece74a))
* **php:** refuse an unrepresentable signing date and an unusable x5c key ([88baee1](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/88baee106147e306faa84d05749d4ba833cb2e27))
* **php:** refuse an x5c certificate carrying one extension twice ([5d27341](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/5d27341828c358bbb523b94ba6588c81d1e9f0e6))
* **php:** tighten the types the static analysis found loose ([fa63277](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/fa6327744423606e0ca7c53881a8043e865d5611))
* **python:** answer INVALID_CERTIFICATE for an unusable x5c public key ([8ce9ea2](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/8ce9ea2fa13d7eeb66000954660a2ec9786a5a75))
* **python:** parse x5c[2], and read the receipt signer strictly ([bf24985](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/bf24985e6fdcaacfe2cb30eb68a25c3423c907c9))
* **python:** report a duplicate extension as a verdict, not a crash ([9cdf966](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/9cdf96624de6b60bb892ac71002d5681249a94c5))
* **python:** turn five JWS-path exception escapes into typed verdicts ([84cfefd](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/84cfefd581d93db354bdc1e24a826baf03a8d014))
* **release:** bump jvm-interop's library version with every other manifest ([7234614](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7234614273cb2bdf07b975a71711dc0001a88e66))
* **repo:** accept receipt base64 padding only when omitted or canonical ([d0d80b3](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/d0d80b39bd1b76a0408dd68f4ed31d27d3836de4))
* **repo:** check every copy of the Apple roots against certs/ ([774f8c5](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/774f8c58ff86675247c9825297224b27692ec3b8))
* **repo:** decode compact-JWS segments strictly in every port ([935f62d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/935f62d2b561ed7592095fdd7096b00c69da7fe4))
* **repo:** decode receipt base64 by Apple's rule, identically in every port ([1360a4e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/1360a4ed0d7b06b310a4bc6805cdd86da31110a8))
* **repo:** reconcile four places where the ports already disagreed ([141387b](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/141387b04f69bb9a7cffb80444eb395ef5c3abba))
* **repo:** stop git rewriting fixture bytes on a Windows checkout ([407d785](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/407d785a60334b044287a83a410116a54ce6a86e))
* **repo:** test the impossible base64 length on the data, not the padded string ([b8a6693](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/b8a66932136931c729f8b83349898f51d245a07e))
* **ruby:** parse x5c[2], and read the receipt signer strictly ([0d8d4d5](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/0d8d4d5950c33bb5fbe8682354f9c6225576ab67))
* **ruby:** refuse an x5c certificate carrying one extension twice ([bf080e3](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/bf080e35e6dd61a1a22e21263d9152c18be4a037))
* **ruby:** reject an x5c certificate whose version or key it cannot read ([34abadd](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/34abadd5b200ccf321aa36e2abbc0595813a8595))
* **ruby:** repair three defects the tools job exposed on its first run ([251d101](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/251d1011704568e316e3e216b9b8ef44d009fc80))
* **rust:** keep whitespace in fuzz seed paths ([3a0a520](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/3a0a5206dab1eb1c55f83c9c603d6f3393617d3f))
* **rust:** parse x5c[2], and blame the signer rather than the receipt ([134dc5d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/134dc5d37bb4f3a72b371e346c8d67cfcff41052))
* **rust:** refuse an unrepresentable signing date and an unusable x5c key ([dea396a](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/dea396aa6e979ed85ba6307a4ecd96e94c9462ac))
* **rust:** refuse an x5c certificate carrying one extension twice ([2dd1dd3](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/2dd1dd3a6c67352a7cc9a53c4bfc1f0fd1ba11a3))
* **swift:** apply the embedded-certificate bound before decoding ([7c6c20c](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7c6c20cb10f1a272f834c579b83f0ef5f8244284))
* **swift:** call an unrepresentable signing date a chain failure ([33bb146](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/33bb1462eb3d9991bec8f90289ee0c04af99a9b6))
* **swift:** fail the validation-time range guard closed on a NaN instant ([5666056](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/56660560b7ce452b0d92d563ed394f75f363851f))
* **swift:** parse x5c[2], and read the receipt signer strictly ([7f62031](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7f620313d6929a83935a263d4362db4f5d77843f))
* **swift:** require the JWS payload to be a JSON object ([adebba2](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/adebba233f64e9bda56060d30d5c26a1b840c37b))


### Performance

* **node:** run the two TypeScript passes at once ([9003c09](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/9003c093874b16db7d7cc6f383f0ae90aed15d86))


### Build & Dependencies

* **deps:** Bump actions/setup-go from 6.5.0 to 7.0.0 ([af0673a](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/af0673afefda6cc7a089330bb8f00b67b435a423))
* **deps:** Bump actions/setup-go from 6.5.0 to 7.0.0 ([0bb7937](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/0bb79377aef2372109533c9a728cc282d3932779))
* **dotnet:** keep the VSTest bridge for SDKs before 10 ([2a20ded](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/2a20ded9db5790573ede4604ccbc66c0c2e93f12))
* **dotnet:** move dotnet test to Microsoft.Testing.Platform for xunit.v3 4.0 ([f1b5b89](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/f1b5b89c901204489b2536075f70fb5f4169855b))
* **java:** emit parameter names in the published jar ([59e0d61](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/59e0d615d374ab26c850b14fb0f0d66453d9536c))
* **release:** publish the four new packages, and say what only you can do ([1241d8b](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/1241d8bb93f2391ac2f037d38604e9a45c87ab6c))

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
