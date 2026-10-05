# The Java port on every JDK vendor setup-java installs

**Question.** Does the BouncyCastle port give the same verdicts on every
JDK vendor a consumer might run, not only on Temurin? Every Java job ran
on Temurin, plus Debian's OpenJDK 17 in the distroless leg. The answer
decides whether the `java-vendors` job in `.github/workflows/ci.yml` is
worth keeping, and which vendor and line pairs it runs.

**Method.** One CI run, 37260913345, on 2026-10-05, on PR #263 at the
library version 0.8.1 with BouncyCastle 1.86. Twelve vendors were each
asked for Java 8, 21 and 25 through `actions/setup-java` v6.0.1 on the
`ubuntu-24.04` runner image 20260927.320.1 (x86_64). Maven ran on
Temurin 25.0.4+1, and surefire 3.6.0 forked the vendor's JVM through the
`jdk8-runtime` profile, so only the runtime varied. Each leg printed
`java -XshowSettings:properties` from the JVM under test, then ran the
whole suite: 599 tests, all 388 cases of `fixtures/cases.json`
included. Temurin is not in the table; the `java` job already covers it.

## Results

Tests are run/failures/errors/skipped. The skip is
`FixtureGeneratorTest` in every leg. Among the 599 is
`ConformanceCasesTest`'s last test, which fails when any case in
`fixtures/cases.json` did not run, so every passing leg ran all 388.

| vendor | line | tests | java.runtime.version | java.vm.name | setup-java refusal |
|---|---|---|---|---|---|
| corretto | 8 | 599/0/0/1 | 1.8.0_504-b04 | OpenJDK 64-Bit Server VM | |
| corretto | 21 | 599/0/0/1 | 21.0.12.1+12-LTS | OpenJDK 64-Bit Server VM | |
| corretto | 25 | 599/0/0/1 | 25.0.4.1+10-LTS | OpenJDK 64-Bit Server VM | |
| dragonwell | 8 | 599/0/0/1 | 1.8.0_502-b01 | OpenJDK 64-Bit Server VM | |
| dragonwell | 21 | 599/0/0/1 | 21.0.12.0.12 | OpenJDK 64-Bit Server VM | |
| dragonwell | 25 | 599/0/0/1 | 25.0.4.0.4 | OpenJDK 64-Bit Server VM | |
| graalvm | 8 | not shipped | | | GraalVM is only supported for JDK 17 and later. Requested version: 8 |
| graalvm | 21 | 599/0/0/1 | 21.0.12+7-LTS-jvmci-23.1-b96 | Java HotSpot(TM) 64-Bit Server VM | |
| graalvm | 25 | 599/0/0/1 | 25.0.4+7-LTS-jvmci-b01 | Java HotSpot(TM) 64-Bit Server VM | |
| jetbrains | 8 | not shipped | | | No matching version found for SemVer '8'. |
| jetbrains | 21 | 599/0/0/1 | 21.0.11+10-b1163.116 | OpenJDK 64-Bit Server VM | |
| jetbrains | 25 | 599/0/0/1 | 25.0.4+1-b508.27 | OpenJDK 64-Bit Server VM | |
| kona | 8 | 599/0/0/1 | 1.8.0_492-b1 | OpenJDK 64-Bit Server VM | |
| kona | 21 | 599/0/0/1 | 21.0.11+1-LTS | OpenJDK 64-Bit Server VM | |
| kona | 25 | 599/0/0/1 | 25.0.3+1-LTS | OpenJDK 64-Bit Server VM | |
| liberica | 8 | 599/0/0/1 | 1.8.0_504-b01 | OpenJDK 64-Bit Server VM | |
| liberica | 21 | 599/0/0/1 | 21.0.12+10-LTS | OpenJDK 64-Bit Server VM | |
| liberica | 25 | 599/0/0/1 | 25.0.4+9-LTS | OpenJDK 64-Bit Server VM | |
| microsoft | 8 | not shipped | | | No matching version found for SemVer '8'. |
| microsoft | 21 | 599/0/0/1 | 21.0.11+10-LTS | OpenJDK 64-Bit Server VM | |
| microsoft | 25 | 599/0/0/1 | 25.0.3+9-LTS | OpenJDK 64-Bit Server VM | |
| oracle | 8 | not shipped | | | Oracle JDK is only supported for JDK 17 and later |
| oracle | 21 | 599/0/0/1 | 21.0.12.1+1-LTS-4 | Java HotSpot(TM) 64-Bit Server VM | |
| oracle | 25 | 599/0/0/1 | 25.0.4.1+1-LTS-5 | Java HotSpot(TM) 64-Bit Server VM | |
| redhat | 8 | 599/0/0/1 | 1.8.0_462-b08 | OpenJDK 64-Bit Server VM | |
| redhat | 21 | 599/0/0/1 | 21.0.8+9-LTS | OpenJDK 64-Bit Server VM | |
| redhat | 25 | not shipped | | | No matching version found for SemVer '25'. |
| sapmachine | 8 | not shipped | | | No matching version found for SemVer '8'. |
| sapmachine | 21 | 599/0/0/1 | 21.0.12.1+1-LTS | OpenJDK 64-Bit Server VM | |
| sapmachine | 25 | 599/0/0/1 | 25.0.4.1+1-LTS | OpenJDK 64-Bit Server VM | |
| semeru | 8 | 599/0/0/1 | 1.8.0_504-b01 | Eclipse OpenJ9 VM | |
| semeru | 21 | 599/0/0/1 | 21.0.12.1+1-LTS | Eclipse OpenJ9 VM | |
| semeru | 25 | 599/0/0/1 | 25.0.4.1+1-LTS | Eclipse OpenJ9 VM | |
| zulu | 8 | 599/0/0/1 | 1.8.0_504-b01 | OpenJDK 64-Bit Server VM | |
| zulu | 21 | 599/0/0/1 | 21.0.12+8-LTS | OpenJDK 64-Bit Server VM | |
| zulu | 25 | 599/0/0/1 | 25.0.4+7-LTS | OpenJDK 64-Bit Server VM | |

- **30 legs reached the tests, and all 30 passed** with the same counts.
  The verdicts did not depend on the vendor.
- **IBM Semeru runs a different JVM**, Eclipse OpenJ9, and passed on all
  three lines. GraalVM and Oracle run HotSpot under Oracle's name; the
  rest run OpenJDK HotSpot builds.
- **Six legs never started.** setup-java has no build for them, and its
  message is quoted in the last column. The job now excludes those six.

## Where this stops holding

- Linux x86_64 only. No vendor was tried on arm64, macOS or Windows.
- One run, on each vendor's build of that day. A vendor update can
  change the result. The job runs on every pull request that touches the
  Java port, not on pushes to main, so a vendor regression shows up on
  the next such pull request rather than on the day it ships.
- The default `java.security` of each vendor build. A FIPS mode, a
  hardened policy (the `java-hardened-policy` job covers one) or a
  replaced default `SecureRandom` was not tried. The round-3 review of
  the port found that BouncyCastle draws from the JVM's default
  `SecureRandom` when it first decodes an RSA key, so a broken default
  RNG changes a verdict on any vendor.
- Default thread stacks only. The same review measured a stack overflow
  below about 160 KB on OpenJDK 21; OpenJ9 frames differ in size and
  were not measured.
- GraalVM ran as a JIT JVM, not as native-image.
