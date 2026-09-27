# jvm-interop (internal — not published)

Proves the library is actually usable from other JVM languages, not just
Java. `java/` ships a single artifact to Maven Central; every other JVM
language that consumes it does so "through the jar" — this module is the
test of that claim, in Kotlin and Scala 3.

## What it proves

Both `KotlinInteropTest` and `ScalaInteropTest` run the same three checks,
each written the way a consumer of that language would actually write it:

1. Verify the genuine sandbox receipt (`fixtures/public-receipts/receipt-sandbox-g5.b64`)
   with `Verifier.create(Config.defaults())`, the library's built-in Apple
   roots, asserting `receiptType == "ProductionSandbox"` and the bundle id
   the payload carries (`dev.bonzer.weeka.app`).
2. Verify the shared JWS transaction fixture (`fixtures/generated/transaction.jws`)
   with `verifySignedData`, under a `Config` whose only root is
   `fixtures/generated/jws-root.der`, asserting the returned JSON carries
   `transactionId` `2000000000000001`.
3. A verification that is expected to fail (an Xcode-signed receipt against
   the real Apple roots) surfaces `Reason.UNTRUSTED_CHAIN` through the
   `VerificationResult`, with no exception: Kotlin reads it with `?:`, Scala
   turns the result into an `Either`.

Beyond that, each test file exercises the ergonomics that would break first
if the Java API were unfriendly to that language:

- **Kotlin**: JSpecify nullness at the boundary on `VerificationResult` and
  `ReceiptPayload`'s accessors, an exhaustive `when` over `Reason` with no
  `else` branch, and the `Config` builder standing in for named arguments,
  which Kotlin cannot use against this (or any) Java API; see the finding
  below.
- **Scala 3**: an exhaustive `match` over the same `Reason` enum with no
  wildcard case, `Option(...)` at the nullable accessors, and
  `scala.jdk.CollectionConverters` at the `java.util.Collection` boundary
  of `Config.Builder.roots`.

## Findings

- **Kotlin named arguments against a Java API: impossible, by Kotlin
  design — not something `java/pom.xml` could ever fix.** Established on
  the 0.6 API, whose verifiers took their settings as constructor
  parameters. The first pass of this module blamed the original compile failure on `java/pom.xml`'s
  `maven-compiler-plugin` not passing `-parameters` to `javac` (the
  published class files had no `MethodParameters` attribute — verified
  with `javap -v`, showing `p0..p4` instead of `trustedRoots`, `bundleId`,
  etc.). `java/pom.xml` was then changed to
  `<parameters>true</parameters>`, and `javap -v` now shows the real
  names on every method and constructor. **The named-argument call still
  does not compile.** Two checks nail down why, and rule out anything
  about our jar:
  1. `JwsVerifier(trustedRoots = ..., bundleId = ..., ...)` fails even
     though the class file now carries the real parameter names.
  2. The identical named-argument syntax against a plain JDK class —
     `java.awt.Point(x = 1, y = 2)`, nothing to do with this repo — fails
     the same way, with the Kotlin compiler's own diagnostic: `Named
     arguments are prohibited for non-Kotlin functions.`

  So this is a categorical Kotlin/Java-interop rule with no bytecode flag
  that lifts it: Kotlin refuses named-argument syntax at any Java-declared
  function or constructor, full stop. **My original diagnosis was wrong**
  — `-parameters` was never the blocker. In 0.6 a Kotlin consumer fell
  back to overload selection. In 0.7 the optional settings live on
  `Config.builder()`, where each setting is a named method call and the
  ones left out keep their defaults; `KotlinInteropTest` checks that the
  builder chain reads naturally from Kotlin.

  `<parameters>true</parameters>` is still worth keeping in `java/pom.xml`
  for what it actually does: real parameter names in IDE hints and
  compiler diagnostics (visible even in the Kotlin error messages above),
  and correct names for anything that inspects this jar via Java or Kotlin
  reflection (e.g. a framework binding request parameters to constructor
  args by name). It just doesn't — and structurally cannot — enable
  Kotlin named-argument call syntax.
- **JSpecify annotations survive the jar, and Kotlin honours them without
  resolving the annotation artifact.** The library's public packages are
  `@NullMarked` and its optional accessors are `@Nullable`, so Kotlin
  types `ReceiptPayload.receiptType()` and `VerificationResult.payload()`
  as nullable and `Config.roots()` as a non-null `Set<X509Certificate>`
  rather than as platform types. `org.jspecify:jspecify` is `<optional>` in
  `java/pom.xml`, so it is not transitive and is NOT on this module's
  classpath — Kotlin reads the annotation names straight out of the class
  files. Both halves were measured with a throwaway probe source file
  (first on the 0.6 jar with Kotlin 2.4.10 on 2026-09-06, again on the 0.7
  jar with Kotlin 2.4.20 on 2026-09-27, both with
  `-Xjspecify-annotations=strict`):
  `fun probeNullable(r: ReceiptPayload): String = r.receiptType()` is
  `error: Return type mismatch: expected 'String', actual 'String?'`, and
  `Config.defaults().roots()?.size` is
  `warning: Unnecessary safe call on a non-null receiver`. Neither direction
  can be a permanent test here, because a compile error fails the whole
  module and a platform type would satisfy every assignment that does
  compile; `KotlinInteropTest` carries the probe and both messages in a
  comment so the check can be repeated.
- **Reason exhaustiveness works in both languages, cleanly.** A `mvn clean
  test` run of this module produces zero exhaustiveness warnings from
  either `kotlinc` or `scalac` — both a Kotlin `when` and a Scala 3 `match`
  over `Reason` are treated as fully checked without
  an `else`/wildcard branch, because it is a plain Java `enum` and both
  compilers recognize Java enums as closed sets for this purpose. Adding
  another `Reason` constant to the library would fail this module's build
  at the `when`/`match` sites until updated — which is the point.
- No other friction: the factory, builder, methods and returned types
  (`VerificationResult`, `ReceiptPayload`, `JsonPayload`) read naturally
  from both languages; collections are plain `java.util` types, so Scala
  needs `.asJava`/`CollectionConverters` (expected) and Kotlin needs
  nothing extra (`kotlin.collections.Set` and `java.util.Set` are
  compatible at the call site).

## Why it is not published

This module has no source under `src/main/`, exists only to compile and run
tests against the real published artifact coordinates, and is deliberately
excluded from every release mechanism in this repo:

- Not listed in `release-please-config.json` (which only tracks
  `java/pom.xml`, `node/package.json`, `python/pyproject.toml`).
- Not a `<module>` of any aggregator pom — there isn't one in this repo;
  every language directory already builds independently.
- Its own `pom.xml` has no `central` profile, no `<distributionManagement>`,
  and a version (`0.0.0-not-for-publication`) that signals intent even if
  someone tried to `deploy` it directly.

## How to run it

```bash
cd java && mvn -B install -DskipTests   # publishes the jar to ~/.m2 so
                                         # jvm-interop can resolve it as a
                                         # real Maven coordinate
cd ../jvm-interop && mvn -B test
```

The first run downloads the Kotlin and Scala 3 compilers (both pulled by
their Maven plugins from Maven Central) — budget a few minutes and a few
hundred MB on a cold cache.
