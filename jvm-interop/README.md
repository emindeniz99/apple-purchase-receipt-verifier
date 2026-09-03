# jvm-interop (internal — not published)

Proves the library is actually usable from other JVM languages, not just
Java. `java/` ships a single artifact to Maven Central; every other JVM
language that consumes it does so "through the jar" — this module is the
test of that claim, in Kotlin and Scala 3.

## What it proves

Both `KotlinInteropTest` and `ScalaInteropTest` run the same three checks,
each written the way a consumer of that language would actually write it:

1. Verify the genuine sandbox receipt (`fixtures/public-receipts/receipt-sandbox-g5.b64`)
   against the library's built-in Apple root certificates, bundle id
   `dev.bonzer.weeka.app`, asserting `receiptType == "ProductionSandbox"`.
2. Verify the shared JWS transaction fixture (`fixtures/generated/transaction.jws`)
   against `fixtures/generated/jws-root.der`, bundle id `com.example.app`,
   `Environment.SANDBOX`, asserting `transactionId == "2000000000000001"`.
3. A verification that is expected to fail (an Xcode-signed receipt against
   the real Apple roots) surfaces its `Reason` through each language's
   idiomatic error handling — `try`/`catch` in both.

Beyond that, each test file exercises the ergonomics that would break first
if the Java API were unfriendly to that language:

- **Kotlin**: null-safety at the boundary on `AppReceipt`'s platform-typed
  accessors, an exhaustive `when` over `VerificationException.Reason` with
  no `else` branch, and overload selection standing in for named/default
  arguments — Kotlin cannot use either against this (or any) Java API; see
  the finding below.
- **Scala 3**: an exhaustive `match` over the same `Reason` enum with no
  wildcard case, and `scala.jdk.CollectionConverters` at the `java.util.Set`
  boundary.

## Findings

- **Kotlin named arguments against a Java API: impossible, by Kotlin
  design — not something `java/pom.xml` could ever fix.** The first pass
  of this module blamed the original compile failure on `java/pom.xml`'s
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
  — `-parameters` was never the blocker, and there is no fix for a Kotlin
  consumer to reach for beyond overload selection (calling the 2-arg
  `JwsVerifier` constructor when the trailing params really are omitted,
  not just named), which is what `KotlinInteropTest` now documents in
  place of the named-argument test.

  `<parameters>true</parameters>` is still worth keeping in `java/pom.xml`
  for what it actually does: real parameter names in IDE hints and
  compiler diagnostics (visible even in the Kotlin error messages above),
  and correct names for anything that inspects this jar via Java or Kotlin
  reflection (e.g. a framework binding request parameters to constructor
  args by name). It just doesn't — and structurally cannot — enable
  Kotlin named-argument call syntax.
- **Reason exhaustiveness works in both languages, cleanly.** A `mvn clean
  test` run of this module produces zero exhaustiveness warnings from
  either `kotlinc` or `scalac` — both a Kotlin `when` and a Scala 3 `match`
  over `VerificationException.Reason` are treated as fully checked without
  an `else`/wildcard branch, because it is a plain Java `enum` and both
  compilers recognize Java enums as closed sets for this purpose. Adding a
  twelfth `Reason` constant to the library would fail this module's build
  at the `when`/`match` sites until updated — which is the point.
- No other friction: constructors, methods, and returned model types
  (`AppReceipt`, `TransactionPayload`) read naturally from both languages;
  collections are plain `java.util.Set`, so Scala needs
  `.asJava`/`CollectionConverters` (expected) and Kotlin needs nothing
  extra (`kotlin.collections.Set` and `java.util.Set` are compatible at the
  call site).

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
