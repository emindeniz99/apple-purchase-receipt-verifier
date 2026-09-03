# CI job to add for jvm-interop

Not wired into `.github/workflows/ci.yml` here — the orchestrator adds it.
Pins copied verbatim from the existing `java` job in that file (same
`actions/checkout` and `actions/setup-java` SHAs, same `persist-credentials:
false`, no extra `permissions:` block since the workflow-level
`contents: read` already covers a read-only checkout).

```yaml
  # Proves jvm-interop/README.md's claim: the published jar is usable from
  # other JVM languages, not just Java. Builds java/ first (install, not
  # just package, so jvm-interop resolves it as a real Maven coordinate
  # from the local repo — same as any consumer would from Central), then
  # runs the Kotlin + Scala 3 interop tests. Never part of the release:
  # jvm-interop/ has no release-please entry and no <module> anywhere.
  jvm-interop:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-java@dd06d9cba3e5552c54d9f8ea23572deb30010f7c # v6.0.0
        with:
          distribution: temurin
          java-version: "21"
          cache: maven
      - run: mvn -B install -DskipTests
        working-directory: java
      - run: mvn -B test
        working-directory: jvm-interop
```
