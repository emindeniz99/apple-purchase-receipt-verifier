# One regex replaces the source-scan tokenizer

**Question.** `TrustStoreIsolationTest` reads every main source with its
comments removed and its string literals kept, then asserts that no code
names a trust store, the network or a subprocess. A 50-line character
loop did the stripping. Does a single pattern give the same text on
every source the test scans, so the loop can go (owner Q117 a,
2026-10-12)?

**Versions.** OpenJDK 21.0.10, `java.util.regex`. Run on 2026-10-12 on
`test/java-readable-harness`, from main at 4f2b8cbc; the sources
compared are the 88 `.java` files under `java/src` at that commit.

## Method

`Compare.java` holds both the old loop and the new pattern,

```
//[^\n]*|/\*.*?\*/|"(?:[^"\\]|\\.)*+"|'(?:[^'\\]|\\.)*+'
```

with `DOTALL`, and replaces a match with nothing when it starts with `/`
and with itself otherwise. Alternation picks whichever token starts
first, so a `//` inside a literal is not a comment and a quote inside a
comment opens no literal, which is what the loop's state machine did. It
runs both over every file under a root and prints the files that
differ, then over five hand-written edge inputs (a URL in a string
followed by a line comment, a quote in a character literal, a comment
text inside a string, escaped quotes, `'/'` and real division), then
over one 200,000-character string literal followed by a 200,000-
character block comment.

## Results

| Input | Result |
|---|---|
| 88 files under `java/src` | `0 differ` |
| five edge inputs | all `same` |
| 200,000-character literal and comment | `true` (identical) |

The possessive quantifiers (`*+`) matter for the last row: the same
pattern with greedy `*` overflowed the regex engine's stack on that
literal. Text blocks are not handled by either version; the sources
compile at the Java 8 baseline, which has none.

## Verdict

The loop is replaced by the pattern (`codeOf` in
`TrustStoreIsolationTest`), 39 lines fewer, same output on every
scanned source. String literals stay in the scanned text on purpose: a
URL or a class name written in a string is still a hit, and stripping
literals would have weakened the claim.
