# lint-cases' Ajv errors: a formatter library or Ajv alone (2026-10-04)

**Question.** `tools/lint-cases.mjs` validates `fixtures/cases.json` with
Ajv (owner decision Q24). With `allErrors`, a oneOf that matches nothing
carries every branch's errors: one planted problem in a case gives 26 to
53 errors (`better-ajv-errors-trial.txt`, the counts before the
formatter). Can a library, or Ajv with `allErrors` off, give one
line per problem, so the linter does not need its own `explain()` that
validates the value against each branch and keeps the closest?

**Versions.** Ajv 8.20.0 (`Ajv2020`, `strict: true`, `strictTypes` and
`strictRequired` off), `@apideck/better-ajv-errors` 0.3.7, Node
22.22.2, `fixtures/cases.json` and `cases.schema.json` as of `3760a71`.
Registry data read on 2026-10-04. Scripts and commands are in
`2026-10-04-lint-cases-ajv-errors/`.

## The formatter libraries

| Package | Version | Licence | Downloads, week to 2026-10-01 |
|---|---|---|---|
| `better-ajv-errors` | 2.0.3 | Apache-2.0 | 1,998,375 |
| `@readme/better-ajv-errors` | 2.4.0 | Apache-2.0 | 1,149,154 |
| `@apideck/better-ajv-errors` | 0.3.7 | MIT | 10,007,897 |

Only MIT was acceptable for this dependency, which leaves the apideck
fork. 0.3.7 was published 2026-03-28; the release before it, 0.3.6, on
2022-06-28. Its dependencies are `leven` and `jsonpointer`, both MIT.

It does not work on this schema (`better-ajv-errors-trial.txt`):

- With `allErrors` on it threw `TypeError: Cannot read properties of
  undefined (reading 'properties')` on all five plants. For an
  `additionalProperties` error it looks the property list up at the
  error's `schemaPath`, read against the root schema. After a `$ref`,
  Ajv's `schemaPath` is relative to the referenced schema
  (`#/oneOf/0/additionalProperties` for a case), so the lookup returns
  `undefined`; its fallback only applies when the lookup throws.
- With `allErrors` off it threw on two of five (wrong type, unknown
  property) and gave 2, 7 and 6 lines for the other three. It does not
  choose a oneOf branch: it keeps one error per instance path and
  property, so lines from the branches the case was not meant to match
  stay ("'operation' property must be equal to the allowed value",
  "must have required property 'decoders'").

## Ajv with allErrors off

`all-errors-off-trial.txt`. Ajv stops each branch at its first error
but still evaluates every branch of a oneOf, so a failed case oneOf
reports one error per branch: 5 to 8 errors per plant. A filter that
keeps only the errors at the deepest instance path, the nearest thing
to "the closest branch" without validating again, leaves 4, 2, 4, 5 and
1 lines; only the trustedRoots plant comes down to its one problem. The
branch an error came from cannot be read off the error: after a `$ref`
the `schemaPath` names a place in the referenced schema, not the
branch. And Ajv stops at the first invalid case: with two cases broken,
none of the five errors is about the second (the `two-cases-broken`
plant), where the linter lists every problem.

## Verdict

Neither gives one line per problem. lint-cases keeps `explain()`: for a
failed oneOf it validates the value against each branch, compiled on its
own with the root's `$defs`, and reports the branch with the fewest
errors. `tools/test/lint-cases.test.mjs` plants the violations the
hand-written validator was checked against and asserts one line each.

This holds for this schema, whose oneOf branches sit behind `$ref`s, and
for these versions. A formatter that resolved `$ref`s and chose a oneOf
branch would be worth a new trial.
