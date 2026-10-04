# 2026-10-04 lint-cases-ajv-errors scripts

| File | Question it answered |
|---|---|
| `plants.mjs` | The five schema violations both trials plant, and the Ajv options `tools/lint-cases.mjs` uses. |
| `better-ajv-errors-trial.mjs` | Does `@apideck/better-ajv-errors` 0.3.7 turn Ajv's errors for one planted violation into one readable line, with `allErrors` on or off? |
| `all-errors-off-trial.mjs` | With `allErrors` off, are Ajv's errors few enough to cap a failed oneOf to one branch without validating again? Where does Ajv stop when two cases are broken? |

## Reproduce

`$REPO` is the repository root at `3760a71` or later (the schema and
cases are unchanged since), `$SCRATCH` any directory outside it. Node
22.22.2.

```sh
npm ci --prefix "$REPO/tools" --ignore-scripts
echo '{"private":true}' > "$SCRATCH/package.json"
npm install --prefix "$SCRATCH" --ignore-scripts --save-exact \
  ajv@8.20.0 @apideck/better-ajv-errors@0.3.7

E="$REPO/docs/evidence/2026-10-04-lint-cases-ajv-errors"
node "$E/better-ajv-errors-trial.mjs" "$REPO" "$SCRATCH" > "$SCRATCH/better-ajv-errors-trial.txt"
node "$E/all-errors-off-trial.mjs" "$REPO" > "$SCRATCH/all-errors-off-trial.txt"
```

Licences and download counts were read from the registry:

```sh
for p in better-ajv-errors @readme/better-ajv-errors @apideck/better-ajv-errors; do
  npm view "$p" version license
  curl -s "https://api.npmjs.org/downloads/point/last-week/$p"; echo
done
npm view @apideck/better-ajv-errors time --json
```
