# Dependency survey scripts (2026-10-31)

These are the scripts behind [../2026-10-31-dependency-survey.md](../2026-10-31-dependency-survey.md).

| File | What it answers |
|---|---|
| `parse.py` | What the repository locks or pins. It reads every lockfile and manifest under `$REPO` and writes one JSON list of `{eco, name, version, file, kind}`. |
| `newer.py` | Which locked versions have a newer release dated on or after `$CUT` (default 2026-10-24, the seven-day cooldown). It asks each registry's API. |
| `osv.py` | Which locked versions have a known advisory. It sends `api.osv.dev/v1/querybatch` and fetches each hit's details. |
| `acts.sh` | Which pinned GitHub Actions have newer tags. It reads `owner/repo version` lines on stdin and calls `git ls-remote`. |

## Reproduce

```sh
cd $SCRATCH
REPO=$REPO python3 -I $REPO/docs/evidence/2026-10-31-dependency-survey/parse.py deps.json
python3 -I $REPO/docs/evidence/2026-10-31-dependency-survey/newer.py deps.json newer.json
python3 -I $REPO/docs/evidence/2026-10-31-dependency-survey/osv.py deps.json osv.json
grep -ho 'uses: [^@ ]*@[^ ]* # v[0-9.]*' $REPO/.github/workflows/*.yml \
  | sed 's/uses: \([^@]*\)@[^ ]* # \(.*\)/\1 \2/' | sort -u \
  | sh $REPO/docs/evidence/2026-10-31-dependency-survey/acts.sh
```

Behind a TLS-intercepting proxy, set `SSL_CERT_FILE` to its CA bundle. The JSON outputs stay in `$SCRATCH`.
