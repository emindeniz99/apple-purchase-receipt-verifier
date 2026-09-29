# Python package on the release module: measurement sources

The note is `../2026-09-29-python-g1.md`. `$VENV` is a virtualenv with the
package installed, `$SCRATCH` a directory outside the repository.

| File | Question |
|---|---|
| `measure.py` | Start-up wall and CPU time, and peak memory, with the cache off, filling and hit, on all CPUs and on one |
| `calls.py` | CPU time per call on the two genuine receipts and a JWS |
| `throughput.py` | Receipts per second with 1, 2, 4 threads and 1, 2, 4 processes |

```sh
$VENV/bin/python measure.py $SCRATCH/cache 3
$VENV/bin/python calls.py
$VENV/bin/python throughput.py 4
```

To compare two modules, put a copy of the package with the other module and
its `.sha256` on `PYTHONPATH` and run from another directory.
