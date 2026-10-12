# .NET growth test on osx-arm64: a steady reading, not a warm-up tail

**Question.** `PlatformTests.RepeatedVerificationDoesNotGrowUnboundedly`
still fails now and then on `dotnet (macos-latest)` after ac28f88f
(2026-09-29) made it judge up to three consecutive windows. Which
change stops that without weakening leak detection: more windows, a
longer or adaptive warm-up, or a budget for osx-arm64? The owner asked
for a robust measurement with a 256 B per call leak still failing on
every platform, and no skip (2026-10-12, Q119 a).

**Versions.** CI: `macos-latest` (osx-arm64), the failing hosts on
.NET 8.0.31 and 10.0.12, Wasmtime 48.0.2, the test's stub module.
Here: Linux x86-64, .NET SDK 10.0.401 with the 8.0.31, 9.0.20 and
10.0.12 runtimes, main at 4f2b8cbc, built with the release module the
.NET pin names (`d882964f…bec5`). Run on 2026-10-12. Sources and
commands are in `2026-10-12-dotnet-growth-test-macos/`.

## What CI shows

`pull-failures.sh` listed every ci run from 2026-09-29T17:00Z to
2026-10-12T07:25Z (642 runs) and every `dotnet (<os>)` job in them,
every attempt (`macos-jobs.txt`). After ac28f88f, 262 macOS jobs finished: 253 passed, eight failed on
this test and one failed before any test ran (`111383960050`, 10-04, an
action it could not find); 41 more were cancelled and one never ran.
A ninth growth-test failure, on main at 08:01Z (3e222169), came after the listing
and is in the table too. Each failing job failed in one of its three
test hosts, never two; the other two passed (`messages/`). Linux and
Windows never failed it. The failing messages:

| Run / job | Date | Host | Allocated per call | Control | Windows, B per call | Whole path again | Take and return |
|---|---|---|---|---|---|---|---|
| 36794567797 / 110163883833 | 10-01 | net8.0 | 26,280 B | −5.5 | 824.9, 824.8, 824.7 | 837.2 | 32.1 |
| 36807101128 / 110195934394 | 10-01 | net10.0 | 26,168 B | −5.5 | 985.1, 1,360.0, 1,266.4 | 1,264.4 | 26.6 |
| 36954576440 / 110675346318 | 10-02 | net8.0 | 26,280 B | 5.5 | 813.9, 808.3, 820.6 | 822.7 | 32.1 |
| 37687132226 / 113020173197 | 10-07 | net10.0 | 15,704 B | −0.1 | 1,117.5, 1,336.9, 1,269.8 | 1,216.5 | 32.1 |
| 37793939257 / 113368809429 | 10-08 | net10.0 | 15,920 B | 5.5 | 1,524.0, 1,469.8, 1,458.9 | 1,469.6 | 37.6 |
| 38185421270 / 114606777660 | 10-11 | net10.0 | 15,920 B | 5.3 | 1,548.2, 1,469.8, 1,469.9 | 1,469.7 | 26.6 |
| 38185497318 / 114608025763 | 10-12 | net10.0 | 15,920 B | −5.5 | 1,603.5, 1,485.1, 1,485.1 | 1,387.2 | 26.6 |
| 38185455960 / 114608715422 | 10-12 | net10.0 | 15,920 B | 0.0 | 1,491.9, 1,479.5, 1,484.9 | 1,387.0 | 37.6 |
| 38220311874 / 114715074952 | 10-12 | net10.0 | 15,920 B | −0.2 | 1,483.6, 1,458.8, 1,464.3 | 1,475.2 | 26.6 |

"Whole path again" is the breakdown's first figure, measured after the
three windows. Every other piece (clock, UTF-8 encoding, lowering, the
export, the post-return, the whole native call, reading the answer)
reads −5.5 to 5.5 B, the idle control 0.0 to 5.5 B, and 0 of 200
dropped results are alive after two collections, in every row. The
allocation fell from about 26 kB to about 16 kB per call with
4c07a75f (2026-10-02); the figure did not.

Passing jobs print nothing about this test, so there is no macOS figure
for a host that passed.

Three things follow.

1. **The growth does not fall.** Each window is 3 × 500 + 3 × 2,000
   calls, so the four readings of a failing host span 30,000 calls after
   the warm-up, and the lowest is at least 72 % of the highest. Where
   they differ most (110195934394), the first window is the lowest, not
   the highest. The failures before ac28f88f
   were another shape: one window of 1,533 and 3,505 B, then 0.0 and
   −0.7 B for the same path measured again
   (`messages/job-109538858153.txt`). That first-window tail is what
   ac28f88f absorbed. What fails now is a host whose reading is high
   from the first window to the last.
2. **The reading counts bytes the code dropped.** Taking an instance
   and handing it back allocates 32 B per call (`linux/allocation.txt`):
   the `ConcurrentStack` node of the push, which the next pop drops; the
   stack holds one node. It reads
   26.6 to 37.6 B per call in every failing host, and 0.0 on Linux
   (`linux/breakdown.txt`). In the same hosts the weak-reference count
   finds every dropped result collected. So in a failing host
   `GC.GetTotalMemory` after `GC.Collect()` reports a share of what the
   path allocated and dropped as live, close to all of it for the
   stack node.
3. **The control cannot subtract it.** The control allocates as many
   bytes in 100 B arrays with no references and reads −5.5 to 5.5 B in
   those same hosts. The share depends on what is allocated, not on how
   much, so a control of equal bytes does not carry it.

## The three candidates, against the figures

- **More windows** (3 to 5): rejected. No failing host's readings fall
  toward the budget: the fourth reading, taken after the three windows,
  is 822.7 to 1,475.2 B, three to six times the budget. Two more windows
  would read the same.
- **A longer or adaptive warm-up**: rejected. The failures are not
  first-window-dominated; the reading does not decay over the 30,000
  calls after the 500-call, 400 ms warm-up. A "two windows agree" rule
  would stop at once on these hosts, with the same figure.
- **An osx-arm64 budget**: rejected. The steady figure is 808 to
  1,604 B per call. A budget above it is above the 256 B leak the test
  must catch, and near one leaked `X509Certificate2` per call
  (1,730 B). It would also wave through a real leak of that size on the
  platform where the test is flaky.

None of the three fits the figures. The owner chose a change to the
reading instead (2026-10-12, after these figures), below.

## Leak detection before the change, on Linux

The clean path reads 0.0 B per call in six windows on every runtime, now
and then ±5.5 B in one window (`linux/windows.txt`,
`linux/breakdown.txt`); every piece of the breakdown reads 0.0. The
test as it was ran 10 times per runtime and passed 10 of 10 on net8.0,
net9.0 and net10.0 (`linux/ten-runs.txt`).

With a leak injected into the measured path (a static `List<byte[]>`,
one array per call), each window reads (`linux/leak-sizes.txt`,
`linux/leak-256-unchanged-test.txt`):

| Kept per call | First window | Later windows | Verdict at the 256 B budget |
|---|---|---|---|
| 128 B array | 125.3 | (passed) | passes |
| 256 B array | 253.3 | (passed) | **passes** |
| 264 B array | 261.3 | 264.0, 264.0 | fails |
| 280 B array | 277.3 | 280.0, 280.0 | fails |
| 512 B array | 509.3 | 512.0, 512.0 | fails |

The same on net8.0, net9.0 and net10.0. `linux/leak-sizes.txt` was read
through `probe-instruments.patch` (its `total` mode, which adds a
compacting collection before `GetTotalMemory`); the test exactly as it
was read the same 253.3 B for the 256 B array on net8.0 and net10.0
and passed (`linux/leak-256-unchanged-test.txt`). Later windows read the array
bytes exactly; the first reads 2.7 B low because the list's own backing
array grows once inside it. So the test caught about 259 B per call and
more, and **a 256 B leak passed**. The CI notes said injected leaks of
256 B fail; that does not hold for a 256 B array per call.

## The change

Two changes to `PlatformTests.cs`, nothing else:

- **A second reading.** `LiveSet` still reads `GC.GetTotalMemory` after
  a full collection, then runs a compacting full collection
  (`GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting:
  true)`) and also reads the bytes it marked
  (`GC.GetGCMemoryInfo(GCKind.FullBlocking).PromotedBytes`), which count
  only what the collector reached. Every window, both controls and every
  piece are measured under both; each reading takes its own smallest
  round and its own control. A window passes when either reading, net of
  its control, is within the budget, so the test fails only when both
  exceed it in every window. The message prints both readings for every
  window, both controls and every piece.
- **The budget is 128 B per call**, about half of what a 256 B array reads.

Why either reading may pass a window: a leak is live under both. On
Linux the two read the same on every probe (`linux/instruments.txt`):
0.0 B clean, 253.3 B for the 256 B array. If the macOS figure is bytes
that `GetTotalMemory` counts but no collection reaches, it is absent from
the marked bytes and the window passes there. If it is reachable after
all, both readings are high and the test still fails, now with both
figures in the message.

Results on Linux after the change (`linux/leak-new-test.txt`,
`linux/ten-runs.txt`):

| Kept per call | Windows, total / marked, B per call | Verdict |
|---|---|---|
| nothing | (passed, 10 runs of 10 per runtime) | passes |
| 128 B array | (passed) | passes |
| 136 B array | 133.3 / 133.3, 136.0 / 136.0, 136.0 / 136.0 | fails |
| 256 B array | 253.3 / 253.3, 256.0 / 256.0, 256.0 / 256.0 | fails |

The same figures on net8.0, net9.0 and net10.0, and the whole test
project passes, 676 of 676 on each. The test now catches a leak of about
131 B per call and more; a 128 B array reads about 125 B and passes.

## Open

**The marked bytes are unproven on macOS.** Nothing here ran on
osx-arm64. That the macOS figure is absent from them is the hypothesis
this change rests on, taken from the take-and-return piece and the
weak-reference count, not a measurement. The pull request's
`dotnet (macos-latest)` legs are the first measurement. A pass there
says little on its own: the old test failed in 9 of 263
macOS jobs (3.4 %, one test host in about 90), so about 86 macOS jobs
in a row have to pass before such a streak is less than 5 % likely
under the old behaviour. A failure settles it either
way, because the message now carries both readings of every window.

The macOS margin under the 128 B budget is also unknown: passing hosts
print nothing, so no macOS figure exists for a host that passed.

## Where this stops holding

- macOS figures come from failing hosts only; no macOS machine was used
  here.
- That `GetTotalMemory` counts dropped bytes is inferred from the
  take-and-return piece and the weak-reference count. Nothing here
  looked inside the collector on macOS.
- `macos-latest` images and the .NET 8.0.31 and 10.0.12 runtimes of
  late September and October 2026, Wasmtime 48.0.2.
