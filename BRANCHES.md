# Branch layout

This repository uses **two product branches**. Do not merge one into the other to "sync" them.

| Branch | Purpose | Build from |
|--------|---------|------------|
| **master** | GNU Radio **3.10** OOT (OpenSSL blocks, Python QA, GRC) | Repository root: `cmake ..` in `build/` |
| **gnuradio4** | GNU Radio **4.0** header-only OOT | **`gnuradio4/`** only: `cmake -S gnuradio4 -B gnuradio4/build` |

## Shared fixes

When a fix applies to both (e.g. OpenSSL 3 in `lib/`, Python ABI in `python/CMakeLists.txt`):

1. Commit on the branch where you developed the fix.
2. On the other branch: `git cherry-pick <sha>` (resolve conflicts if any).
3. Do **not** use `git merge master` on `gnuradio4` for routine updates.

## Releases / docs

- **master** `README.md`: GR 3.10 only; short pointer to `gnuradio4` branch.
- **gnuradio4** `README.md`: GR 4.0 primary; note that `master` is canonical for GR 3.10.
