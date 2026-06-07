# Noita-Eyesieve — convergence review & audit (delivered via h3x-dash)

This folder is the deliverable for a **review + audit + bugfix** of the three
lines of effort in [`Null-H3x/Noita-Eyesieve`](https://github.com/Null-H3x/Noita-Eyesieve):
EyeStat (GPU seed-scan), EyeSieve (structural sweep), and the eye-cipher
workbench.

It lives in the `h3x-dash` repo only because the cloud agent's credentials do
**not** have write access to `Noita-Eyesieve` (push returns HTTP 403 — the token
is scoped to this repo). To land these changes directly in `Noita-Eyesieve`,
grant the cloud agent write access to that repo and re-run; otherwise apply the
patches below.

## Contents
- `CONVERGENCE_AND_AUDIT.md` — capability map, convergence analysis, full audit
  findings, and recommendations.
- `patches/01-eyesieve.patch` — `eyesieve_keyderiv.py`, `eyesieve_run_report.py`,
  `eyesieve_selftest.py`.
- `patches/02-eyestat.patch` — `eyestat_scoring.py`.
- `patches/03-workbench.patch` — `eye-cipher-workbench.html`.

## Applying the patches
```bash
# In a Noita-Eyesieve checkout:
tar xzf eyesieve-v1.0.1.tar.gz -C eyesieve_src   # if not already extracted
(cd eyesieve_src && patch -p1 < /path/to/patches/01-eyesieve.patch)

unzip eyestat.zip                                # -> eyestat/
(cd eyestat && patch -p1 < /path/to/patches/02-eyestat.patch)

patch -p1 < /path/to/patches/03-workbench.patch  # from repo root
```

All patches were dry-run-applied cleanly against the pristine archive contents,
and the suites are green after applying: EyeStat 57/57 + 8/8 + shadow audit;
EyeSieve 220/220; workbench JS parses clean.
