---
name: Bug report
about: Something crashed, gave a wrong result, or behaved unexpectedly
title: "[BUG] "
labels: bug
assignees: ''
---

**Command run**
```
snikrflow ...
```
(Redact proprietary binary paths/names if needed -- architecture, OS, and
angr version are still useful.)

**Expected behavior**
What you thought would happen.

**Actual behavior**
What actually happened. If it crashed, paste the full traceback here:
```
(traceback)
```

**Environment**
- SnikrFlow version: (`snikrflow --version`)
- OS: (Windows / Kali / other Linux)
- Python version:
- angr version: (`pip show angr`)

**Binary details (if relevant)**
- Architecture (x86_64 / arm64 / etc.):
- Stripped?
- Source: (e.g. "OWASP UnCrackable Level 3", "internal binary" -- no need to
  attach proprietary binaries, just describe them)

**Anything else**
Anything that might help reproduce it (timeout used, --max-states, etc.)
