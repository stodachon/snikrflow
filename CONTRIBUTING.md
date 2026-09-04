# Contributing to SnikrFlow

Thanks for considering a contribution. SnikrFlow is young and the architecture
is still settling, so please read this before opening a PR -- it'll save both
of us time.

## Before you write code

For anything beyond a small bugfix or typo, **open an issue first** to discuss
the change. This project follows a specific architecture on purpose (see
below), and PRs that don't fit it are hard to merge no matter how good the
code is -- an issue thread lets us agree on the approach before you spend time
writing it.

## The one rule that matters most

**SnikrFlow owns the concepts. angr is an implementation detail.**

- `snikrflow/core/models.py` defines SnikrFlow's own data shapes (`Function`,
  `SecuritySink`, `AnalysisPath`, `SymbolicResult`, ...). Every layer above
  the backend works with these, never with raw angr/CLE objects.
- `snikrflow/analysis/interfaces/` defines *what* SnikrFlow can do. This is
  what the CLI imports.
- `snikrflow/analysis/backends/angr/` defines *how* angr does it today. This
  is the ONLY place `import angr` / `import claripy` should appear (outside
  of `elf/loader.py`, which owns loading the binary).

If you're adding a feature, ask: does this belong in a backend (angr-specific
logic) or an interface (the stable thing callers depend on)? If your PR adds
`import angr` inside `snikrflow/cli.py` or `snikrflow/reporting/`, that's a
sign it's in the wrong layer.

## Common contribution: adding sink signatures

The easiest, most welcome contribution. Edit
`snikrflow/sinks/signatures.py` -- it's a plain dict, no code changes needed
elsewhere:

```python
"my_category": [
    "some_dangerous_function",
],
```

Open a PR with a one-line reason why the function belongs (what makes it
security-sensitive, or -- like the `comparison` category -- what makes it
useful to flag even though it isn't "dangerous" in the classic sense).

## Terminology rules (please read)

SnikrFlow is deliberately careful about not overclaiming. If your change
touches reachability, symbolic execution, or data-flow results:

- Never collapse `statically_reachable` / `SAT` / `POSSIBLE` (data flow) /
  `CONFIRMED` into each other. They mean different things and the codebase
  keeps them as distinct enum values on purpose.
- Automated findings must carry a `Confidence` or be clearly labeled
  heuristic. Don't add a code path that presents a guess as certain.
- If an analysis stage can stop early (timeout, state limit, unsupported
  instruction), report that explicitly (`stopped_reason` on `SymbolicResult`
  is the pattern to follow) -- never silently treat "didn't finish" as "safe."

## Testing

- New analysis logic should be validated against small, deterministic test
  binaries (see `test_target.c` / `test_target2.c` in the repo for the
  pattern: minimal C, compiled with `-O0 -fno-stack-protector`, so control
  flow is easy to reason about by hand).
- If you're fixing a bug, a regression test that would have caught it is
  the fastest way to get a PR merged.
- Run the existing pytest suite (`pytest tests/`) before opening a PR.

## Code style

- Type hints on public functions.
- Docstrings that explain *why*, not just *what* -- especially for anything
  heuristic. Future readers (including you, in six months) need to know the
  limitations of a result, not just how it was computed.
- Keep backend modules narrow: one analysis concern per file
  (`functions.py`, `sinks.py`, `symbolic.py`, ...), matching the existing
  `analysis/backends/angr/` layout.

## Reporting bugs

Open an issue with:
- The exact command you ran (redact any proprietary binary paths/names if
  needed, but architecture/OS/angr version are useful).
- What you expected vs. what happened.
- If it's a crash, the full traceback.

## Responsible use

SnikrFlow is for authorized security research only. PRs that add features
whose primary purpose is enabling unauthorized access, exploitation, or
analysis of software you don't have permission to test will not be merged.

## License

By contributing, you agree your contribution is licensed under the same
MIT license as the rest of the project.
