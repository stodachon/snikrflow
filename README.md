<p align="center">
  <img src="https://raw.githubusercontent.com/Stodachon/snikrflow/main/logo.svg" width="140" alt="SnikrFlow logo"/>
</p>

<h1 align="center">SnikrFlow</h1>

<p align="center">
  <b>Native binary security triage and reachability platform.</b><br/>
  Stop wondering where to start reversing a binary. Let SnikrFlow tell you.
</p>

<p align="center">
  <a href="https://pypi.org/project/snikrflow/"><img alt="PyPI" src="https://img.shields.io/pypi/v/snikrflow.svg"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-orange.svg"></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-blue.svg">
</p>

<p align="center">
  Built by <b>John Ebinyi Odey</b> at <b>Stodachon</b>
</p>

---

## The problem

You've got a large ELF binary or an Android `.so` library. Thousands of functions.
No idea where the interesting stuff is. You could spend two hours blindly
following callers, references, and branches in Ghidra... or you could ask:

> "Before I spend two hours reversing this binary, tell me where I should
> spend those two hours."

That's what SnikrFlow answers.

SnikrFlow is **not** a replacement for Ghidra, IDA, Binary Ninja, or GDB. It's
the step *before* those tools: automated triage, reachability analysis, and
symbolic execution that narrows "here are thousands of functions" down to
"here are the paths you should investigate first."

```
Large ELF / Android .so
        │
        ▼
    SnikrFlow
        │
        ├── ELF analysis          ├── Call graph analysis
        ├── Function discovery    ├── Reachability
        ├── JNI discovery         ├── Data-flow analysis
        ├── Security sink detect  └── Symbolic execution
        ├── CFG analysis
        │
        ▼
  Prioritized findings
        │
        ▼
      Ghidra
        │
        ▼
  Deep manual RE
```

## Install

```bash
pip install snikrflow
```

(Or, for development: clone the repo and `pip install -e .`)

Requires Python 3.11+. Built on [angr](https://angr.io) + Claripy for the
underlying static/symbolic analysis engine.

## Quick start

```bash
# The whole pipeline, orchestrated -- this is the one you actually want
snikrflow audit libfoo.so

# Or drill in stage by stage:
snikrflow info libfoo.so                 # ELF metadata
snikrflow functions libfoo.so            # discovered functions (angr CFGFast + symbols)
snikrflow jni libfoo.so                  # statically-exported JNI entry points
snikrflow sinks libfoo.so                # security-sensitive function calls
snikrflow cfg libfoo.so                  # control-flow graph summary
snikrflow callers libfoo.so 0x400d80     # who calls this address
snikrflow callees libfoo.so 0x400d80     # what this address calls
snikrflow reach libfoo.so --source 0x403a00 --sink 0x400d80     # static reachability
snikrflow solve libfoo.so --source 0x403a00 --target 0x400d80   # symbolic candidate input
snikrflow dataflow libfoo.so --source 0x403a00 --sink 0x400d80  # does tainted data reach the sink?
```

Every command supports `--json` for scripting/piping into other tools.

## Demo

Here's SnikrFlow in action — from installation to native binary analysis.

### Installation

![SnikrFlow installation](https://raw.githubusercontent.com/Stodachon/snikrflow/main/snikrflow/demos/snikrflow-install.gif)

### Interactive terminal demo

Explore SnikrFlow's analysis workflow, including reachability, CFG analysis,
callers, callees, and other security triage commands.

**[▶ Watch the full interactive Asciinema demo](https://asciinema.org/a/n83kUR2CpK8abgDa)**

## What `audit` actually does

`audit` is the flagship command -- it runs the full pipeline automatically:

1. Discovers all functions, JNI entry points, and security-sensitive sinks.
2. Checks static (call-graph) reachability across every JNI-to-sink pair --
   cheap, so it covers everything.
3. Ranks the statically-reachable pairs by call-chain directness and picks
   the most promising few for **deep analysis**.
4. Runs data-flow (symbolic) analysis on that shortlist -- expensive, so
   it's spent only where it matters.
5. Scores risk transparently and prints ranked findings.

```
SnikrFlow Security Audit
═══════════════════════════
Binary
  Architecture: x86_64
  Type:         Shared Object
Functions
  294 discovered
  3 JNI candidates
Security-sensitive operations
  2 identified
Interesting paths
  1 statically reachable
  1 selected for data-flow analysis
Findings
  [MEDIUM] JNI -> memory
    Source: Java_..._MainActivity_init @ 0x403a00
    Sink:   strncpy @ 0x400d80  (memory)
    Status: statically_reachable
```

Risk levels are a **prioritization aid, not a vulnerability verdict**. Manual
verification is still required -- SnikrFlow narrows the search space, it
doesn't replace the researcher.

## Architecture

SnikrFlow is built in layers, deliberately kept independent from its analysis
backend:

```
CLI ──┐
      ├──> Core Engine ──> SnikrFlow Models ──> Analysis Interfaces ──> Backends
Future GUI ──┘                                                          (angr today;
                                                                     Unicorn/Pin/Dyninst
                                                                          possible later)
```

- **SnikrFlow owns the concepts** (`Function`, `SecuritySink`, `AnalysisPath`,
  `SymbolicResult`, `AnalysisFinding`, ...). The CLI never touches angr
  objects directly.
- **`analysis/interfaces/`** define *what* SnikrFlow can do.
  **`analysis/backends/angr/`** define *how* angr does it today. Adding a
  future backend means writing a new backend module, not rewriting the CLI.
- The sink signature database (`sinks/signatures.py`) is a plain, editable
  Python dict -- add your own categories/functions freely.

## Terminology (read this before trusting a finding)

SnikrFlow is deliberately precise about what different results mean --
these are never used interchangeably:

| Term | Meaning |
|---|---|
| `statically_reachable` | A direct call-graph path exists. Doesn't see indirect calls (function pointers, vtables). |
| `SAT` (solve) | A concrete candidate input exists that walks this exact path. Not a confirmed exploit. |
| `POSSIBLE` (dataflow) | Symbolic input appears to reach the sink's argument. Heuristic, not sound taint analysis. |
| Risk level (audit) | A prioritization signal. Never a confirmed vulnerability. |

## Responsible use

SnikrFlow is for authorized security research only -- use it against binaries
you own or have explicit permission to analyze.

## Roadmap

- [x] M1 -- ELF foundation (`info`, `functions`)
- [x] M2 -- Security triage (`jni`, `sinks`)
- [x] M3 -- Program structure (`cfg`, `callers`, `callees`)
- [x] M4 -- Reachability (`reach`)
- [x] M5 -- Symbolic execution (`solve`)
- [x] M6 -- Data flow (`dataflow`)
- [x] M7 -- Audit engine (`audit`)
- [x] M8 -- Android APK support (`audit app.apk`)
- [ ] M9 -- Advanced analysis (better taint tracking, caching, SARIF)
- [ ] M10 -- GUI (presentation layer over the same engine, no duplicated logic)

## Credits

Built on [angr](https://angr.io) and Claripy. CLI powered by
[Typer](https://typer.tiangolo.com) and [Rich](https://rich.readthedocs.io).

## License

SnikrFlow is licensed under the **GNU General Public License v3.0** — see [LICENSE](./LICENSE) for the full text.