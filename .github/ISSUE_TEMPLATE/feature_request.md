---
name: Feature request
about: Suggest a new command, flag, or capability
title: "[FEATURE] "
labels: enhancement
assignees: ''
---

**What problem does this solve?**
Describe the actual triage/RE workflow this would help with -- SnikrFlow's
goal is narrowing down where to spend manual reversing time, so it helps to
frame requests around that.

**Proposed solution**
What command/flag/output would you want? A rough example is great:
```
snikrflow newcommand --some-flag <value>
```

**Which layer does this touch?**
(See CONTRIBUTING.md if unsure) -- is this:
- [ ] A new SnikrFlow-owned model/concept
- [ ] A new analysis interface + angr backend
- [ ] A CLI/reporting change only
- [ ] A new sink signature (see CONTRIBUTING.md -- these are quick, just edit signatures.py)

**Alternatives considered**
Any other way you thought about solving this, and why this approach seems best.
