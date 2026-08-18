---
name: Feature request
about: A new analyzer, detector, protocol, or CLI improvement
labels: enhancement
---

**What problem does this solve for an analyst?** (the investigation
story, not just the feature name)

**Sketch of the behavior** — command + expected output helps a lot:

```
$ netsleuth ...
```

**Detector requests**: what benign traffic could look the same
(false-positive risk)? What evidence string should the finding show?
Which MITRE technique (if any) genuinely fits?

**Scope check** — NetSleuth is offline/defensive only: does this stay
within analyzing capture files? (see CONTRIBUTING.md ground rules)
