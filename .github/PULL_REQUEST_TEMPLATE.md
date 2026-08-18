## What & why

<!-- One paragraph: what changes and the investigation problem it solves. -->

## Detector/analyzer checklist (delete if not applicable)

- [ ] Positive test: fires on synthetic attack-shaped traffic
- [ ] Negative test: benign traffic stays quiet
- [ ] Evidence strings show concrete numbers
- [ ] Wireshark filter attached to findings
- [ ] Explanation names the benign look-alikes
- [ ] MITRE mapping only where justified (why-field filled)

## Security checklist

- [ ] New code treats capture data as hostile (names, sizes, encodings)
- [ ] No new hard dependency (or DESIGN.md entry justifying it)
- [ ] No network activity added; no execution of capture-derived data
- [ ] Report output (if any) escapes capture-derived values

## Verification

- [ ] `python -m pytest` passes (all tests)
- [ ] Docs updated (`docs/`, README feature table if user-visible)
