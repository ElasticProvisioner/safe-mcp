# Isolated Validation Proof

The canonical clean-room files were copied into `validation/mock-repository` with only the generic research validator, the independently authored bundle, and minimal synthetic neighbor and mitigation records needed to exercise joins.

Strict command executed on 2026-09-01:

```text
/Users/fkautz/anaconda3/bin/python3 scripts/validate-technique-research.py SAF-T1008
```

Result: `PASS SAF-T1008` in `strict-validator-output.txt`. The executable detection fixture suite separately reports 8 of 8 passed, 2 positive and 6 negative, in `detection-test-output.json`.

The system `python3` lacked PyYAML, so the unchanged copied validator was executed with a local Python environment containing PyYAML 6.0.1. No network access, repository target artifact, or shared registry was used during validation.
