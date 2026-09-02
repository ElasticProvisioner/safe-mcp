# SAF-T1704 clean-room integration notes

This bundle is a frozen, standalone clean-room artifact. It has not been reconciled with or integrated into the target repository.

The following values exist only to satisfy isolated referential-integrity validation and must be reconciled by a maintainer after the freeze without changing the archived bundle:

- `SAF-T9991` is a synthetic neighbor labeled “Server-Originated Instruction Manipulation.”
- `SAF-T9992` is a synthetic neighbor labeled “Server/Client Session Hijacking.”
- `1704170417041704170417041704170417041704` is a synthetic bundle-baseline history token, not a target Git commit.
- The included `research/source-manifest.yml`, `research/framework-model.yml`, and `research/alignment-ledger.yml` are isolated fragments, not copies of shared target registries.
- No mitigation joins are asserted; the README states controls directly and leaves framework mitigation reconciliation to maintainers.

Validation used a synthetic mock repository containing only this bundle, the generic validator, and two minimal neighbor stubs. No existing target technique, target research packet, target test, shared registry, catalog, history, issue, pull request, or SAF website was inspected before freeze.

## Post-freeze canonical reconciliation

After the immutable bundle freeze, the synthetic neighbors were mechanically joined to SAF-T1001 and SAF-T1004. SAF-T1703 was added as the broader cross-tool overlap. The canonical framework joins ten mitigations, analogous ATT&CK T1210, repository paths, source IDs, baseline commit `26c39823e0b55144bc7891f6345e6030646c16a0`, and checked-in detector and strict-validation transcripts. These integration-only changes do not alter the frozen research evidence.
