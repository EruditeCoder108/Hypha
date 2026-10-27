# Dated custody repair evidence summary

The 25 October 2026 engineering run recorded 124 passing normal Android tests in 24 suites, including 13 focused reliability tests. ESP host cases comprised seven repaired regressions, two controls, and three explicitly open observations; firmware compilation passed.

The opt-in Android lost-ACK probe still failed: an initial allowance of eight became twelve. ESP expiry and pressure-victim policy remained open. These results are dated engineering evidence, not fresh phone or radio acceptance.

Private raw logs and device captures are intentionally excluded. The corresponding source tests and [audit tools](../../tools/audit/README.md) are included so contributors can rerun them. See [the repair report](../../docs/CUSTODY_REPAIR_2026-10-25.md).
