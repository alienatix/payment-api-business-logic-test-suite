# zap-rules

Mirror of the ZAP active scan rule source, kept in sync with the pull request branch in
`zaproxy/zap-extensions` (add-on `ascanrulesAlpha`).

| Rule | Plugin ID | Source commit | Status |
| --- | --- | --- | --- |
| Payment Amount Manipulation | 40049 | `612df5645d` | Under review |

- `src/main/PaymentAmountManipulationScanRule.java`
- `src/test/PaymentAmountManipulationScanRuleUnitTest.java`
- `Messages.properties.snippet`: the `ascanalpha.paymentamount.*` keys

The upstream copy is authoritative. Re-sync this directory when the pull request changes or merges.
