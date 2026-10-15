# Payment API Business-Logic Test Suite

Tests for business-logic vulnerabilities (flaws in which each request is technically valid but should be refused in context) in payment APIs, released as scan rules (automated checks) for [ZAP](https://www.zaproxy.org/).

> **Status: in development.** The tests below are being built and contributed to ZAP. Each row in the [status table](#status) is updated, with links, as work is published. Nothing here is listed as released until it actually is.

---

## Why this exists

Most API security scanners look for *malformed* requests: injection, broken input parsing, exposed data. Payment APIs fail in another way. A request can be perfectly well-formed and still be wrong in context:

- a refund for a **negative amount**, which turns a refund into a charge, or the reverse;
- a payment **amount changed** after the customer saw and approved it;
- the **same payment or refund processed twice** because the request was retried or sent twice at the same moment.

These are business-logic flaws. The OWASP Web Security Testing Guide (v4.2) says of this class: *"This type of vulnerability cannot be detected by a vulnerability scanner and relies upon the skills and creativity of the penetration tester."*

As of September 2026, ZAP's published scan rules detect payment card numbers exposed in responses. None of them tests whether a payment API rejects an altered amount or processes the same payment, reload, or refund twice when duplicate requests arrive together. This project turns those manual checks into repeatable automated tests that any team can run in ZAP, including in CI/CD pipelines.

---

## The tests

| Test | What it checks, in plain English | Applies to | OWASP API Security Top 10 (2023) | CWE |
|---|---|---|---|---|
| **Payment Amount Manipulation** | Checks whether an API accepts a monetary amount that has been altered to an invalid value, such as a negative or zero amount, instead of rejecting it. | Payments, refunds, reloads, transfers: any request carrying an amount | [API3:2023 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/) | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) |
| **Duplicate Request Processing** | Checks whether an API processes the same state-changing request more than once when it is repeated, either by not honouring an idempotency key or by accepting concurrent duplicate submissions. | Payment, refund, reload and payout submissions | [API6:2023 Unrestricted Access to Sensitive Business Flows](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/) | [CWE-837](https://cwe.mitre.org/data/definitions/837.html) |

### Payment Amount Manipulation: how it works

- **Targets** only parameters whose name looks like money (`amount`, `total`, `price`, `fee`, `refund`, `reload`, `charge`, and compounds such as `refundAmount` or `order_total`) **and** whose original value is a number. Every other parameter is skipped without sending a request.
- **Sends** altered amounts. The set grows with ZAP's attack strength:
  - Low: negative and zero.
  - Medium: adds excess precision (`10.00` → `10.00001`) and very large values.
  - High: adds numeric-string variants (`1e3`, `+10`) and whitespace padding.
- **Alerts** only when the altered request succeeds (2xx) **and** the API either reflects the altered amount or creates or updates a resource that the original request did not. Rejections (4xx/5xx) never alert.
- **Risk:** High when a negative amount is accepted, Medium otherwise.

### Duplicate Request Processing: how it works

- **Targets** only `POST`, `PUT` and `PATCH` requests that carry a money parameter or hit a payment path (`/payments`, `/charges`, `/refunds`, `/reloads`, `/transfers`, `/payouts`, `/topup`).
- **Idempotency-key mode** (when the request carries an `Idempotency-Key` header or a configured equivalent) resends the identical request with the same key. It alerts if the second response succeeds but describes a different result.
- **Concurrent mode** (no idempotency header) sends N identical copies at once (default 3). It alerts, at Low confidence, if all succeed and return N different transaction identifiers.
- The header name, N, and a "money parameter required" toggle are configurable.

---

## ⚠️ Use only where you are authorized

These tests send **real state-changing requests**: altered amounts and duplicate submissions. Against a live system they can create real payments, refunds or balance changes.

- Run them only against systems you own or are explicitly authorized to test.
- Use a test or sandbox environment with test credentials and test funds, never production.
- Start at Low attack strength.

---

## Repository layout

```
zap-rules/          Source of the ZAP scan rules, mirrored from the pull requests to zaproxy/zap-extensions
zap-scripts/        Active-scan script version of the amount test, usable in any current ZAP without installing an add-on
mock-payment-api/   A small, deliberately vulnerable payment API (Docker) to try the tests against safely
docs/               Mapping notes and how to run the tests in CI/CD with ZAP's Docker images
```

## Quick start

*Instructions will be added here when the first test is published. They will cover running the mock payment API with Docker Compose and scanning it with ZAP's Docker image.*

---

## Status

| Item | State | Link |
|---|---|---|
| Design issue in `zaproxy/zaproxy` | Planned | — |
| Payment Amount Manipulation scan rule (PR to `zaproxy/zap-extensions`, alpha add-on) | In development | — |
| Duplicate Request Processing scan rule (PR to `zaproxy/zap-extensions`, alpha add-on) | In development | — |
| Script version of the amount test (`zaproxy/community-scripts`) | Planned | — |
| Mock payment API | In development | — |

**About ZAP distribution.** New ZAP scan rules start in the *alpha* active-scan add-on. Alpha rules are installed from the ZAP Marketplace, or with the `-a` option in ZAP's packaged Docker scans. They are **not** part of ZAP's default scans until the ZAP team promotes them to beta or release.

---

## Related proposals to the OWASP API Security Top 10

The payment-specific risks behind these tests have been submitted as proposals for future editions of the OWASP API Security Top 10:

- [OWASP/API-Security #179](https://github.com/OWASP/API-Security/issues/179)
- [OWASP/API-Security #180](https://github.com/OWASP/API-Security/issues/180)

---

## Contributing

Issues and pull requests are welcome, especially reports of false positives or false negatives against real payment API patterns (with sensitive details removed). Please sign off your commits (`git commit -s`), following the [Developer Certificate of Origin](https://developercertificate.org/), which ZAP also uses.

## License

[Apache License 2.0](LICENSE), the same license as ZAP's add-ons.
