# Mock payment API

**Insecure by design. Never expose it beyond localhost.** It exists only as a local target for the
scan rules in this repository. It binds to `127.0.0.1` by default.

Endpoints: `POST /payments`, `POST /refunds`, `POST /reloads` with a JSON body such as
`{"amount": "10.00"}`.

| Environment flag          | When `true`                                              |
|---------------------------|----------------------------------------------------------|
| `ACCEPT_NEGATIVE_AMOUNT`  | zero and negative amounts are accepted                   |
| `ACCEPT_EXCESS_PRECISION` | amounts with more than 2 decimal places are accepted     |
| `ACCEPT_HUGE_AMOUNT`      | amounts above 1,000,000 are accepted                     |
| `IGNORE_IDEMPOTENCY_KEY`  | the `Idempotency-Key` header is ignored                  |
| `NO_DUPLICATE_PROTECTION` | identical requests without a key are all processed       |
| `ERROR_IN_BODY`           | non-positive, over-precise and too-large amounts get HTTP 200 with `{"error": ..., "amount": ...}` instead of 400; unparsable amounts still get 400 |

All flags default to `false` (the secure behaviour).

```
python app.py                                   # secure
ACCEPT_NEGATIVE_AMOUNT=true python app.py       # one vulnerability on
docker compose up --build                       # all vulnerabilities on
```
