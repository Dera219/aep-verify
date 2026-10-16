# aep-verify

An independent, from-the-text verifier for the
[A-Comm Evidence Protocol](https://github.com/A-Comm-Tech/a-comm-evidence-protocol)
(AEP) draft v1.0.3-rc.2: the hash chain, the Ed25519 seal, the structural
MUSTs a verifier can check without third-party keys, and the §6.2
DisputeBundle export gate. It was written against the specification text and
then run against the published §6.3 conformance vectors. Every vector outcome,
and every place where the draft and the vectors disagree, is recorded in
[CONFORMANCE.md](CONFORMANCE.md).

It is not the reference implementation and shares no code with it. That is
the point: two implementations built from the same prose should produce the
same bytes, and where they cannot, the prose needs fixing.

Since 0.2.0 it also **produces** evidence: a chain builder that refuses any
artifact the text forbids, a §6.1 exporter that derives the bundle wrapper from
the chain, and `aep-verify demo`, a worked dispute that attacks its own export
22 ways and reports which attacks any verifier can catch, which only this one
does, and which none can. The answer to the last question is the most useful
thing here: see [What a DisputeBundle proves](#what-a-disputebundle-proves).

## What it checks

| Area | Section | Status |
|---|---|---|
| JCS canonical form, NFC, UTF-16 key order, integer-only numbers | §4.1 | implemented, vector (h) + (a) byte-exact |
| `current_hash` recomputation, `previous_hash` links, genesis rule | §4.1, §4.2, §5 | implemented, vector (b) |
| Ed25519 `server_signature` over the raw 32-byte digest | §4.3 | implemented; vector (b) signatures verify and are reproduced from the test seed |
| Seal: `sealed_bundle_hash` = authorization `current_hash`; post-seal types only after it | §2.5 | implemented |
| Artifact order, permitted actors, transaction-type layers | §3.8, §3.9.2, §2.2 | implemented |
| Cart total integrity, integer minor units, cart/authorization amount match | §3.5 MUST-1, §3.6 MUST-1 | implemented |
| `delivery_address_match` recomputed from the two address hashes | §3.7 | implemented; §5 does not list this step, see CONFORMANCE.md |
| Unsigned copies (`canonical_json`, record-level `artifact_type`) agree with the signed hash input | §4.1 | implemented |
| AP2 checkout-hash binding | §3.9.11 rule 4 | implemented (hash-only rule) |
| `spec_version` refusal, `merchant_id` scoping, `captured_at` monotonicity | §0.1, §2.7 | implemented |
| `chain_complete` via Appendix B `expectedArtifactCount` | §2.2, §5, Appendix B | implemented literally; see CONFORMANCE.md for why vector (b) comes out `false` |
| DisputeBundle re-verification, embedded-claim comparison, export gate | §6.1, §6.2 | implemented |
| Wrapper cross-checks: `totalValue`, `currency`, `evidenceTier`, envelope list, channel, dates | §6.1 | implemented as an **extension**: §6.1 binds no wrapper field, so a contradiction is refused by this verifier, not by the text |
| Seal against an independently anchored value (`--anchored-seal`) | §4.3 | the comparison is implemented; verifying the anchor itself (RFC 3161 token, log proof) is the caller's job |
| Seal and every post-seal artifact against an append-time head log (`--anchored-heads`) | none | **proposal**, not in v1.0.3-rc.2: the mechanism draft Issue I suggests, implemented so its effect can be measured |
| Hostile input: wrong JSON types, 10,000-deep nesting, multi-megabyte strings | n/a | refused, never crashed: 24,000 fuzzed bundles and events, nesting capped at 128 levels, every echoed value bounded |
| Protocol envelope verification (TAP, AP2 signatures, x402, Mastercard VI, KYA, Web Bot Auth, ...) | §3.9.11 rules 1-3, 5-12 | **not implemented**: needs live/witnessed keys and reference envelopes; no vectors published |
| Evidence tier above D | §3.9.12 | not computed when any sub-wrapper is present (depends on the above) |
| Key publication, rotation, revocation lookups | §4.3 | not implemented; the caller supplies the public key |

## Install

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

Runtime dependency: `cryptography` (Ed25519). `rfc8785` is a dev-only
cross-check for the canonicalizer. Python 3.12+.

## Use

```bash
# the published conformance vectors (vendored under vectors/)
aep-verify vectors

# an artifact sequence (vector (b) shape, or flat records) against a public key
aep-verify chain chain.json --key keys.json --transaction-type ai_referral_agent_session

# a DisputeBundle: re-verifies the chain, compares the embedded verification
# object to the recomputed one, and applies the §6.2 export gate
aep-verify bundle bundle.json --key <base64 Ed25519 public key> --merchant-id acct_123

# the same, also requiring the seal to equal one the recipient holds from an
# independent §4.3 existence anchor
aep-verify bundle bundle.json --key <key> --anchored-seal sha256:<64 hex>

# proposed, not in the draft: also require the seal and every post-seal artifact
# to match an append-time head log (a file of hashes, one per line)
aep-verify bundle bundle.json --key <key> --anchored-heads heads.txt

# canonical bytes + SHA-256 of any JSON file
aep-verify canon artifact.json

# produce, export and attack a worked dispute; writes REPORT.md and every bundle
aep-verify demo --out aep-demo
```

Exit status 0 means every check passed (or the bundle is exportable), 1 means a
check failed, 2 means the input could not be read. `--json` prints the §5
verification result; verifier extensions live under `x_aep_verify` so the
normative keys stay exactly as the schema names them.

From Python:

```python
from aep_verify import verify_chain, public_key_from_base64

result = verify_chain(
    artifacts, public_key_from_base64(pk), transaction_type="direct_web", sealed_bundle_hash=seal
)
result.valid, result.errors, result.to_dict()
```

## Produce

```python
from aep_verify import ChainBuilder, export_dispute_bundle

chain = ChainBuilder(
    transaction_type="direct_web",
    chain_id="c1",
    merchant_id="m1",
    session_id_hash=session_hmac,
    signing_key=merchant_key,
)
chain.append(
    "intent",
    actor_type="agent",
    actor_id="agent:shop",
    interaction_channel="text_chat",
    timestamp="2026-09-14T15:05:12Z",
    payload={...},
)  # raises ProducerError if non-conformant
...
bundle = export_dispute_bundle(
    chain.records,
    merchant_key.public_key(),
    transaction_id="t1",
    transaction_type="direct_web",
    status="disputed",
    merchant_name="Example",
    exported_at="2026-10-21T14:00:00Z",
)
```

`append` checks the artifact against its own section (required fields, enums,
cart arithmetic, the §3.6 card-representment set, the §3.6/§8.3 Luhn gate on
authorization payloads) and against the chain so far (order, the seal, permitted
actors, timestamps, the authorization settling the cart, the §3.7 address
match, refunds bounded by the charge), then hashes and signs it. Appends are
idempotent on `idempotency_key` (§8.4). Delegation is refused: its envelopes are
signed by third parties with keys a merchant does not hold. Every rule names its
section, and the few places the producer is stricter than the text say so in
`aep_verify/produce.py`.

`export_dispute_bundle` re-verifies first and refuses to export an invalid chain
for submission (§6.2). It derives `totalValue`, `currency`,
`interactionChannel`, the dates, the seal and the tier from the chain, so the
wrapper cannot contradict the evidence, and it never asserts `customerHistory`.

## What a DisputeBundle proves

`aep-verify demo` builds one AI-referred $55.00 purchase, exports it, and runs
22 attacks against copies of the export. Three recipients re-verify each one:

| recipient | refused | flagged | undetected |
|---|---|---|---|
| merchant's key only (all v1.0.3-rc.2 assumes) | 15 | 2 | 5 |
| key + a §4.3 anchored seal | 16 | 2 | 4 |
| key + an append-time head log (proposed, draft Issue I) | 18 | 2 | 2 |

What the five attacks the key alone misses show about v1.0.3-rc.2, for any
verifier:

- **A signature is not a timestamp.** The merchant holds the key and can
  rebuild its own chain (here, upgrading a 3DS result to `authenticated`). §4.3
  says so itself; an externally anchored seal catches it.
- **Nothing commits to the end of the chain.** The seal stops at
  authorization, so a returned-shipment event can be cut from the tail.
  Neither anchoring target §4.3 names (the seal, the export hash) closes this,
  and the cut *raises* `chain_complete`. A head log written as each event
  arrives does close it.
- **`delivered` is the merchant's word.** Fulfillment is signed by the
  merchant's server, and the payload has no field for a carrier signature
  (upstream #35 defers carrier-signed events to v1.0.4). A head log stops
  after-the-fact rewrites, not a false event logged at the time.
- **The transaction type is unbound.** No artifact records it, yet it alone
  sets the expected count, so relabelling it makes an incomplete chain
  complete.
- **The wrapper is unsigned** (`transaction.id`, `status`, `merchantName`,
  `exportedAt`, `customerHistory`; upstream #3 and #16).

Two of the forgeries are byte-identical to the honest export, so no verifier
that reads only the bundle will ever tell them apart; only evidence from
outside it can, and the head log is such evidence. The two attacks that
survive everything are the unsigned wrapper (upstream #3, #16) and the unbound
transaction type (draft Issue G). `REPORT.md` in the demo output has the full
table, the exact verifier messages, and file digests; the run is deterministic
and is itself a test (`tests/test_demo.py`).

## Tests

```bash
.venv/bin/python -m pytest -q      # 250 tests
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/python -m mypy           # strict
```

250 tests: the vectors, the canonicalizer edge cases (control characters,
non-BMP key order, NFC collisions, floats, 2**53, lone surrogates, duplicate
names, nesting depth), a cross-check against stock RFC 8785, the DisputeBundle
gate, wrapper cross-checks, anchored seal and head log (39), 30 tamper cases on
vector (b), 52 producer tests, 43 hostile-input tests including a seeded
structural fuzz, and the 22-attack demo with every outcome pinned (37). Each
tamper case is a mutation of vector (b) that must be caught: payload edits,
metadata edits, edit-then-resign, a full rechain against a stored seal,
deletion, reordering, post-seal insertion, signature bit flips, a signature over
the hex string instead of the raw digest, wrong keys, wrong seal, bad
timestamps, forbidden actors, cart arithmetic, merchant scope, a re-signed
address-match lie, and unsigned copies that disagree with the signed content.
The guards added in 0.2.0 were mutation-tested: 50 of them were broken one at
a time, and the suite failed every time.

## Licensing

Verifier code: MIT. The vendored vectors under `vectors/` are Apache-2.0,
Copyright A-Comm Technologies, Inc.; see `vectors/NOTICE.md`. The Ed25519
seed in `keys.json` is a published test key and must never be used for
anything else. The demo's keys and salt are derived from public labels in
`aep_verify/demo.py`; they sign demo evidence and nothing else.
