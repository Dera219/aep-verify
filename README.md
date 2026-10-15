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

## What it checks

| Area | Section | Status |
|---|---|---|
| JCS canonical form, NFC, UTF-16 key order, integer-only numbers | §4.1 | implemented, vector (h) + (a) byte-exact |
| `current_hash` recomputation, `previous_hash` links, genesis rule | §4.1, §4.2, §5 | implemented, vector (b) |
| Ed25519 `server_signature` over the raw 32-byte digest | §4.3 | implemented; vector (b) signatures verify and are reproduced from the test seed |
| Seal: `sealed_bundle_hash` = authorization `current_hash`; post-seal types only after it | §2.5 | implemented |
| Artifact order, permitted actors, transaction-type layers | §3.8, §3.9.2, §2.2 | implemented |
| Cart total integrity, integer minor units, cart/authorization amount match | §3.5 MUST-1, §3.6 MUST-1 | implemented |
| AP2 checkout-hash binding | §3.9.11 rule 4 | implemented (hash-only rule) |
| `spec_version` refusal, `merchant_id` scoping, `captured_at` monotonicity | §0.1, §2.7 | implemented |
| `chain_complete` via Appendix B `expectedArtifactCount` | §2.2, §5, Appendix B | implemented literally; see CONFORMANCE.md for why vector (b) comes out `false` |
| DisputeBundle re-verification, embedded-claim comparison, export gate | §6.1, §6.2 | implemented |
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

# canonical bytes + SHA-256 of any JSON file
aep-verify canon artifact.json
```

Exit status 0 means every check passed (or the bundle is exportable), 1 means a
check failed, 2 means the input could not be read. `--json` prints the §5
verification result; verifier extensions live under `x_aep_verify` so the
normative keys stay exactly as the schema names them.

From Python:

```python
from aep_verify import verify_chain, public_key_from_base64

result = verify_chain(artifacts, public_key_from_base64(pk),
                      transaction_type="direct_web", sealed_bundle_hash=seal)
result.valid, result.errors, result.to_dict()
```

## Tests

```bash
.venv/bin/python -m pytest -q
```

51 tests: the vectors, the canonicalizer edge cases (control characters,
non-BMP key order, NFC collisions, floats, 2**53, lone surrogates, duplicate
names), a cross-check against stock RFC 8785, the DisputeBundle gate, and
twenty-odd tamper cases. Each tamper case is a mutation of vector (b) that
must be caught: payload edits, metadata edits, edit-then-resign, a full
rechain against a stored seal, deletion, reordering, post-seal insertion,
signature bit flips, a signature over the hex string instead of the raw
digest, wrong keys, wrong seal, bad timestamps, forbidden actors, cart
arithmetic, and merchant scope.

## Licensing

Verifier code: MIT. The vendored vectors under `vectors/` are Apache-2.0,
Copyright A-Comm Technologies, Inc.; see `vectors/NOTICE.md`. The Ed25519
seed in `keys.json` is a published test key and must never be used for
anything else.
