# Conformance record: aep-verify 0.1.0 against AEP v1.0.3-rc.2

Run on 2026-10-15 with `aep-verify vectors` against the vectors vendored under
`vectors/v1.0.3-rc.2/` (upstream commit `fd5174e`, published 2026-07-06; spec
HTML at upstream commit `2b54cc9`, 2026-10-13). The verifier was written from
the specification text before any vector was executed.

## Published vectors

| Vector | Checks | Result |
|---|---|---|
| keys.json | public key derived from the published seed equals `public_key_base64` | PASS |
| (h) `nfc-composed-vs-decomposed` | composed and decomposed inputs give identical bytes and the expected SHA-256 | PASS |
| (h) `key-order-utf16-code-units` | `A,B,a,b` order, bytes and hash | PASS |
| (h) `integer-representation` | bytes and hash | PASS |
| (h) `strings-verbatim` | bytes and hash | PASS |
| (h) `nested-sorting` | bytes and hash | PASS |
| (a) genesis | canonical bytes equal `canonical_json`; length 482; SHA-256 equals `expected_sha256` | PASS (byte-for-byte) |
| (b) artifacts 1-8 | canonical bytes, `current_hash`, `previous_hash` link, Ed25519 signature verifies against the published key, signature reproduced exactly by re-signing with the seed | PASS, all 40 checks |
| (b) seal | `sealed_bundle_hash` equals the authorization artifact's `current_hash` (§2.5) | PASS |
| (b) `verify_chain` | `valid`, `hash_chain_intact`, `signatures_valid`, `artifacts_verified == 8`, `seal_valid` | PASS |

55 checks, 0 failures. The conformance gate of §6.3 (vector (a) byte-for-byte)
is met.

Not exercised because not published: (c) signed DisputeBundle, (d)-(g) and
(i)-(m) protocol-wrapper vectors. The bundle logic in `aep_verify/bundle.py` is
tested only against a bundle synthesized from vector (b) (`tests/test_bundle.py`).

Negative controls: `tests/test_tamper.py` mutates vector (b) twenty-two ways
(payload and metadata edits, edit-then-resign, full rechain against a stored
seal, deletion, reordering, post-seal insertion, signature bit flip, signature
over the hex string instead of the raw digest, missing signature, wrong key,
wrong seal, timestamp precision, non-monotonic `captured_at`, forbidden actor,
wrong transaction-type layer, cart arithmetic, non-integer money, extra
hash-input field, merchant scope). Every mutation is caught.

## Where the draft and the vectors disagree

Each item says whether it is already in the upstream comment round.

### 1. Vector (b) carries a delegation artifact that §3.9.2 says MUST be omitted, and Appendix B then reports the chain incomplete

Vector (b) is the normative 8-artifact `ai_referral_agent_session` chain. Its
artifact 4 is a delegation with `protocol: "GENERIC"` and every sub-wrapper
`null`. §3.9.2: "Delegation MUST be omitted when protocol = GENERIC AND no
sub-wrapper is populated." The conformance chain therefore violates a MUST.

Appendix B's `expectedArtifactCount(type, protocol)` infers delegation from
`protocol !== 'GENERIC'`, so for vector (b) it returns 7. The chain has 8
artifacts. §5 computes `chain_complete` as `total_artifacts ==
expectedArtifactCount(...)`, so a verifier that follows Appendix B literally
reports the official full-chain vector as `chain_complete: false`. Counting by
delegation presence (the §2.2 prose: "counts may be lower when ... delegation
is omitted") gives 8 and `true`. Two readings, two answers, on the published
vector. This verifier follows Appendix B and emits a warning naming the other
reading.

Status: not filed. Issue #70 item 3 notes the §2.2/Appendix B wording gap as
editorial; #26 and #77 argue about when delegation may be present. None
observes that vector (b) itself breaks the MUST or that Appendix B marks it
incomplete. Draft in `notes/issues-draft.md`.

### 2. §2.7 required fields do not match Appendix B or the vectors

§2.7 says every artifact MUST carry `seq`, `type`, `actor`, `signing_actor`,
`captured_at` (per-artifact), plus the chain-level fields. Vector (b) records
carry `sequence_number`, `artifact_type`, `actor_type`; no `signing_actor`,
`chain_id` or `session_id_hash` anywhere; the authorization artifact has no
`captured_at` at all (only `authorized_at`); the delegation artifact's
`captured_at` sits inside `payload.protocol_metadata`. A verifier that
enforces §2.7 as written rejects the conformance vector. This verifier checks
`captured_at` monotonicity where the field exists and warns where it is
absent.

Status: not filed as such. #3 covers the integrity of the chain-level fields,
not their names or presence. Draft in `notes/issues-draft.md`.

### 3. `chain_complete` tests equality, but the counts are called minimums and fulfillment arrives in multiples

§5: `total_artifacts == expectedArtifactCount(transaction_type)`. §2.2: "Counts
are minimums". §2.5 expects fulfillment artifacts to arrive as multiple events
("shipping events, delivery confirmations"). A chain with a shipped and a
delivered fulfillment artifact has 9 artifacts and is `chain_complete: false`
forever under `==`. This verifier implements `==` as written.

Status: not found in the issue list. Draft in `notes/issues-draft.md`.

### 4. §4.1 says "code point", RFC 8785 and vector (h) say UTF-16 code unit

Already filed as #17 (open). This verifier sorts by UTF-16 code unit and has a
test for the non-BMP case (`tests/test_canonical.py::test_utf16_order_differs_from_code_point_order`).

### 5. Chain-level fields are hashed via `metadata` in the vectors but excluded from the hash input in the text

Already filed as #3 (open). Confirmed here: editing `metadata.merchant_id` in
vector (b) breaks `current_hash` (`tests/test_tamper.py::test_metadata_edit_is_hashed_too`).

## Smaller observations (recorded, not filed)

- §5 envelope status has no value for "a rule exists but this verifier does
  not implement it". `unverifiable` with reason `no_rule` would be a false
  statement about the specification. This verifier emits `status: null`
  (schema-permitted, semantics undefined) with a note under
  `x_aep_verify_note`. A `not_supported` reason would let partial verifiers
  report honestly.
- `vic_payment_payload` (§3.9.13) has no value in the §5 `envelope` enum.
  Reported here as `VIC` with a warning.
- §3.9.11 rule 4 does not say whether `ap2_checkout_hash` is padded base64url.
  This verifier compares with padding stripped on both sides.
- `cart_payment_binding_verified` is a boolean with no "not applicable" value.
  This verifier emits `null` when AP2 `consumer_authorization` is absent.
- `interaction_channel`: §2.4 says it is null for non-agent actors, but vector
  (b) sets `text_chat` on the user-actor referral and cart artifacts. This
  verifier only enum-checks the field.
- The §6.1 `EhcArtifactRecord` type is never defined. This verifier accepts the
  vector (b) record shape and a flat shape with the eight hash-input fields at
  the top level.

## What this verifier does not do

- §3.9.11 rules 1-3 and 5-12 (TAP, AP2 signatures, A2A, UCP, ACP, MCP, x402
  signer recovery, Mastercard VI, Skyfire KYA, Web Bot Auth, request_binding).
  No vectors exist for them yet; they need live or witnessed keys.
- Evidence tier above D (§3.9.12), which depends on the above.
- Key discovery, rotation overlap, revocation statements (§4.3). The caller
  supplies the key.
- External anchoring checks (RFC 3161, transparency logs).
- Cross-chain `customerHistory` (§6.1), network renderers (§6.4).
