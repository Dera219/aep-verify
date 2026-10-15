# Draft comments for the AEP comment round (not yet posted)

Filed through the "Technical issue" template at
https://github.com/A-Comm-Tech/a-comm-evidence-protocol/issues/new/choose.
One topic per issue, section numbers cited, as the round asks.

---

## Issue A

**Title:** [bug] §3.9.2 / §2.2 / Appendix B / vector (b): the conformance chain carries a GENERIC delegation that §3.9.2 forbids, and Appendix B's expectedArtifactCount marks it incomplete

**Affected section(s):** §3.9.2, §2.2, §5, Appendix B, vectors/v1.0.3-rc.2/b-chain.json

**Severity:** Major — implementations will diverge or carry real risk

**Description:**

I built an independent verifier from the rc.2 text and ran it against the published vectors. Vector (b) is the normative 8-artifact `ai_referral_agent_session` chain. Its artifact 4 is a delegation artifact with `protocol: "GENERIC"` and every sub-wrapper `null`.

§3.9.2 (Strengthened normative rule): "Delegation MUST be omitted when protocol = GENERIC AND no sub-wrapper is populated." The conformance vector therefore contains an artifact the specification says must not exist.

The same vector then exposes a second disagreement. Appendix B defines

```
const hasDelegation = protocol !== 'GENERIC';
case 'ai_referral_agent_session': return hasDelegation ? 8 : 7;
```

so for vector (b) `expectedArtifactCount` is 7. The chain has 8 artifacts. §5 defines `chain_complete` as `total_artifacts == expectedArtifactCount(transaction_type)`. A verifier that follows Appendix B literally reports the full-chain conformance vector as `chain_complete: false`.

The §2.2 prose reads differently: "counts may be lower when no agentic protocol is in play AND delegation is omitted." Under that reading the condition is delegation presence, not the protocol value, the expected count for vector (b) is 8, and `chain_complete` is `true`.

Two readings, two `chain_complete` results, on the published vector. #70 item 3 notes the §2.2/Appendix B wording gap as editorial; #26 and #77 argue about when delegation may appear. Neither observes that the vector breaks the §3.9.2 MUST or that Appendix B marks it incomplete.

**Proposed resolution:**

Either (1) regenerate vector (b) without the delegation artifact (7 artifacts, GENERIC) so it satisfies §3.9.2, and leave Appendix B as is; or (2) change Appendix B to take delegation presence as its argument, `expectedArtifactCount(type, hasDelegation)`, and relax §3.9.2 to "MAY be omitted" for GENERIC, so the vector stands. In both cases state in §5 which signature of `expectedArtifactCount` is normative, and add the `chain_complete` value a verifier must produce to vector (b)'s JSON so it is machine-checked.

**Security:** unchecked.

---

## Issue B

**Title:** [bug] §2.7 required field names and presence do not match Appendix B or vector (b)

**Affected section(s):** §2.7, §4.1, Appendix B, vectors/v1.0.3-rc.2/b-chain.json

**Severity:** Major — implementations will diverge or carry real risk

**Description:**

§2.7 says the following "MUST appear on every artifact in every chain, regardless of type": `seq`, `type`, `actor`, `signing_actor`, `captured_at`, `idempotency_key`, `previous_hash`, `current_hash`, plus the chain-level `chain_id`, `merchant_id`, `session_id_hash`, `spec_version` (per artifact or at bundle level).

The artifact records in vector (b) carry `sequence_number`, `artifact_type` and `actor_type` (the Appendix B names), not `seq`, `type` and `actor`. No record carries `signing_actor`, `chain_id` or `session_id_hash`, and no bundle level exists in the vector to carry them. The authorization artifact (seq 7) has no `captured_at` anywhere, only `authorized_at`. The delegation artifact's `captured_at` is nested under `payload.protocol_metadata` rather than at the payload level like every other artifact.

A verifier that enforces §2.7 as written rejects the conformance vector. A verifier that accepts the vector cannot be enforcing §2.7. §2.7 also makes `captured_at` "monotonically non-decreasing across the chain", which cannot be checked on an artifact that has no `captured_at`.

**Proposed resolution:**

Align §2.7 with Appendix B: use `sequence_number`, `artifact_type`, `actor_type`; state where `signing_actor` lives (artifact record, not hash input) or drop the MUST; add `captured_at` to the §3.6 Authorization payload (or state that `authorized_at` serves as its `captured_at`); move the delegation `captured_at` to the payload level or state the exception. Then regenerate vector (b) so that a §2.7 check passes on it.

**Security:** unchecked.

---

## Issue C

**Title:** [bug] §5 chain_complete uses equality, but §2.2 calls the counts minimums and §2.5 expects multiple fulfillment artifacts

**Affected section(s):** §5, §2.2, §2.5, §3.7

**Severity:** Minor — inconsistency or gap with a workaround

**Description:**

§5 defines `chain_complete` as `total_artifacts == expectedArtifactCount(transaction_type)`. §2.2 says "Counts are minimums for agent-mediated transactions". §2.5 says fulfillment artifacts "often arrive asynchronously after the chain is sealed (shipping events, delivery confirmations)", i.e. as more than one artifact, and the late-arrival append path has no cap.

A chain with a `shipped` and a `delivered` fulfillment artifact has nine artifacts and is `chain_complete: false` under `==`, permanently. Refund is explicitly excluded from the count (§3.10); additional fulfillment artifacts are not.

**Proposed resolution:**

Either define `chain_complete` as `total_artifacts >= expectedArtifactCount(...)` with each expected layer present at least once, or count at most one fulfillment artifact toward the total, mirroring the refund exclusion. State which.

**Security:** unchecked.

---

## Issue D (review notes, one issue, editorial)

**Title:** Verifier-implementation notes: §5 envelope status for unimplemented rules, VIC envelope enum, rule 4 base64url padding, cart_payment_binding_verified N/A

**Affected section(s):** §5, §3.9.13, §3.9.11 rule 4

**Kind:** Editorial / clarity

**Comment:**

1. §5 gives an envelope entry three statuses and three `unverifiable_reason` values, all describing the specification or the key material. A verifier that implements the chain layer but not a particular §3.9.11 rule has no honest value: `no_rule` is a false statement about the spec. A `not_supported` reason (or an explicit statement that `status: null` means "not checked by this verifier") would let partial verifiers report truthfully. The text already says omitting the entry is non-conformant, so the entry must exist.
2. `vic_payment_payload` (§3.9.13) has no value in the §5 `envelope` enum (`TAP | AP2 | MASTERCARD_VI | ACP | UCP | MCP | x402 | A2A | SKYFIRE_KYA | WEB_BOT_AUTH`).
3. §3.9.11 rule 4 says `ap2_checkout_hash` MUST equal `base64url(sha-256(ap2_checkout_jwt))` without saying whether padding is present. AP2 v0.2 uses unpadded; stating it avoids a byte mismatch.
4. `cart_payment_binding_verified` is typed boolean. When no AP2 `consumer_authorization` is present, rule 4 does not apply, and `false` reads as a failure. Allow `null` for not-applicable.
