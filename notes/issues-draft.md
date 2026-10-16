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

---

## Issue E

**Title:** [bug] §3.7 says `delivery_address_match` cannot be forged, but no §5 check recomputes it

**Affected section(s):** §3.7, §5

**Severity:** Major — implementations will diverge or carry real risk

**Description:**

§3.7 defines `delivery_address_match` as "MUST equal (delivery_address_hash === cart.shipping_address_hash)" and says its value "cannot be forged without breaking the hash chain upstream".

The merchant's server computes that boolean and signs the artifact. A fulfillment artifact carrying `delivery_address_match: true` beside a `delivery_address_hash` that differs from the cart's `shipping_address_hash` has a valid hash, a valid link and a valid signature. Nothing upstream breaks. The only thing that catches it is recomputing the comparison, and §5's verification table lists four checks (links, hashes, signatures, completeness), none of which does.

So the field the section calls "the single most valuable representment signal" for item-not-received disputes is, under §5 as written, exactly as strong as the signer's word. I confirmed this with an independent verifier: the re-signed lie passes all four §5 checks.

**Proposed resolution:** Add to §5 a payload-invariant check, required of verifiers, that recomputes `delivery_address_match` from the two hashes and fails the chain on a mismatch (and on `true` when either hash is null, which #65 makes possible for non-shipped fulfillment). §3.5 MUST-1 and §3.6 MUST-1 are natural companions for the same list. Then soften the §3.7 sentence to say the value is unforgeable *given* that check.

**Security:** checked. The current text overstates a guarantee a reviewer is told to rely on.

---

## Issue F

**Title:** [bug] §3.6/§8.3 Luhn gate rejects one valid numeric `network_transaction_id` in ten

**Affected section(s):** §3.6, §8.3

**Severity:** Major — implementations will diverge or carry real risk

**Description:**

§3.6 requires `network_transaction_id` on card authorizations. §3.6 and §8.3 require that an authorization payload be rejected at ingestion if it contains any 13-19 digit sequence that passes the Luhn check, and §8.3's reference code scans the serialized payload.

For any fixed length, exactly one number in ten passes Luhn: the check digit is uniform. Visa's transaction identifier is 15 characters long (CyberSource, for one, documents `networkTransactionId` as a 15-character string). Whenever such an identifier is all digits, one in ten passes Luhn, and a conformant producer must reject the artifact. The field is required, so the authorization cannot be recorded at all. (I have not confirmed from a primary Visa source how often the identifier is purely numeric; the arithmetic holds for every value that is.)

#34 (accepted for v1.0.3-final) moves network identifiers to a digest in the shared plane, which removes the conflict for the chain payload. The raw plane, and any implementation of rc.2, keeps it.

**Proposed resolution:** Exempt fields whose value is defined as a network or PSP identifier (`network_transaction_id`, `charge_id`, `payment_intent_id`, `ds_transaction_id`) from the digit-run scan, or scope the scan to fields not on an allowlist of identifier fields. State the rule in §8.3 next to the reference code so implementations agree.

**Security:** checked. The fix narrows a PCI control by field name only, not by pattern.

---

## Issue G

**Title:** [bug] the transaction type decides `chain_complete` but is not a hashed chain-level field

**Affected section(s):** §2.2, §2.7, §5, §6.1

**Severity:** Minor — inconsistency or gap with a workaround

**Description:**

§5 computes `chain_complete` against `expectedArtifactCount(transaction_type)`. §2.7's chain-level fields are `chain_id`, `merchant_id`, `session_id_hash` and `spec_version`; the transaction type is not among them and appears in no artifact. It is supplied at export time, in `transaction.transactionType`, outside every hash.

The §2.2 layer rules constrain the type (a chain with discovery cannot be `direct_web`) but do not determine it: a six-artifact GENERIC chain with referral, intent, policy, cart, authorization and fulfillment fits both `ai_referral_agent_session` (expected 7, incomplete) and `ai_referral_standard_checkout` (expected 6, complete). The exporter picks the label, and with it the answer.

**Proposed resolution:** Add `transaction_type` to the §2.7 chain-level fields carried in hashed `metadata` (the #3 disposition already moves chain-level fields there), and have verifiers read it from the chain rather than the bundle wrapper.

**Security:** unchecked.

---

## Issue H

**Title:** [bug] §3.1 says discovery is absent from most chains; Appendix B's agent-session count assumes it

**Affected section(s):** §3.1, §2.2, Appendix B

**Severity:** Minor — inconsistency or gap with a workaround

**Description:**

§3.1: discovery "can be populated only by the AI platform itself" and "is absent from most chains". Appendix B expects 7 artifacts for a GENERIC `ai_referral_agent_session` (8 with delegation), a count that includes discovery. A typical honest chain of that type (referral, intent, policy, cart, authorization, fulfillment) has 6 and reports `chain_complete: false` permanently. The same count model is behind Issue C.

**Proposed resolution:** Exclude discovery from the expected count, as refund is excluded, or define completeness per layer ("each required layer present at least once") with discovery optional.

**Security:** unchecked.

---

## Issue I

**Title:** [bug] §4.3 anchoring targets leave post-seal artifacts truncatable by the exporter

**Affected section(s):** §2.3, §2.5, §4.3, §6.1

**Severity:** Major — implementations will diverge or carry real risk

**Description:**

§4.3 recommends anchoring "the sealed chain hash (or the exported bundle hash)". The seal is the authorization artifact (§2.5), so it commits to nothing after it. An export hash is computed by the exporter after it has chosen what to export. Under either target, a fulfillment or refund artifact dropped from the tail of the chain is undetectable: the truncated export verifies, matches the anchored seal, and can be anchored itself.

§2.3 says "any insertion, deletion, or mutation is detectable at every subsequent artifact". A deleted tail has no subsequent artifact. Concretely, a chain whose last event is a `returned` fulfillment exports, minus that event, as byte-for-byte the bundle of a transaction that was delivered and kept, and its `chain_complete` goes from false to true. #16's disclosure manifest (deferred to v1.0.4) lets an honest exporter declare omissions but is written by the exporter, and #35's carrier-signed events (also deferred) prove an event exists only to someone who already knows to ask for it.

**Proposed resolution:** Add a third anchoring target to §4.3: the chain head, anchored at each post-seal append (an RFC 3161 token or log entry over the new `current_hash`). A recipient then checks that the bundle's seal and post-seal artifacts are exactly the anchored heads, in order. Alternatively, require the party that emits a post-seal event (PSP for refunds, carrier for fulfillment) to counter-sign the new head.

I implemented the first option in an independent verifier to measure it. Across 22 attacks on a worked dispute bundle, a recipient holding only the merchant's key misses 5, one holding an anchored seal misses 4, and one holding the head log misses 2 (an unsigned wrapper field, covered by #3/#16, and the transaction type, which no artifact carries). The head log does not stop a false event from being logged at the time; that still needs the event source's own signature (#35).

**Security:** checked. This is an omission attack by the exporting party, the case §4.3 exists for.
