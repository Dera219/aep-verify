"""DisputeBundle re-verification and the §6.2 export gate.

A §6.1 bundle is two things: the artifact chain, which every artifact's hash and signature
protect, and a wrapper (transaction, merchantContext, evidenceTier, customerHistory, ...)
that no signature covers. The draft defines no export hash or exporter signature; the comment
round scopes that work under upstream issue #16. Until it lands, a recipient reads a wrapper
the evidence does not bind.

So, beyond the §6.2 gate, this module cross-checks every wrapper value the chain determines
(the total, the currency, the evidence tier, the envelope list, the channel, the dates) and
refuses to certify a bundle whose summary contradicts its own sealed evidence. That refusal is
an aep-verify extension, labeled as one. What cannot be checked against anything is reported
as unbound, by name, in `wrapper_binding`.
"""

from __future__ import annotations

import hmac
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .chain import (
    HASH_RE,
    ArtifactRecord,
    ChainFormatError,
    VerificationResult,
    show,
    verify_chain,
)
from .summary import interaction_channel_of, major_to_minor, minor_unit_exponent

# §6.1 camelCase member -> §5 snake_case field.
_EMBEDDED_FIELDS: tuple[tuple[str, str], ...] = (
    ("valid", "valid"),
    ("hashChainIntact", "hash_chain_intact"),
    ("signaturesValid", "signatures_valid"),
    ("chainComplete", "chain_complete"),
    ("artifactsVerified", "artifacts_verified"),
    ("specVersion", "spec_version"),
    ("evidenceTier", "evidence_tier"),
)

# How far a recipient can trust each §6.1 wrapper member, as this verifier checks it.
CHAIN_BOUND = "chain-bound"
CROSS_CHECKED = "cross-checked"
UNBOUND = "unbound"
WRAPPER_BINDING: dict[str, tuple[str, str]] = {
    "transaction.sealedBundleHash": (
        CHAIN_BOUND,
        "must equal the authorization artifact's current_hash (§2.5)",
    ),
    "transaction.transactionType": (
        CROSS_CHECKED,
        "constrains which layers may appear (§2.2), but no artifact carries it (§2.7), and "
        "more than one type can fit a chain; it alone decides chain_complete",
    ),
    "merchantContext.merchantId": (
        CHAIN_BOUND,
        "every artifact's hashed metadata.merchant_id must match it (§2.7)",
    ),
    "verification": (CHAIN_BOUND, "recomputed by full re-verification and compared (§6.2)"),
    "merchantContext.totalValue": (CROSS_CHECKED, "must equal the sealed cart total"),
    "merchantContext.currency": (CROSS_CHECKED, "must equal the sealed cart currency"),
    "evidenceTier": (CROSS_CHECKED, "must equal the recomputed evidence tier"),
    "protocolEnvelopesVerified": (
        CROSS_CHECKED,
        "must list exactly the envelopes the chain carries",
    ),
    "transaction.interactionChannel": (
        CROSS_CHECKED,
        "compared with the artifacts' channels (warning only: §6.1 defines no derivation)",
    ),
    "transaction.createdAt": (
        CROSS_CHECKED,
        "must not postdate the first artifact (warning only)",
    ),
    "transaction.completedAt": (
        CROSS_CHECKED,
        "must not predate the seal, and needs a delivered fulfillment (warning only)",
    ),
    "transaction.id": (UNBOUND, "no artifact carries it"),
    "transaction.status": (UNBOUND, "free text; no artifact carries it"),
    "merchantContext.merchantName": (UNBOUND, "no artifact carries it"),
    "customerHistory": (
        UNBOUND,
        "computed across chains and not hash-chained (§6.1); open upstream issue #16",
    ),
    "exportedAt": (UNBOUND, "no export hash or exporter signature exists (upstream #3, #16)"),
}


class BundleFormatError(ValueError):
    """The input is not a DisputeBundle at all."""


@dataclass
class BundleVerification:
    verification: VerificationResult
    exportable: bool
    gate_reasons: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    embedded_disagreements: list[str] = field(default_factory=list)
    wrapper_contradictions: list[str] = field(default_factory=list)
    anchor_matches: bool | None = None
    heads_match: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "exportable": self.exportable,
            "gate_reasons": list(self.gate_reasons),
            "bundle_errors": list(self.errors),
            "bundle_warnings": list(self.warnings),
            "embedded_disagreements": list(self.embedded_disagreements),
            "wrapper_contradictions": list(self.wrapper_contradictions),
            "anchor_matches": self.anchor_matches,
            "heads_match": self.heads_match,
            "wrapper_binding": {
                member: {"binding": binding, "basis": basis}
                for member, (binding, basis) in WRAPPER_BINDING.items()
            },
            "verification": self.verification.to_dict(),
        }


def _instant(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo is not None else None


def _cross_check_wrapper(
    bundle: dict[str, Any],
    transaction: dict[str, Any],
    records: list[ArtifactRecord],
    verification: VerificationResult,
) -> tuple[list[str], list[str]]:
    """Wrapper values the sealed chain determines, checked against it. (contradictions, warnings)

    An aep-verify extension: §6.1/§6.2 bind none of these. A contradiction is a statement in the
    bundle's own summary that its sealed evidence refutes, such as a total the customer was never
    charged, and this verifier will not certify a bundle that makes one.
    """
    contradictions: list[str] = []
    warnings: list[str] = []
    cart = next((r for r in records if r.artifact_type == "cart"), None)
    cart_total = cart.payload.get("total") if cart else None
    cart_currency = cart.payload.get("currency") if cart else None

    context = bundle.get("merchantContext")
    context = context if isinstance(context, dict) else {}
    claimed_currency = context.get("currency")
    if claimed_currency is not None and cart is not None and claimed_currency != cart_currency:
        contradictions.append(
            f"merchantContext.currency {show(claimed_currency)} but the sealed cart is in "
            f"{show(cart_currency)}"
        )
    claimed_total = context.get("totalValue")
    if claimed_total is not None:
        currency = cart_currency if cart is not None else claimed_currency
        if cart is None:
            warnings.append("merchantContext.totalValue present but the chain has no cart to check")
        elif minor_unit_exponent(currency) is None:
            warnings.append(
                f"merchantContext.totalValue not checked: minor-unit exponent of {show(currency)} "
                "is not in this verifier's ISO 4217 table"
            )
        else:
            minor = major_to_minor(claimed_total, currency)
            if minor is None:
                contradictions.append(
                    f"merchantContext.totalValue {show(claimed_total)} is not an exact {currency} "
                    "amount"
                )
            elif minor != cart_total:
                contradictions.append(
                    f"merchantContext.totalValue {show(claimed_total)} {currency} is {minor} minor "
                    f"units, but the sealed cart total is {cart_total}"
                )

    recomputed_tier = verification.evidence_tier
    claimed_tier = bundle.get("evidenceTier")
    if claimed_tier is not None:
        if recomputed_tier is None:
            warnings.append(
                f"evidenceTier {show(claimed_tier)} cannot be recomputed: the chain's protocol "
                "envelopes were not verified (§3.9.11 not implemented)"
            )
        elif claimed_tier != recomputed_tier:
            contradictions.append(
                f"evidenceTier {show(claimed_tier)} but the chain recomputes to "
                f"{show(recomputed_tier)}"
            )

    claimed_envelopes = bundle.get("protocolEnvelopesVerified")
    if isinstance(claimed_envelopes, list):
        claimed_names = sorted(
            e["envelope"]
            if isinstance(e, dict) and isinstance(e.get("envelope"), str)
            else show(e, 40)
            for e in claimed_envelopes
        )
        actual_names = sorted(str(e["envelope"]) for e in verification.protocol_envelopes_verified)
        if claimed_names != actual_names:
            contradictions.append(
                f"protocolEnvelopesVerified lists {show(claimed_names)}, but the chain carries "
                f"{show(actual_names)}"
            )
        for entry in claimed_envelopes:
            if isinstance(entry, dict) and (
                entry.get("verified") is True or entry.get("status") == "verified"
            ):
                warnings.append(
                    f"protocolEnvelopesVerified claims {show(entry.get('envelope'))} verified; "
                    "this verifier does not verify envelopes (§3.9.11), so the claim is "
                    "unconfirmed"
                )

    claimed_channel = transaction.get("interactionChannel")
    derived_channel = interaction_channel_of([r.hash_input for r in records])
    if "interactionChannel" in transaction and claimed_channel != derived_channel:
        warnings.append(
            f"transaction.interactionChannel {show(claimed_channel)} but the artifacts' channels "
            f"imply {show(derived_channel)}"
        )

    first_ts = _instant(records[0].hash_input.get("timestamp")) if records else None
    created = _instant(transaction.get("createdAt"))
    if created is not None and first_ts is not None and created > first_ts:
        warnings.append("transaction.createdAt postdates the first artifact")
    seal_record = next((r for r in records if r.artifact_type == "authorization"), None)
    seal_ts = _instant(seal_record.hash_input.get("timestamp")) if seal_record else None
    completed = _instant(transaction.get("completedAt"))
    if completed is not None and seal_ts is not None and completed < seal_ts:
        warnings.append("transaction.completedAt predates the authorization seal")
    delivered = any(
        r.artifact_type == "fulfillment" and r.payload.get("status") == "delivered" for r in records
    )
    if completed is not None and not delivered:
        warnings.append("transaction.completedAt is set but no fulfillment artifact says delivered")

    if bundle.get("customerHistory") is not None:
        warnings.append(
            "customerHistory is present but not hash-chained (§6.1): its prior transactions, "
            "dispute and refund counts cannot be verified by a recipient (upstream #16)"
        )
    return contradictions, warnings


def _compare_heads(records: list[ArtifactRecord], log: list[str]) -> str | None:
    """None when the seal and every post-seal artifact are exactly the logged heads."""
    seal_at = next((i for i, r in enumerate(records) if r.artifact_type == "authorization"), None)
    if seal_at is None:
        return "the chain has no authorization artifact, so nothing matches the head log"
    heads = [r.current_hash for r in records[seal_at:]]
    if heads == log:
        return None
    if heads == log[: len(heads)]:
        missing = len(log) - len(heads)
        return (
            f"the bundle ends {missing} anchored post-seal event(s) early: its last artifact is "
            f"head {len(heads)} of the {len(log)} the log recorded"
        )
    if log == heads[: len(log)]:
        return f"the bundle carries {len(heads) - len(log)} post-seal artifact(s) never anchored"
    at = next(i for i, (a, b) in enumerate(zip(heads, log, strict=False)) if a != b)
    what = "the seal" if at == 0 else f"post-seal head {at}"
    return f"{what} is {show(heads[at])} but the log anchored {show(log[at])}"


def _bundle_spec_version(bundle: dict[str, Any], transaction: dict[str, Any]) -> str | None:
    for container in (bundle, transaction):
        for key in ("spec_version", "specVersion"):
            value = container.get(key)
            if isinstance(value, str):
                return value
    return None


def verify_bundle(
    bundle: Any,
    public_key: Ed25519PublicKey,
    *,
    expected_merchant_id: str | None = None,
    verified_at: str | None = None,
    anchored_seal: str | None = None,
    anchored_heads: Sequence[str] | None = None,
) -> BundleVerification:
    """Re-verify a §6.1 DisputeBundle and decide whether it may be exported (§6.2).

    The embedded `verification` object is treated as a claim and compared with
    the recomputed result; disagreements are surfaced, never silently replaced.

    `anchored_seal` is a sealed chain hash the recipient obtained independently of the
    bundle, from a §4.3 external existence anchor (an RFC 3161 token, a transparency-log
    entry, or a counter-signature by a non-exporting party). Verifying the anchor itself is
    the caller's job; this checks that the chain's seal is the anchored one. It is what turns
    "the merchant's key signed this" into "this existed when the anchor says it did", and it
    covers the pre-seal chain only: the seal is the authorization artifact (§2.5).

    `anchored_heads` goes further, and beyond the text: it is the sequence of chain heads an
    independent log recorded for this chain, the seal first and then the new head after each
    post-seal append. v1.0.3-rc.2 defines no such log; draft Issue I in notes/issues-draft.md
    proposes it. The bundle's seal and post-seal artifacts must be exactly the logged heads,
    in order, so a dropped, altered or added post-seal event is caught.
    """
    if anchored_seal is not None and not HASH_RE.match(str(anchored_seal)):
        raise BundleFormatError("anchored_seal must be 'sha256:' + 64 lowercase hex (§2.5)")
    if anchored_heads is not None:
        if isinstance(anchored_heads, str) or not anchored_heads:
            raise BundleFormatError("anchored_heads must be a non-empty sequence of hashes")
        if not all(isinstance(h, str) and HASH_RE.match(h) for h in anchored_heads):
            raise BundleFormatError("every anchored head must be 'sha256:' + 64 lowercase hex")
    if not isinstance(bundle, dict):
        raise BundleFormatError("bundle must be a JSON object (§6.1)")
    errors: list[str] = []
    warnings: list[str] = []

    transaction = bundle.get("transaction")
    if not isinstance(transaction, dict):
        errors.append("bundle.transaction missing or not an object (§6.1)")
        transaction = {}
    raw_artifacts = bundle.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise BundleFormatError("bundle.artifacts must be a non-empty array (§6.1)")
    try:
        records = [ArtifactRecord.from_json(a) for a in raw_artifacts]
    except ChainFormatError as exc:
        raise BundleFormatError(str(exc)) from exc

    sequences = [r.sequence_number for r in records]
    if any(not isinstance(s, int) or isinstance(s, bool) for s in sequences):
        errors.append("every artifact needs an integer sequence_number (§2.7, §6.1)")
    elif sequences != sorted(sequences):
        errors.append("artifacts are not ordered by sequence_number ASC (§6.1)")

    merchant_context = bundle.get("merchantContext")
    context_merchant = (
        merchant_context.get("merchantId") if isinstance(merchant_context, dict) else None
    )
    if expected_merchant_id is None and isinstance(context_merchant, str):
        expected_merchant_id = context_merchant
    elif (
        expected_merchant_id is not None
        and isinstance(context_merchant, str)
        and context_merchant != expected_merchant_id
    ):
        errors.append(
            f"merchantContext.merchantId {show(context_merchant)} is not the expected "
            f"{show(expected_merchant_id)} (§2.7)"
        )

    transaction_type = transaction.get("transactionType")
    sealed = transaction.get("sealedBundleHash")
    verification = verify_chain(
        records,
        public_key,
        transaction_type=transaction_type if isinstance(transaction_type, str) else None,
        sealed_bundle_hash=sealed if isinstance(sealed, str) else None,
        spec_version=_bundle_spec_version(bundle, transaction),
        expected_merchant_id=expected_merchant_id,
        verified_at=verified_at,
    )
    if not isinstance(transaction_type, str):
        errors.append("transaction.transactionType missing (§6.1)")

    disagreements: list[str] = []
    embedded = bundle.get("verification")
    mode: Any = None
    if isinstance(embedded, dict):
        for camel, snake in _EMBEDDED_FIELDS:
            recomputed = getattr(verification, snake)
            if camel == "evidenceTier" and recomputed is None:
                continue  # not computed here (§3.9.11); the wrapper check already says so
            if camel in embedded and embedded[camel] != recomputed:
                disagreements.append(
                    f"bundle.verification.{camel}={show(embedded[camel])} but re-verification "
                    f"gives {show(recomputed)} (§6.2)"
                )
        mode = embedded.get("verificationMode")
        if mode == "cached" and not isinstance(embedded.get("verifiedAt"), str):
            errors.append("cached verification MUST carry a non-null verifiedAt (§5, §6.2)")
    else:
        warnings.append("bundle carries no verification object (§6.1)")
    if not isinstance(bundle.get("exportedAt"), str):
        warnings.append("bundle.exportedAt missing (§6.1)")

    anchor_matches: bool | None = None
    if anchored_seal is not None:
        derived = verification.sealed_bundle_hash
        anchor_matches = derived is not None and hmac.compare_digest(derived, anchored_seal)
        if not anchor_matches:
            errors.append(
                f"the chain's seal {show(derived)} is not the externally anchored seal "
                f"{show(anchored_seal)}: the pre-seal chain is not the one that was anchored (§4.3)"
            )

    heads_match: bool | None = None
    if anchored_heads is not None:
        problem = _compare_heads(records, list(anchored_heads))
        heads_match = problem is None
        if problem is not None:
            errors.append(f"{problem} (anchored head log: draft Issue I, not in v1.0.3-rc.2)")

    contradictions, wrapper_warnings = _cross_check_wrapper(
        bundle, transaction, records, verification
    )
    warnings.extend(wrapper_warnings)

    gate: list[str] = []
    if not verification.valid:
        gate.append("re-verification gives valid=false; MUST NOT be exported for submission (§6.2)")
    if sealed is None:
        gate.append("transaction.sealedBundleHash is null: the chain is not sealed (§2.5)")
    if mode == "cached":
        gate.append(
            "verification.verificationMode is 'cached'; representment export requires a full "
            "re-verification (§6.2)"
        )
    if disagreements:
        gate.append("embedded verification disagrees with re-verification (§6.2)")
    if anchor_matches is False:
        gate.append("the seal does not match the externally anchored seal (§4.3)")
    if heads_match is False:
        gate.append("the seal and post-seal artifacts do not match the anchored head log")
    if contradictions:
        gate.append(
            "the bundle wrapper contradicts its own sealed chain; aep-verify will not certify it "
            "(extension: §6.1 binds no wrapper field, see upstream #16)"
        )
    if errors:
        gate.append("bundle-level errors present")

    return BundleVerification(
        verification=verification,
        exportable=not gate,
        gate_reasons=gate,
        errors=errors,
        warnings=warnings,
        embedded_disagreements=disagreements,
        wrapper_contradictions=contradictions,
        anchor_matches=anchor_matches,
        heads_match=heads_match,
    )
