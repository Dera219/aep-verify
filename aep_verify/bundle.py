"""DisputeBundle re-verification and the §6.2 export gate."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .chain import ArtifactRecord, ChainFormatError, VerificationResult, verify_chain

# §6.1 camelCase member -> §5 snake_case field.
_EMBEDDED_FIELDS: tuple[tuple[str, str], ...] = (
    ("valid", "valid"),
    ("hashChainIntact", "hash_chain_intact"),
    ("signaturesValid", "signatures_valid"),
    ("chainComplete", "chain_complete"),
    ("artifactsVerified", "artifacts_verified"),
)


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

    def to_dict(self) -> dict[str, Any]:
        return {
            "exportable": self.exportable,
            "gate_reasons": list(self.gate_reasons),
            "bundle_errors": list(self.errors),
            "bundle_warnings": list(self.warnings),
            "embedded_disagreements": list(self.embedded_disagreements),
            "verification": self.verification.to_dict(),
        }


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
) -> BundleVerification:
    """Re-verify a §6.1 DisputeBundle and decide whether it may be exported (§6.2).

    The embedded `verification` object is treated as a claim and compared with
    the recomputed result; disagreements are surfaced, never silently replaced.
    """
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
            f"merchantContext.merchantId {context_merchant!r} is not the expected "
            f"{expected_merchant_id!r} (§2.7)"
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
            if camel in embedded and embedded[camel] != getattr(verification, snake):
                disagreements.append(
                    f"bundle.verification.{camel}={embedded[camel]!r} but re-verification "
                    f"gives {getattr(verification, snake)!r} (§6.2)"
                )
        mode = embedded.get("verificationMode")
        if mode == "cached" and not isinstance(embedded.get("verifiedAt"), str):
            errors.append("cached verification MUST carry a non-null verifiedAt (§5, §6.2)")
    else:
        warnings.append("bundle carries no verification object (§6.1)")
    if not isinstance(bundle.get("exportedAt"), str):
        warnings.append("bundle.exportedAt missing (§6.1)")

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
    if errors:
        gate.append("bundle-level errors present")

    return BundleVerification(
        verification=verification,
        exportable=not gate,
        gate_reasons=gate,
        errors=errors,
        warnings=warnings,
        embedded_disagreements=disagreements,
    )
