"""Chain-layer verification for AEP v1.0.3-rc.2.

Implemented, key-free parts of the draft: the §4.1 hash input and canonical
form, §4.2 genesis/link rules, §4.3 Ed25519 server signatures, §2.5 seal,
§3.8 permitted actors, §3.9.2 ordering, §3.5 MUST-1 cart total integrity,
§3.6 MUST-1 cart/authorization amount match, the §3.7 delivery-address
match, §3.9.11 rule 4 (AP2 checkout hash binding), §2.2 / Appendix B
completeness, and the §5 result schema.

Not implemented: protocol-envelope verification (§3.9.11 rules 1-3, 5-12).
Those rules need live or witnessed third-party keys and reference envelopes,
and no conformance vector for them has been published. Envelope entries are
still emitted, with status null, so a reader can see what was not checked.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, TypeGuard

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import CanonicalizationError, canonicalize

VERIFIER_ID = "aep-verify/0.2.0"
SPEC_VERSION = "aep-1.0.3-rc.2"
SUPPORTED_SPEC_VERSIONS: frozenset[str] = frozenset({SPEC_VERSION})

# §4.1 / Appendix B: the exhaustive per-artifact hash input.
HASH_INPUT_FIELDS: tuple[str, ...] = (
    "actor_id",
    "actor_type",
    "artifact_type",
    "interaction_channel",
    "metadata",
    "payload",
    "previous_hash",
    "timestamp",
)

# §3.9.2 sequence; §2.5 post-seal types.
PRE_SEAL_ORDER: tuple[str, ...] = (
    "discovery",
    "referral",
    "intent",
    "delegation",
    "policy",
    "cart",
    "authorization",
)
POST_SEAL_TYPES: frozenset[str] = frozenset({"fulfillment", "refund"})
ARTIFACT_TYPES: tuple[str, ...] = PRE_SEAL_ORDER + ("fulfillment", "refund")

# §2.4 / Appendix B.
ACTOR_TYPES: frozenset[str] = frozenset(
    {
        "user",
        "agent",
        "merchant",
        "psp",
        "fulfillment_provider",
        "credentials_provider",
        "identity_verifier",
    }
)
INTERACTION_CHANNELS: frozenset[str] = frozenset({"voice", "text_chat", "voice_and_text"})

# §3.8 "Permitted Actors" column.
PERMITTED_ACTORS: dict[str, frozenset[str]] = {
    "discovery": frozenset({"agent", "merchant"}),
    "referral": frozenset({"user"}),
    "intent": frozenset({"user", "agent"}),
    "delegation": frozenset({"agent", "merchant", "credentials_provider"}),
    "policy": frozenset({"merchant"}),
    "cart": frozenset({"user", "agent"}),
    "authorization": frozenset({"psp"}),
    "fulfillment": frozenset({"fulfillment_provider"}),
    "refund": frozenset({"merchant", "psp"}),
}

TRANSACTION_TYPES: tuple[str, ...] = (
    "ai_referral_agent_session",
    "ai_referral_standard_checkout",
    "agent_session_only",
    "direct_web",
)

# §2.2 notes: which pre-seal layers a transaction type may carry at all.
_ALL_PRE_SEAL = frozenset(PRE_SEAL_ORDER)
TYPE_LAYERS: dict[str, frozenset[str]] = {
    "ai_referral_agent_session": _ALL_PRE_SEAL,
    "ai_referral_standard_checkout": _ALL_PRE_SEAL,
    "agent_session_only": _ALL_PRE_SEAL - {"discovery", "referral"},
    "direct_web": _ALL_PRE_SEAL - {"discovery", "referral", "delegation"},
}

# Appendix B expectedArtifactCount: (without delegation, with delegation).
_EXPECTED_COUNTS: dict[str, tuple[int, int]] = {
    "ai_referral_agent_session": (7, 8),
    "ai_referral_standard_checkout": (6, 7),
    "agent_session_only": (5, 6),
    "direct_web": (5, 5),
}

# §3.9.4 sub-wrapper field -> §5 envelope name. vic_payment_payload (§3.9.13)
# has no value in the §5 envelope enum; "VIC" is emitted and flagged.
SUB_WRAPPERS: tuple[tuple[str, str], ...] = (
    ("agent_identity", "TAP"),
    ("kya_identity", "SKYFIRE_KYA"),
    ("web_bot_auth", "WEB_BOT_AUTH"),
    ("agent_coordination", "A2A"),
    ("consumer_authorization", "AP2"),
    ("mastercard_verifiable_intent", "MASTERCARD_VI"),
    ("session_binding_acp", "ACP"),
    ("session_binding_ucp", "UCP"),
    ("http_payment", "x402"),
    ("kya_payment", "SKYFIRE_KYA"),
    ("tool_invocation", "MCP"),
    ("vic_payment_payload", "VIC"),
)

CART_MONEY_FIELDS: tuple[str, ...] = ("subtotal", "shipping", "tax", "discounts", "total")

HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class ChainFormatError(ValueError):
    """The input is not an artifact chain at all (as opposed to a chain that fails)."""


def _is_int(value: Any) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def show(value: Any, limit: int = 96) -> str:
    """repr() for messages about untrusted input: bounded in length, never recursive.

    Identical to repr() for the short values a conformant chain carries; a 5 MB string or a
    10,000-deep array in a hostile bundle becomes a short placeholder instead of being echoed
    into every error that mentions it.
    """
    if isinstance(value, list | tuple):
        if len(value) <= 10 and all(v is None or isinstance(v, str | int | bool) for v in value):
            text = "[" + ", ".join(show(v, 40) for v in value) + "]"
        else:
            text = f"<array of {len(value)} items>"
    elif isinstance(value, dict):
        text = f"<object with {len(value)} members>"
    else:
        text = repr(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _known(value: Any, allowed: Any) -> TypeGuard[str]:
    """Membership for untrusted JSON: a dict or list where a name belongs is simply unknown.

    `{} in frozenset(...)` raises TypeError (unhashable), and a verifier must reject hostile
    input, never crash on it.
    """
    return isinstance(value, str) and value in allowed


def _parse_timestamp(value: Any) -> datetime | None:
    """§4.1: RFC 3339 UTC 'Z', whole seconds (vectors README pins the precision)."""
    if not isinstance(value, str) or not TIMESTAMP_RE.match(value):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def _parse_iso_utc(value: Any) -> datetime | None:
    """§2.7 captured_at is 'ISO 8601 UTC' with no byte format pinned; parse leniently."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def now_utc() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_hash(hash_input: dict[str, Any]) -> str:
    """§4.1: 'sha256:' + lowercase hex of SHA-256 over the canonical eight-field input."""
    missing = [f for f in HASH_INPUT_FIELDS if f not in hash_input]
    if missing:
        raise ChainFormatError(f"hash input missing {missing}")
    canonical = canonicalize({f: hash_input[f] for f in HASH_INPUT_FIELDS})
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def digest_bytes(hash_str: str) -> bytes:
    """The raw 32 digest bytes behind a 'sha256:<hex>' string (§4.1 signature input encoding)."""
    if not HASH_RE.match(hash_str):
        raise ChainFormatError(f"not a sha256:<64 lowercase hex> string: {show(hash_str)}")
    return bytes.fromhex(hash_str[len("sha256:") :])


def sign_hash(private_key: Ed25519PrivateKey, hash_str: str) -> str:
    """§4.3: Ed25519 over the raw digest bytes, base64 at rest."""
    return base64.b64encode(private_key.sign(digest_bytes(hash_str))).decode("ascii")


def verify_signature(
    public_key: Ed25519PublicKey, hash_str: str, signature_b64: Any
) -> tuple[bool, str | None]:
    if not isinstance(signature_b64, str):
        return False, "server_signature is not a string (§4.3)"
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        return False, "server_signature is not valid base64 (§4.3)"
    if len(signature) != 64:
        return (
            False,
            f"server_signature is {len(signature)} bytes; Ed25519 signatures are 64 (§4.3)",
        )
    try:
        public_key.verify(signature, digest_bytes(hash_str))
    except InvalidSignature:
        return False, "Ed25519 server_signature does not verify over the raw digest (§4.3)"
    return True, None


def expected_artifact_count(transaction_type: str, protocol: str = "GENERIC") -> int:
    """Appendix B expectedArtifactCount, literally: delegation is inferred from protocol."""
    try:
        without, with_delegation = _EXPECTED_COUNTS[transaction_type]
    except KeyError:
        raise ChainFormatError(f"unknown transaction_type {show(transaction_type)}") from None
    return with_delegation if protocol != "GENERIC" else without


def expected_count_by_presence(transaction_type: str, delegation_present: bool) -> int:
    """The §2.2 prose reading: the count drops by one only when delegation is omitted."""
    try:
        without, with_delegation = _EXPECTED_COUNTS[transaction_type]
    except KeyError:
        raise ChainFormatError(f"unknown transaction_type {show(transaction_type)}") from None
    return with_delegation if delegation_present else without


@dataclass
class ArtifactRecord:
    """One artifact as stored or exported. Two shapes are accepted:

    * vector (b) shape: {"sequence_number", "hash_input": {...eight fields...},
      "current_hash", "server_signature"}
    * flat shape: the eight fields alongside sequence_number / current_hash /
      server_signature at the top level (the §6.1 EhcArtifactRecord is not
      defined in the draft text, so this is the obvious flattening).
    """

    hash_input: dict[str, Any]
    sequence_number: Any
    current_hash: Any
    server_signature: Any
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_json(cls, obj: Any) -> ArtifactRecord:
        if not isinstance(obj, dict):
            raise ChainFormatError("artifact record must be a JSON object")
        if isinstance(obj.get("hash_input"), dict):
            hash_input = dict(obj["hash_input"])
        else:
            hash_input = {f: obj[f] for f in HASH_INPUT_FIELDS if f in obj}
        sequence = obj.get("sequence_number", obj.get("seq"))
        return cls(
            hash_input=hash_input,
            sequence_number=sequence,
            current_hash=obj.get("current_hash"),
            server_signature=obj.get("server_signature"),
            raw=obj,
        )

    @property
    def artifact_type(self) -> Any:
        return self.hash_input.get("artifact_type")

    @property
    def payload(self) -> dict[str, Any]:
        payload = self.hash_input.get("payload")
        return payload if isinstance(payload, dict) else {}

    @property
    def metadata(self) -> dict[str, Any]:
        metadata = self.hash_input.get("metadata")
        return metadata if isinstance(metadata, dict) else {}


@dataclass
class ArtifactCheck:
    position: int
    sequence_number: Any
    artifact_type: Any
    computed_hash: str | None
    hash_matches: bool
    signature_valid: bool
    link_valid: bool
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.hash_matches and self.signature_valid and self.link_valid and not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "position": self.position,
            "sequence_number": self.sequence_number,
            "artifact_type": self.artifact_type,
            "computed_hash": self.computed_hash,
            "hash_matches": self.hash_matches,
            "signature_valid": self.signature_valid,
            "link_valid": self.link_valid,
            "errors": list(self.errors),
        }


@dataclass
class VerificationResult:
    """The §5 verification result, plus verifier extensions under x_aep_verify."""

    valid: bool
    hash_chain_intact: bool
    signatures_valid: bool
    chain_complete: bool
    artifacts_verified: int
    spec_version: str | None
    verified_at: str
    verification_mode: str = "full"
    evidence_tier: str | None = None
    protocol_envelopes_verified: list[dict[str, Any]] = field(default_factory=list)
    cart_payment_binding_verified: bool | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    artifact_checks: list[ArtifactCheck] = field(default_factory=list)
    total_artifacts: int = 0
    expected_artifact_count: int | None = None
    protocol: str | None = None
    sealed_bundle_hash: str | None = None
    seal_valid: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "hash_chain_intact": self.hash_chain_intact,
            "signatures_valid": self.signatures_valid,
            "chain_complete": self.chain_complete,
            "artifacts_verified": self.artifacts_verified,
            "spec_version": self.spec_version,
            "verified_at": self.verified_at,
            "verification_mode": self.verification_mode,
            "evidence_tier": self.evidence_tier,
            "protocol_envelopes_verified": [dict(e) for e in self.protocol_envelopes_verified],
            "cart_payment_binding_verified": self.cart_payment_binding_verified,
            "errors": list(self.errors),
            "x_aep_verify": {
                "verifier": VERIFIER_ID,
                "warnings": list(self.warnings),
                "total_artifacts": self.total_artifacts,
                "expected_artifact_count": self.expected_artifact_count,
                "protocol": self.protocol,
                "sealed_bundle_hash": self.sealed_bundle_hash,
                "seal_valid": self.seal_valid,
                "artifacts": [c.to_dict() for c in self.artifact_checks],
            },
        }


def _refused(
    reason: str, spec_version: str | None, verified_at: str, total: int
) -> VerificationResult:
    return VerificationResult(
        valid=False,
        hash_chain_intact=False,
        signatures_valid=False,
        chain_complete=False,
        artifacts_verified=0,
        spec_version=spec_version,
        verified_at=verified_at,
        errors=[reason],
        total_artifacts=total,
    )


def _resolve_spec_version(
    artifacts: list[ArtifactRecord], supplied: str | None, errors: list[str]
) -> str | None:
    versions: set[str] = set()
    if supplied is not None:
        versions.add(supplied if isinstance(supplied, str) else show(supplied))
    for artifact in artifacts:
        if "spec_version" in artifact.metadata:
            value = artifact.metadata["spec_version"]
            versions.add(value if isinstance(value, str) else show(value))
        if "spec_version" in artifact.raw:
            value = artifact.raw["spec_version"]
            versions.add(value if isinstance(value, str) else show(value))
    if not versions:
        errors.append(
            "spec_version missing: not on any artifact and not supplied at bundle level (§2.7)"
        )
        return None
    if len(versions) > 1:
        errors.append(
            f"conflicting spec_version values {show(sorted(versions))} across the chain (§2.7)"
        )
        return None
    return versions.pop()


def _check_artifact(
    position: int,
    artifact: ArtifactRecord,
    public_key: Ed25519PublicKey,
    previous_hash: str | None,
) -> tuple[ArtifactCheck, str | None]:
    """Run the §4.3 'Verification Steps (per artifact)' plus the field-level rules."""
    errors: list[str] = []
    hash_input = artifact.hash_input

    if artifact.sequence_number != position:
        errors.append(
            f"sequence_number {show(artifact.sequence_number)} at position {position} "
            "(§4.2: 1 for genesis, then consecutive)"
        )

    missing = [f for f in HASH_INPUT_FIELDS if f not in hash_input]
    extra = sorted(set(hash_input) - set(HASH_INPUT_FIELDS))
    if missing:
        errors.append(f"hash input missing {missing} (§4.1 / Appendix B)")
    if extra:
        errors.append(f"hash input carries fields outside the §4.1 eight: {extra}")

    artifact_type = hash_input.get("artifact_type")
    actor_type = hash_input.get("actor_type")
    channel = hash_input.get("interaction_channel")
    if not _known(artifact_type, ARTIFACT_TYPES):
        errors.append(f"unknown artifact_type {show(artifact_type)} (Appendix B)")
    if not _known(actor_type, ACTOR_TYPES):
        errors.append(f"unknown actor_type {show(actor_type)} (§2.4 / Appendix B)")
    elif (
        _known(artifact_type, PERMITTED_ACTORS)
        and actor_type not in PERMITTED_ACTORS[artifact_type]
    ):
        errors.append(
            f"actor_type {show(actor_type)} is not permitted for {show(artifact_type)} (§3.8)"
        )
    if channel is not None and not _known(channel, INTERACTION_CHANNELS):
        errors.append(
            f"interaction_channel {show(channel)} is not voice|text_chat|voice_and_text|null"
        )
    if not isinstance(hash_input.get("actor_id"), str) or not hash_input.get("actor_id"):
        errors.append("actor_id must be a non-empty string (Appendix B)")
    if not isinstance(hash_input.get("payload"), dict):
        errors.append("payload must be an object (Appendix B)")
    metadata = hash_input.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        errors.append("metadata must be an object or null (Appendix B)")
    if _parse_timestamp(hash_input.get("timestamp")) is None:
        errors.append(
            f"timestamp {show(hash_input.get('timestamp'))} is not RFC 3339 UTC 'Z' "
            "whole-second (§4.1)"
        )

    # §4.2 genesis / link.
    link_valid = False
    prev = hash_input.get("previous_hash")
    if position == 1:
        if prev is None:
            link_valid = True
        else:
            errors.append("genesis previous_hash must be null (§4.2)")
    elif not isinstance(prev, str) or not HASH_RE.match(prev):
        errors.append("non-genesis previous_hash missing or malformed (§4.2)")
    elif previous_hash is None:
        errors.append("cannot verify link: preceding artifact has no usable current_hash (§5)")
    elif hmac.compare_digest(prev, previous_hash):
        link_valid = True
    else:
        errors.append("previous_hash does not equal the preceding current_hash (§4.2, §5)")

    # §4.3 step 1-2: recompute and compare.
    computed: str | None = None
    if not missing:
        try:
            computed = compute_hash(hash_input)
        except CanonicalizationError as exc:
            errors.append(f"canonicalization failed: {exc} (§4.1)")
    stored = artifact.current_hash
    stored_ok = isinstance(stored, str) and bool(HASH_RE.match(stored))
    if not stored_ok:
        errors.append("current_hash missing or not sha256:<64 lowercase hex> (§4.1)")
    hash_matches = bool(
        stored_ok and computed is not None and hmac.compare_digest(computed, stored)
    )
    if stored_ok and computed is not None and not hash_matches:
        errors.append("recomputed hash does not equal stored current_hash (§5: content modified)")

    # Unsigned copies carried beside the hash input (the vector (b) record shape). A reader or
    # tool that trusts them would see content the signature does not cover, so they must agree.
    copy_text = artifact.raw.get("canonical_json")
    if copy_text is not None and not missing:
        try:
            same = isinstance(copy_text, str) and copy_text == canonicalize(hash_input).decode()
        except CanonicalizationError:
            same = True  # already reported above as a canonicalization failure
        if not same:
            errors.append("canonical_json is not the canonical form of hash_input (unsigned copy)")
    record_type = artifact.raw.get("artifact_type")
    if "hash_input" in artifact.raw and record_type is not None and record_type != artifact_type:
        errors.append(
            f"record artifact_type {show(record_type)} but the signed hash_input says "
            f"{show(artifact_type)}"
        )

    # §4.3 step 3: signature over the stored current_hash.
    signature_valid = False
    if artifact.server_signature is None:
        errors.append("server_signature missing: unsigned artifacts are non-conformant (§4.3)")
    elif stored_ok:
        signature_valid, reason = verify_signature(public_key, stored, artifact.server_signature)
        if reason:
            errors.append(reason)

    check = ArtifactCheck(
        position=position,
        sequence_number=artifact.sequence_number,
        artifact_type=artifact_type,
        computed_hash=computed,
        hash_matches=hash_matches,
        signature_valid=signature_valid,
        link_valid=link_valid,
        errors=errors,
    )
    return check, (stored if stored_ok else computed)


def _check_order(
    artifacts: list[ArtifactRecord], transaction_type: str | None, errors: list[str]
) -> int | None:
    """§3.9.2 sequence, §2.5 seal boundary, §2.2 layer membership. Returns the seal position."""
    last_index = -1
    sealed_at: int | None = None
    allowed = TYPE_LAYERS.get(transaction_type or "")
    for i, artifact in enumerate(artifacts, start=1):
        kind = artifact.artifact_type
        if not isinstance(kind, str):
            continue  # reported per artifact as an unknown artifact_type
        if kind in PRE_SEAL_ORDER:
            index = PRE_SEAL_ORDER.index(kind)
            if sealed_at is not None:
                errors.append(
                    f"artifact {i} ({kind}) follows the authorization seal; only fulfillment and "
                    "refund may be appended post-seal (§2.5)"
                )
            elif index <= last_index:
                errors.append(f"artifact {i} ({kind}) is out of order or duplicated (§3.9.2)")
            last_index = max(last_index, index)
            if kind == "authorization" and sealed_at is None:
                sealed_at = i
            if allowed is not None and kind not in allowed:
                errors.append(
                    f"artifact {i} ({kind}) is not a layer of transaction type "
                    f"{show(transaction_type)} (§2.2)"
                )
        elif kind in POST_SEAL_TYPES and sealed_at is None:
            errors.append(
                f"artifact {i} ({kind}) is post-seal but no authorization precedes it (§2.5)"
            )
    return sealed_at


def _check_monotonic(
    artifacts: list[ArtifactRecord], errors: list[str], warnings: list[str]
) -> None:
    previous_ts: datetime | None = None
    previous_captured: datetime | None = None
    for i, artifact in enumerate(artifacts, start=1):
        ts = _parse_timestamp(artifact.hash_input.get("timestamp"))
        if ts is not None:
            if previous_ts is not None and ts < previous_ts:
                warnings.append(f"artifact {i}: timestamp precedes the preceding artifact's")
            previous_ts = ts
        payload = artifact.payload
        captured_raw = payload.get("captured_at")
        if captured_raw is None and artifact.artifact_type == "delegation":
            meta = payload.get("protocol_metadata")
            captured_raw = meta.get("captured_at") if isinstance(meta, dict) else None
        if captured_raw is None:
            warnings.append(
                f"artifact {i} ({artifact.artifact_type}) carries no captured_at; §2.7 lists it "
                "as a per-artifact MUST"
            )
            continue
        captured = _parse_iso_utc(captured_raw)
        if captured is None:
            errors.append(
                f"artifact {i}: captured_at {show(captured_raw)} is not ISO 8601 UTC (§2.7)"
            )
            continue
        if previous_captured is not None and captured < previous_captured:
            errors.append(
                f"artifact {i}: captured_at decreases; MUST be monotonically non-decreasing (§2.7)"
            )
        previous_captured = captured


def _check_cart_and_amount(
    cart: ArtifactRecord | None, authorization: ArtifactRecord | None, errors: list[str]
) -> None:
    if cart is None:
        return
    payload = cart.payload
    money: dict[str, Any] = {k: payload.get(k) for k in CART_MONEY_FIELDS}
    bad = [k for k, v in money.items() if not _is_int(v)]
    if bad:
        errors.append(f"cart fields {bad} are not integer minor units (§3.5)")
    else:
        expected = money["subtotal"] + money["shipping"] + money["tax"] - money["discounts"]
        if expected != money["total"]:
            errors.append(
                "cart total integrity: subtotal + shipping + tax - discounts != total (§3.5 MUST-1)"
            )
    items = payload.get("items")
    if isinstance(items, list):
        for j, item in enumerate(items):
            if not isinstance(item, dict):
                errors.append(f"cart.items[{j}] is not an object (§3.5)")
                continue
            for key in ("unit_price", "quantity"):
                if key in item and not _is_int(item[key]):
                    errors.append(f"cart.items[{j}].{key} is not an integer (§3.5)")
    if payload.get("confirmed") is not True:
        errors.append("cart.confirmed MUST be true (§3.5)")
    if authorization is None:
        return
    auth = authorization.payload
    if _is_int(money["total"]) and auth.get("amount") != money["total"]:
        errors.append("authorization.amount != cart.total (§3.6 MUST-1 amount match)")
    if auth.get("currency") != payload.get("currency"):
        errors.append("authorization.currency != cart.currency (§3.6 MUST-1 amount match)")


def _check_address_match(
    artifacts: list[ArtifactRecord], cart: ArtifactRecord | None, errors: list[str]
) -> None:
    """§3.7: delivery_address_match MUST equal (delivery_address_hash == shipping_address_hash).

    §3.7 calls the boolean unforgeable "without breaking the hash chain upstream". That holds
    only if a verifier recomputes it: the merchant computes and signs the boolean, so a signed
    `true` beside two different hashes breaks no link. It is recomputed here.
    """
    if cart is None:
        return
    shipping = cart.payload.get("shipping_address_hash")
    for position, artifact in enumerate(artifacts, start=1):
        if artifact.artifact_type != "fulfillment":
            continue
        payload = artifact.payload
        if "delivery_address_match" not in payload:
            continue
        claimed = payload["delivery_address_match"]
        delivered_to = payload.get("delivery_address_hash")
        if not (isinstance(delivered_to, str) and isinstance(shipping, str)):
            # Only an explicit true claims a comparison; upstream #65 makes these nullable for
            # fulfillment that never ships.
            if claimed is True:
                errors.append(
                    f"artifact {position}: fulfillment.delivery_address_match={show(claimed)} but "
                    "an address hash it compares is missing (§3.5, §3.7)"
                )
            continue
        expected = delivered_to == shipping
        if claimed is not expected:
            errors.append(
                f"artifact {position}: fulfillment.delivery_address_match={show(claimed)} but "
                f"delivery_address_hash {'==' if expected else '!='} cart.shipping_address_hash "
                "(§3.7 MUST)"
            )


def _check_merchant(
    artifacts: list[ArtifactRecord], expected_merchant_id: str | None, errors: list[str]
) -> None:
    values = [a.metadata["merchant_id"] for a in artifacts if "merchant_id" in a.metadata]
    if any(not isinstance(v, str) for v in values):
        errors.append("metadata.merchant_id must be a string (§2.7)")
    seen = {v for v in values if isinstance(v, str)}
    if len(seen) > 1:
        errors.append(f"artifacts disagree on metadata.merchant_id: {show(sorted(seen))} (§2.7)")
    if expected_merchant_id is not None:
        unknown = sorted(m for m in seen if m != expected_merchant_id)
        if unknown:
            errors.append(
                f"bundle references merchant_id {show(unknown)} which the verifier does not "
                "recognize "
                f"(expected {show(expected_merchant_id)}); MUST be rejected (§2.7)"
            )


def _envelopes(
    delegation: ArtifactRecord | None, errors: list[str], warnings: list[str]
) -> tuple[str, list[dict[str, Any]], list[str]]:
    """Protocol, §5 envelope entries, and the populated sub-wrapper field names."""
    if delegation is None:
        return "GENERIC", [], []
    meta = delegation.payload.get("protocol_metadata")
    if not isinstance(meta, dict):
        errors.append("delegation payload lacks a protocol_metadata object (§3.9.4)")
        return "GENERIC", [], []
    protocol = meta.get("protocol")
    if not isinstance(protocol, str) or not protocol:
        errors.append("delegation protocol_metadata.protocol missing (§3.9.4)")
        protocol = "GENERIC"
    present: list[str] = []
    entries: list[dict[str, Any]] = []
    for field_name, envelope in SUB_WRAPPERS:
        if meta.get(field_name) is None:
            continue
        present.append(field_name)
        entries.append(
            {
                "envelope": envelope,
                "verified": False,
                "status": None,
                "unverifiable_reason": None,
                "witnessed": None,
                "key_discovery_path": "",
                "claims": None,
                "x_aep_verify_note": (
                    f"{field_name} present; §3.9.11 envelope verification is not implemented "
                    "by this verifier, so no status is asserted"
                ),
            }
        )
        if envelope == "VIC":
            warnings.append(
                "vic_payment_payload (§3.9.13) has no value in the §5 envelope enum; "
                "reported as 'VIC'"
            )
    if present:
        warnings.append(
            f"delegation sub-wrappers {present} were not verified (§3.9.11 not implemented); "
            "evidence_tier is not computed"
        )
    if protocol == "GENERIC" and not present:
        warnings.append(
            "delegation artifact present with protocol GENERIC and no populated sub-wrapper; "
            "§3.9.2 says delegation MUST be omitted in that case"
        )
    return protocol, entries, present


def _ap2_binding(
    delegation: ArtifactRecord | None, cart: ArtifactRecord | None, errors: list[str]
) -> bool | None:
    """§3.9.11 rule 4. None when AP2 consumer_authorization is absent (rule not applicable)."""
    if delegation is None:
        return None
    meta = delegation.payload.get("protocol_metadata")
    if not isinstance(meta, dict):
        return None
    auth = meta.get("consumer_authorization")
    if auth is None:
        return None
    if not isinstance(auth, dict):
        errors.append("consumer_authorization is not an object (§3.9.7)")
        return False
    jwt = auth.get("ap2_checkout_jwt")
    claimed = auth.get("ap2_checkout_hash")
    if not isinstance(jwt, str) or not isinstance(claimed, str):
        errors.append(
            "consumer_authorization present without ap2_checkout_jwt/ap2_checkout_hash (rule 4)"
        )
        return False
    digest = hashlib.sha256(jwt.encode("utf-8")).digest()
    expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    if not hmac.compare_digest(expected, claimed.rstrip("=")):
        errors.append("ap2_checkout_hash != base64url(sha256(ap2_checkout_jwt)) (§3.9.11 rule 4)")
        return False
    binding = cart.payload.get("cart_payment_binding") if cart is not None else None
    value = binding.get("binding_value") if isinstance(binding, dict) else None
    if not isinstance(value, str) or not hmac.compare_digest(value.rstrip("="), expected):
        errors.append(
            "cart.cart_payment_binding.binding_value != ap2_checkout_hash (§3.9.11 rule 4)"
        )
        return False
    return True


def verify_chain(
    records: list[Any],
    public_key: Ed25519PublicKey,
    *,
    transaction_type: str | None = None,
    sealed_bundle_hash: str | None = None,
    spec_version: str | None = None,
    expected_merchant_id: str | None = None,
    verified_at: str | None = None,
) -> VerificationResult:
    """Full §5 verification of an ordered artifact sequence against one published key.

    `records` are ArtifactRecord instances or JSON objects in either accepted shape.
    `sealed_bundle_hash`, when supplied, is checked against the authorization
    artifact (§2.5). `transaction_type` drives chain_complete (§2.2 / Appendix B)
    and layer membership. Any error makes `valid` false.
    """
    verified_at = verified_at or now_utc()
    errors: list[str] = []
    warnings: list[str] = []

    artifacts = [
        r if isinstance(r, ArtifactRecord) else ArtifactRecord.from_json(r) for r in records
    ]
    if not artifacts:
        return _refused("chain is empty", None, verified_at, 0)

    resolved = _resolve_spec_version(artifacts, spec_version, errors)
    if resolved is not None and resolved not in SUPPORTED_SPEC_VERSIONS:
        return _refused(
            f"unsupported spec_version {show(resolved)}; this verifier supports "
            f"{sorted(SUPPORTED_SPEC_VERSIONS)} and MUST refuse (§0.1, §2.7)",
            resolved,
            verified_at,
            len(artifacts),
        )

    if transaction_type is not None and transaction_type not in TRANSACTION_TYPES:
        errors.append(f"unknown transaction_type {show(transaction_type)} (§2.2)")
        transaction_type = None

    checks: list[ArtifactCheck] = []
    previous_hash: str | None = None
    for position, artifact in enumerate(artifacts, start=1):
        check, previous_hash = _check_artifact(position, artifact, public_key, previous_hash)
        checks.append(check)

    sealed_at = _check_order(artifacts, transaction_type, errors)
    _check_monotonic(artifacts, errors, warnings)
    _check_merchant(artifacts, expected_merchant_id, errors)

    by_type: dict[str, ArtifactRecord] = {}
    for artifact in artifacts:
        if isinstance(artifact.artifact_type, str):
            by_type.setdefault(artifact.artifact_type, artifact)
    cart = by_type.get("cart")
    authorization = by_type.get("authorization")
    delegation = by_type.get("delegation")
    _check_cart_and_amount(cart, authorization, errors)
    _check_address_match(artifacts, cart, errors)

    # §2.5 seal.
    seal_valid: bool | None = None
    derived_seal: str | None = None
    if sealed_at is not None:
        stored = artifacts[sealed_at - 1].current_hash
        derived_seal = stored if isinstance(stored, str) and HASH_RE.match(stored) else None
    if sealed_bundle_hash is not None:
        if derived_seal is None:
            errors.append(
                "sealed_bundle_hash supplied but the chain has no usable seal point (§2.5)"
            )
            seal_valid = False
        elif hmac.compare_digest(str(sealed_bundle_hash), derived_seal):
            seal_valid = True
        else:
            errors.append(
                "sealed_bundle_hash does not equal the authorization artifact's current_hash (§2.5)"
            )
            seal_valid = False
    elif sealed_at is None:
        warnings.append("chain has no authorization artifact: unsealed (§2.5)")

    protocol, envelopes, present = _envelopes(delegation, errors, warnings)
    evidence_tier = "D" if not present else None
    binding = _ap2_binding(delegation, cart, errors)

    # §2.2 / §5 completeness.
    counted = sum(1 for a in artifacts if a.artifact_type != "refund")
    expected: int | None = None
    chain_complete = False
    if transaction_type is not None:
        expected = expected_artifact_count(transaction_type, protocol)
        chain_complete = counted == expected
        alternative = expected_count_by_presence(transaction_type, delegation is not None)
        if alternative != expected:
            warnings.append(
                f"Appendix B expectedArtifactCount({show(transaction_type)}, "
                f"protocol={show(protocol)}) "
                f"= {expected}, but counting by delegation presence (§2.2 prose) gives "
                f"{alternative}; chain_complete follows Appendix B"
            )
    else:
        warnings.append("transaction_type not supplied; chain_complete cannot be computed (§2.2)")

    hash_chain_intact = all(c.link_valid for c in checks)
    all_hashes = all(c.hash_matches for c in checks)
    signatures_valid = all(c.signature_valid for c in checks)
    for check in checks:
        for message in check.errors:
            errors.append(f"artifact {check.position}: {message}")
    valid = hash_chain_intact and all_hashes and signatures_valid and not errors

    return VerificationResult(
        valid=valid,
        hash_chain_intact=hash_chain_intact,
        signatures_valid=signatures_valid,
        chain_complete=chain_complete,
        artifacts_verified=sum(1 for c in checks if c.ok),
        spec_version=resolved,
        verified_at=verified_at,
        evidence_tier=evidence_tier,
        protocol_envelopes_verified=envelopes,
        cart_payment_binding_verified=binding,
        errors=errors,
        warnings=warnings,
        artifact_checks=checks,
        total_artifacts=counted,
        expected_artifact_count=expected,
        protocol=protocol,
        sealed_bundle_hash=derived_seal,
        seal_valid=seal_valid,
    )
