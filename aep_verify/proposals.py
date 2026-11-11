"""Prototype vectors for two upstream proposals, built on the worked dispute in demo.py.

* #104: post-seal head records and `tail_coverage` (see tail.py), run for the "key + head
  log" recipient (H in aep-demo/REPORT.md), plus the two vectors the maintainer asked for on
  2026-11-10: seq 8 replaced by a different artifact (`mismatch`) and an unreachable holder
  (`no_record`, not a failure).
* #102: `transaction_type` bound in the hashed metadata, with the four vectors asked for on
  2026-11-10: the six-artifact GENERIC chain with no bound type (the verifier lists the types
  that fit), a bound type that contradicts the layers, a bound type that differs from the
  bundle's `transactionType`, and a valid chain whose bound type matches.

Neither mechanism is in v1.0.3-rc.2. Everything here is deterministic: Ed25519 signing is.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .bundle import verify_bundle
from .chain import BOUND_TYPE_FIELD
from .demo import (
    CHAIN_ID,
    MERCHANT_KEY,
    MERCHANT_NAME,
    SHIPPING_ADDRESS,
    TRANSACTION_ID,
    VERIFIED_AT,
    _deliver,
    _material,
    _recopy,
    _resign_from,
    _sealed_prefix,
    build_records,
    export,
)
from .keys import public_key_to_base64
from .produce import export_dispute_bundle
from .tail import (
    ROUTE_MEMBER,
    HeadHolder,
    StaticHolder,
    UnreachableHolder,
    tail_coverage,
)

HOLDER_ID = "holder:demo-transparency-log"
HOLDER_KEY = Ed25519PrivateKey.from_private_bytes(_material("head holder signing key"))
FAKE_HOLDER_ID = "holder:merchant-run-log"
FAKE_HOLDER_KEY = Ed25519PrivateKey.from_private_bytes(_material("merchant-run holder key"))
HOLDER_ENDPOINT = "https://heads.example/v1/chains/"
EXPORTED_AT = "2026-10-21T14:00:00Z"


def _digest(value: Any) -> str:
    text = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _route(holder_id: str, latest: dict[str, Any] | None = None) -> dict[str, Any]:
    route: dict[str, Any] = {"holder": holder_id, "endpoint": HOLDER_ENDPOINT + CHAIN_ID}
    if latest is not None:
        route["latest"] = copy.deepcopy(latest)
    return route


def _record_heads(holder: StaticHolder, records: list[dict[str, Any]], through: int) -> None:
    """The holder records the seal and each post-seal head as it arrives, up to seq `through`."""
    seal = next(r["sequence_number"] for r in records if r["artifact_type"] == "authorization")
    for r in records:
        seq = r["sequence_number"]
        if seal <= seq <= through:
            holder.record(CHAIN_ID, seq, r["current_hash"], r["hash_input"]["timestamp"])


# ---------------------------------------------------------------------------------------------
# #104 tail coverage
# ---------------------------------------------------------------------------------------------


@dataclass
class TailVector:
    name: str
    description: str
    bundle: dict[str, Any]
    holder_answer: list[dict[str, Any]] | str
    trusted_holders: list[str]
    expected_status: str
    observed: dict[str, Any] = field(default_factory=dict)
    chain_valid: bool | None = None
    contrast: dict[str, Any] | None = None

    @property
    def as_expected(self) -> bool:
        return self.observed.get("status") == self.expected_status

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "trusted_holders": list(self.trusted_holders),
            "holder_answer": self.holder_answer,
            "expected_status": self.expected_status,
            "observed": self.observed,
            "chain_valid": self.chain_valid,
            "contrast": self.contrast,
            "bundle_sha256": _digest(self.bundle),
        }


def tail_vectors() -> list[TailVector]:
    returned = build_records("returned")  # seal at seq 6, post-seal fulfillments at 7 and 8
    holder = StaticHolder(HOLDER_ID, HOLDER_KEY)
    _record_heads(holder, returned, through=8)
    honest_answer = holder.query(CHAIN_ID)
    latest_copy = honest_answer[-1]
    seq7_copy = next(r for r in honest_answer if r["sequence_number"] == 7)

    lagging = StaticHolder(HOLDER_ID, HOLDER_KEY)
    _record_heads(lagging, returned, through=7)

    fake = StaticHolder(FAKE_HOLDER_ID, FAKE_HOLDER_KEY)
    _record_heads(fake, returned, through=7)

    full = export(returned)
    truncated = export(returned[:7])

    replaced_records = copy.deepcopy(returned)
    eighth = replaced_records[7]["hash_input"]["payload"]
    eighth["status"] = "in_transit"
    eighth["captured_at"] = "2026-09-24T09:00:00Z"
    replaced_records[7]["hash_input"]["timestamp"] = "2026-09-24T09:00:00Z"
    _recopy(replaced_records[7])
    _resign_from(replaced_records, 7, MERCHANT_KEY)
    replaced = export(replaced_records)

    def with_route(bundle: dict[str, Any], route: dict[str, Any] | None) -> dict[str, Any]:
        out = copy.deepcopy(bundle)
        if route is not None:
            out[ROUTE_MEMBER] = route
        return out

    trusted = {HOLDER_ID: HOLDER_KEY.public_key()}
    vectors: list[tuple[TailVector, dict[str, HeadHolder]]] = [
        (
            TailVector(
                "covered",
                "The honest returned-parcel export (8 artifacts). The holder recorded the seal "
                "and both post-seal heads.",
                with_route(full, _route(HOLDER_ID, latest_copy)),
                honest_answer,
                [HOLDER_ID],
                "covered",
            ),
            {HOLDER_ID: holder},
        ),
        (
            TailVector(
                "short",
                "hide-return: the merchant re-exports without the return (7 artifacts). The "
                "chain verifies; the holder recorded through seq 8.",
                with_route(truncated, _route(HOLDER_ID)),
                honest_answer,
                [HOLDER_ID],
                "short",
            ),
            {HOLDER_ID: holder},
        ),
        (
            TailVector(
                "mismatch",
                "Same length, wrong content: seq 8 is replaced by a different artifact (the "
                "return shown still in transit) and re-signed with the merchant key. The chain "
                "verifies.",
                with_route(replaced, _route(HOLDER_ID)),
                honest_answer,
                [HOLDER_ID],
                "mismatch",
            ),
            {HOLDER_ID: holder},
        ),
        (
            TailVector(
                "unreachable-holder",
                "The honest export, but the holder does not answer. Nothing is claimed about "
                "the tail, and the bundle does not fail for it.",
                with_route(full, _route(HOLDER_ID, latest_copy)),
                "unreachable",
                [HOLDER_ID],
                "no_record",
            ),
            {HOLDER_ID: UnreachableHolder(HOLDER_ID)},
        ),
        (
            TailVector(
                "no-holder-named",
                "The truncated export with no postSealHeadRecord at all.",
                with_route(truncated, None),
                [],
                [HOLDER_ID],
                "no_record",
            ),
            {HOLDER_ID: holder},
        ),
        (
            TailVector(
                "fake-holder",
                "The truncated export names a holder the merchant runs, whose records stop at "
                "seq 7. The recipient never obtained that holder's key independently.",
                with_route(truncated, _route(FAKE_HOLDER_ID)),
                fake.query(CHAIN_ID),
                [HOLDER_ID],
                "no_record",
            ),
            {HOLDER_ID: holder, FAKE_HOLDER_ID: fake},
        ),
        (
            TailVector(
                "beyond-record",
                "The honest 8-artifact export, but the holder's records stop at seq 7 (it "
                "never recorded the return). Seq 8 verifies as a chain but is not covered.",
                with_route(full, _route(HOLDER_ID)),
                lagging.query(CHAIN_ID),
                [HOLDER_ID],
                "beyond_record",
            ),
            {HOLDER_ID: lagging},
        ),
        (
            TailVector(
                "stale-convenience-copy",
                "The truncated export carries a genuine but old convenience copy (seq 7). The "
                "holder says seq 8, and the holder's answer wins.",
                with_route(truncated, _route(HOLDER_ID, seq7_copy)),
                honest_answer,
                [HOLDER_ID],
                "short",
            ),
            {HOLDER_ID: holder},
        ),
    ]

    public_key = MERCHANT_KEY.public_key()
    out: list[TailVector] = []
    for vector, reachable in vectors:
        result = tail_coverage(
            vector.bundle,
            trusted_holder_keys=trusted,
            holders=reachable,
            verified_at=VERIFIED_AT,
        )
        vector.observed = result.to_dict()
        vector.chain_valid = verify_bundle(
            vector.bundle, public_key, verified_at=VERIFIED_AT
        ).verification.valid
        if vector.name == "fake-holder":
            naive = tail_coverage(
                vector.bundle,
                trusted_holder_keys={**trusted, FAKE_HOLDER_ID: FAKE_HOLDER_KEY.public_key()},
                holders=reachable,
                verified_at=VERIFIED_AT,
            )
            vector.contrast = {
                "if_the_key_were_taken_from_the_bundle_route": naive.to_dict()["status"],
            }
        out.append(vector)
    return out


# ---------------------------------------------------------------------------------------------
# #102 bound transaction type
# ---------------------------------------------------------------------------------------------


@dataclass
class TypeVector:
    name: str
    description: str
    bundle: dict[str, Any]
    expect_valid: bool
    expect_in_errors: str | None = None
    observed: dict[str, Any] = field(default_factory=dict)

    @property
    def as_expected(self) -> bool:
        if self.observed.get("valid") is not self.expect_valid:
            return False
        if self.expect_in_errors is None:
            return True
        return any(self.expect_in_errors in e for e in self.observed.get("errors", []))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "expect_valid": self.expect_valid,
            "expect_in_errors": self.expect_in_errors,
            "observed": self.observed,
            "bundle_sha256": _digest(self.bundle),
        }


def _six(transaction_type: str, *, bind: bool) -> list[dict[str, Any]]:
    """Referral, intent, policy, cart, authorization, fulfillment: the #102 six-artifact chain."""
    b = _sealed_prefix(
        discovery=False, transaction_type=transaction_type, bind_transaction_type=bind
    )
    _deliver(b, SHIPPING_ADDRESS)
    return b.records


def _export_as(
    records: list[dict[str, Any]], transaction_type: str, *, for_submission: bool = True
) -> dict[str, Any]:
    return export_dispute_bundle(
        records,
        MERCHANT_KEY.public_key(),
        transaction_id=TRANSACTION_ID,
        transaction_type=transaction_type,
        status="disputed",
        merchant_name=MERCHANT_NAME,
        exported_at=EXPORTED_AT,
        verified_at=VERIFIED_AT,
        for_submission=for_submission,
    )


def type_vectors() -> list[TypeVector]:
    unbound = _export_as(build_records("unattributed"), "ai_referral_agent_session")

    contradicted = _six("ai_referral_standard_checkout", bind=True)
    for record in contradicted:
        record["hash_input"]["metadata"][BOUND_TYPE_FIELD] = "direct_web"
    _resign_from(contradicted, 0, MERCHANT_KEY)  # by hand: the producer refuses this chain
    contradicted_bundle = _export_as(contradicted, "direct_web", for_submission=False)

    relabelled = _export_as(
        _six("ai_referral_agent_session", bind=True), "ai_referral_agent_session"
    )
    relabelled["transaction"]["transactionType"] = "ai_referral_standard_checkout"
    relabelled["verification"]["chainComplete"] = True

    matching = _export_as(
        _six("ai_referral_standard_checkout", bind=True), "ai_referral_standard_checkout"
    )

    vectors = [
        TypeVector(
            "unbound-six-artifact",
            "The six-artifact GENERIC chain with no bound type. Valid as a chain; the verifier "
            "lists every type whose layers fit, with its expected count.",
            unbound,
            expect_valid=True,
        ),
        TypeVector(
            "bound-type-contradicts-layers",
            "Bound as direct_web on every artifact, but the chain carries a referral artifact. "
            "Built by hand and re-signed: the producer refuses it at append time.",
            contradicted_bundle,
            expect_valid=False,
            expect_in_errors="is not a layer of transaction type 'direct_web'",
        ),
        TypeVector(
            "bound-type-differs-from-bundle",
            "Bound as ai_referral_agent_session (6 of 7: incomplete). The wrapper is relabelled "
            "ai_referral_standard_checkout with chainComplete true: the retype attack.",
            relabelled,
            expect_valid=False,
            expect_in_errors="differs from the type bound in the hashed metadata",
        ),
        TypeVector(
            "bound-type-matches",
            "Bound as ai_referral_standard_checkout, and the wrapper says the same. Passes, so "
            "a verifier that rejects every bound type cannot pass the other three.",
            matching,
            expect_valid=True,
        ),
    ]
    public_key = MERCHANT_KEY.public_key()
    for vector in vectors:
        result = verify_bundle(vector.bundle, public_key, verified_at=VERIFIED_AT)
        v = result.verification
        vector.observed = {
            "valid": v.valid,
            "chain_complete": v.chain_complete,
            "expected_artifact_count": v.expected_artifact_count,
            "type_binding": v.type_binding,
            "errors": list(v.errors),
            "exportable": result.exportable,
        }
    return vectors


# ---------------------------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------------------------


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def write_proposals(out_dir: Path) -> tuple[list[TailVector], list[TypeVector]]:
    tails, types = tail_vectors(), type_vectors()
    out_dir.mkdir(parents=True, exist_ok=True)
    for sub, vectors in (("104-tail-coverage", tails), ("102-bound-type", types)):
        folder = out_dir / sub
        folder.mkdir(parents=True, exist_ok=True)
        for vector in vectors:
            (folder / f"{vector.name}.bundle.json").write_bytes(_json_bytes(vector.bundle))
        (folder / "results.json").write_bytes(_json_bytes([vector.to_dict() for vector in vectors]))
    (out_dir / "holder-public-key.txt").write_text(
        public_key_to_base64(HOLDER_KEY.public_key()) + "\n", encoding="utf-8"
    )
    return tails, types
