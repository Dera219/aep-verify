"""Post-seal head records and tail coverage: a prototype of the upstream #104 proposal.

Not in v1.0.3-rc.2. This implements the text proposed in
A-Comm-Tech/a-comm-evidence-protocol#104 as amended by the maintainer on 2026-11-10:

* §4.3.1: a head holder outside the exporter's control (a transparency log, or a
  counter-signer such as an Evidence Custodian or the PSP) records `chain_id`,
  `sequence_number`, `current_hash` and `recorded_at` for the seal and for every post-seal
  append, and signs each record.
* The holder's key is obtained from the holder or from a party the recipient already
  trusts. An identifier carried in the bundle only routes the recipient to the holder.
* §6.1 `postSealHeadRecord`: routing (holder identifier, endpoint) plus an optional
  convenience copy of the latest record, which is never treated as the latest head.
* §5 `tail_coverage`: `covered`, `short`, `beyond_record`, `no_record` or `mismatch`, with
  `recorded_through_seq`, `recorded_at`, the holder, and the record's age at verification.
  `short` and `mismatch` fail. `no_record` is neither a pass nor a failure. No maximum age is
  enforced: the age is reported and the recipient's policy decides.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hmac
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonicalize
from .chain import HASH_RE, TIMESTAMP_RE, show

HEAD_RECORD_FIELDS: tuple[str, ...] = (
    "chain_id",
    "sequence_number",
    "current_hash",
    "recorded_at",
    "holder",
)
ROUTE_MEMBER = "postSealHeadRecord"

COVERED = "covered"
SHORT = "short"
BEYOND_RECORD = "beyond_record"
NO_RECORD = "no_record"
MISMATCH = "mismatch"
FAILING: frozenset[str] = frozenset({SHORT, MISMATCH})


class HolderUnreachable(RuntimeError):
    """The head holder gave no answer (network failure, timeout, holder down)."""


class HeadHolder(Protocol):
    def query(self, chain_id: str) -> list[dict[str, Any]]:
        """Every head record the holder has for `chain_id`, in any order."""
        ...


def _signing_input(record: Mapping[str, Any]) -> bytes:
    return canonicalize({f: record[f] for f in HEAD_RECORD_FIELDS})


def sign_head_record(
    key: Ed25519PrivateKey,
    *,
    holder: str,
    chain_id: str,
    sequence_number: int,
    current_hash: str,
    recorded_at: str,
) -> dict[str, Any]:
    """A §4.3.1 head record: the five fields plus an Ed25519 signature over their JCS form."""
    record: dict[str, Any] = {
        "chain_id": chain_id,
        "sequence_number": sequence_number,
        "current_hash": current_hash,
        "recorded_at": recorded_at,
        "holder": holder,
    }
    record["signature"] = base64.b64encode(key.sign(_signing_input(record))).decode("ascii")
    return record


def head_record_problem(
    record: Any, public_key: Ed25519PublicKey, holder: str, chain_id: str
) -> str | None:
    """None when `record` is a well-formed head record from `holder` for `chain_id`."""
    if not isinstance(record, dict):
        return "head record is not an object"
    missing = [f for f in (*HEAD_RECORD_FIELDS, "signature") if f not in record]
    if missing:
        return f"head record missing {missing}"
    seq = record["sequence_number"]
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        return f"head record sequence_number {show(seq)} is not a positive integer"
    if not isinstance(record["current_hash"], str) or not HASH_RE.match(record["current_hash"]):
        return f"head record at seq {seq} has a malformed current_hash"
    if not isinstance(record["recorded_at"], str) or not TIMESTAMP_RE.match(record["recorded_at"]):
        return f"head record at seq {seq} has a malformed recorded_at"
    if record["holder"] != holder:
        return f"head record at seq {seq} names holder {show(record['holder'])}, not {show(holder)}"
    if record["chain_id"] != chain_id:
        return f"head record at seq {seq} is for chain {show(record['chain_id'])}"
    try:
        signature = base64.b64decode(str(record["signature"]), validate=True)
    except (binascii.Error, ValueError):
        return f"head record at seq {seq}: signature is not valid base64"
    try:
        public_key.verify(signature, _signing_input(record))
    except InvalidSignature:
        return (
            f"head record at seq {seq} does not verify against the independently obtained "
            "holder key"
        )
    return None


@dataclass
class StaticHolder:
    """An in-memory head holder: signs a record as each head is appended, answers queries."""

    holder_id: str
    signing_key: Ed25519PrivateKey = field(repr=False)
    _records: dict[str, list[dict[str, Any]]] = field(default_factory=dict, repr=False)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.signing_key.public_key()

    def record(
        self, chain_id: str, sequence_number: int, current_hash: str, recorded_at: str
    ) -> dict[str, Any]:
        rec = sign_head_record(
            self.signing_key,
            holder=self.holder_id,
            chain_id=chain_id,
            sequence_number=sequence_number,
            current_hash=current_hash,
            recorded_at=recorded_at,
        )
        self._records.setdefault(chain_id, []).append(rec)
        return copy.deepcopy(rec)

    def query(self, chain_id: str) -> list[dict[str, Any]]:
        return copy.deepcopy(self._records.get(chain_id, []))


@dataclass
class UnreachableHolder:
    """A holder that never answers, for the `no_record` vector."""

    holder_id: str

    def query(self, chain_id: str) -> list[dict[str, Any]]:
        raise HolderUnreachable(f"{self.holder_id} did not answer")


@dataclass
class TailCoverage:
    status: str
    reason: str
    holder: str | None = None
    recorded_through_seq: int | None = None
    recorded_at: str | None = None
    head_record_age_seconds: int | None = None
    checked_seqs: list[int] = field(default_factory=list)
    not_covered_seqs: list[int] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return self.status in FAILING

    def statement(self) -> str:
        if self.recorded_through_seq is None:
            return f"{self.status}: nothing is claimed about the tail ({self.reason})"
        return (
            f"{self.status}: recorded through seq {self.recorded_through_seq} as of "
            f"{self.recorded_at} by {self.holder}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "recorded_through_seq": self.recorded_through_seq,
            "recorded_at": self.recorded_at,
            "holder": self.holder,
            "head_record_age_seconds": self.head_record_age_seconds,
            "checked_seqs": list(self.checked_seqs),
            "not_covered_seqs": list(self.not_covered_seqs),
            "errors": list(self.errors),
            "notes": list(self.notes),
            "reason": self.reason,
            "statement": self.statement(),
        }


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _seq(artifact: Mapping[str, Any]) -> Any:
    return artifact.get("sequence_number", artifact.get("seq"))


def _kind(artifact: Mapping[str, Any]) -> Any:
    hash_input = artifact.get("hash_input")
    if isinstance(hash_input, dict) and "artifact_type" in hash_input:
        return hash_input["artifact_type"]
    return artifact.get("artifact_type")


def _chain_id(artifacts: list[Any]) -> str | None:
    first = artifacts[0] if artifacts and isinstance(artifacts[0], dict) else {}
    hash_input = first.get("hash_input") if isinstance(first.get("hash_input"), dict) else first
    metadata = hash_input.get("metadata") if isinstance(hash_input, dict) else None
    value = metadata.get("chain_id") if isinstance(metadata, dict) else None
    return value if isinstance(value, str) else None


def tail_coverage(
    bundle: Mapping[str, Any],
    *,
    trusted_holder_keys: Mapping[str, Ed25519PublicKey],
    holders: Mapping[str, HeadHolder],
    verified_at: str,
) -> TailCoverage:
    """Report how far an independent head record reaches into this export (proposed §5).

    `trusted_holder_keys` are holder keys the recipient obtained without the exporter: from
    the holder itself or from a party it already trusts. `holders` are the clients the
    recipient can query, by holder identifier. The bundle's `postSealHeadRecord` only says
    which holder to ask; its convenience copy is never treated as the latest head.

    This checks the tail only. Run it next to `verify_bundle`, which checks the chain.
    """
    artifacts = bundle.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return TailCoverage(NO_RECORD, "the bundle carries no artifacts")

    route = bundle.get(ROUTE_MEMBER)
    holder_id = route.get("holder") if isinstance(route, dict) else None
    if not isinstance(holder_id, str) or not holder_id:
        return TailCoverage(NO_RECORD, f"the bundle identifies no head holder ({ROUTE_MEMBER})")

    key = trusted_holder_keys.get(holder_id)
    if key is None:
        return TailCoverage(
            NO_RECORD,
            f"no independently obtained key for holder {show(holder_id)}; an identifier in "
            "the bundle only routes the recipient to the holder (§4.3.1)",
            holder=holder_id,
        )

    chain_id = _chain_id(artifacts)
    if chain_id is None:
        return TailCoverage(NO_RECORD, "the chain carries no chain_id to query", holder=holder_id)

    client = holders.get(holder_id)
    if client is None:
        return TailCoverage(
            NO_RECORD, f"holder {show(holder_id)} cannot be reached", holder=holder_id
        )
    try:
        answer = client.query(chain_id)
    except HolderUnreachable as exc:
        return TailCoverage(NO_RECORD, f"holder did not answer: {exc}", holder=holder_id)
    if not answer:
        return TailCoverage(
            NO_RECORD, f"holder has no record for chain {show(chain_id)}", holder=holder_id
        )

    for record in answer:
        problem = head_record_problem(record, key, holder_id, chain_id)
        if problem is not None:
            return TailCoverage(
                NO_RECORD, f"no verified answer: {problem} (§4.3.1)", holder=holder_id
            )

    by_seq: dict[int, dict[str, Any]] = {}
    notes: list[str] = []
    for record in answer:
        seq = record["sequence_number"]
        if seq in by_seq and by_seq[seq]["current_hash"] != record["current_hash"]:
            return TailCoverage(
                NO_RECORD,
                f"the holder signed two different hashes at seq {seq}; its answer is not usable",
                holder=holder_id,
            )
        by_seq[seq] = record
    latest_seq = max(by_seq)
    latest = by_seq[latest_seq]
    age = int((_instant(verified_at) - _instant(latest["recorded_at"])).total_seconds())

    if isinstance(route, dict) and isinstance(route.get("latest"), dict):
        copy_seq = route["latest"].get("sequence_number")
        if copy_seq != latest_seq:
            notes.append(
                f"the bundle's convenience copy says seq {show(copy_seq)}; the holder says "
                f"{latest_seq}. The holder's answer is used."
            )

    seal_seq = next((_seq(a) for a in artifacts if _kind(a) == "authorization"), None)
    if not isinstance(seal_seq, int):
        return TailCoverage(
            NO_RECORD,
            "the chain has no authorization artifact, so there is no seal",
            holder=holder_id,
        )

    exported = [a for a in artifacts if isinstance(_seq(a), int) and _seq(a) >= seal_seq]
    checked: list[int] = []
    not_covered: list[int] = []
    errors: list[str] = []
    for artifact in exported:
        seq = _seq(artifact)
        logged = by_seq.get(seq)
        if logged is None:
            if seq > latest_seq:
                not_covered.append(seq)
            else:
                notes.append(f"the holder has no record at seq {seq}, below its recorded head")
            continue
        checked.append(seq)
        stored = artifact.get("current_hash")
        if not (isinstance(stored, str) and hmac.compare_digest(stored, logged["current_hash"])):
            errors.append(
                f"exported artifact at seq {seq} has current_hash {show(stored)} but the holder "
                f"recorded {show(logged['current_hash'])} at that seq (tail_coverage mismatch)"
            )

    last_exported = max(_seq(a) for a in exported) if exported else seal_seq - 1
    common = {
        "holder": holder_id,
        "recorded_through_seq": latest_seq,
        "recorded_at": latest["recorded_at"],
        "head_record_age_seconds": age,
        "checked_seqs": checked,
        "not_covered_seqs": not_covered,
        "notes": notes,
    }
    if errors:
        return TailCoverage(
            MISMATCH,
            "an exported artifact differs from the record at its seq",
            errors=errors,
            **common,
        )
    if last_exported < latest_seq:
        return TailCoverage(
            SHORT,
            f"the export ends at seq {last_exported} but the holder recorded through seq "
            f"{latest_seq}",
            errors=[
                f"export ends at seq {last_exported}; the head holder recorded through seq "
                f"{latest_seq} as of {latest['recorded_at']} (tail_coverage short)"
            ],
            **common,
        )
    if not_covered:
        return TailCoverage(
            BEYOND_RECORD,
            f"seq {', '.join(map(str, not_covered))} verified as a chain but not covered by "
            "any head record",
            **common,
        )
    return TailCoverage(
        COVERED,
        "the export ends at the recorded head and every checked hash matches the record at its seq",
        **common,
    )
