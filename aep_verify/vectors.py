"""Run the published §6.3 conformance vectors (a), (b), (h) and keys.json."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonicalize, sha256_of
from .chain import compute_hash, sign_hash, verify_chain, verify_signature
from .keys import private_key_from_seed_base64, public_key_from_base64, public_key_to_base64


@dataclass
class Case:
    vector: str
    name: str
    status: str  # PASS | FAIL | NOTE
    detail: str = ""


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def run_vectors(directory: Path) -> list[Case]:
    cases: list[Case] = []
    keys = _load(directory / "keys.json")
    private = private_key_from_seed_base64(keys["seed_base64"])
    public = public_key_from_base64(keys["public_key_base64"])
    derived = public_key_to_base64(private.public_key())
    cases.append(
        Case(
            "keys",
            "public key derives from seed",
            "PASS" if derived == keys["public_key_base64"] else "FAIL",
            derived,
        )
    )

    h = _load(directory / "h-canonicalization.json")
    for case in h["cases"]:
        outputs = []
        ok = True
        for i, item in enumerate(case["inputs"]):
            canonical = canonicalize(item)
            outputs.append(canonical)
            if canonical != case["expected_canonical"].encode("utf-8"):
                ok = False
                cases.append(
                    Case("h", f"{case['name']} input[{i}] canonical", "FAIL", canonical.decode())
                )
            if sha256_of(item) != case["expected_sha256"]:
                ok = False
                cases.append(
                    Case("h", f"{case['name']} input[{i}] sha256", "FAIL", sha256_of(item))
                )
        if case.get("all_inputs_must_match") and len(set(outputs)) != 1:
            ok = False
            cases.append(Case("h", f"{case['name']} inputs differ", "FAIL"))
        if ok:
            cases.append(Case("h", case["name"], "PASS"))

    a = _load(directory / "a-genesis.json")
    canonical = canonicalize(a["hash_input"])
    cases.append(
        Case(
            "a",
            "genesis canonical bytes",
            "PASS" if canonical == a["canonical_json"].encode() else "FAIL",
        )
    )
    cases.append(
        Case(
            "a",
            "genesis canonical length",
            "PASS" if len(canonical) == a["canonical_utf8_length_bytes"] else "FAIL",
            str(len(canonical)),
        )
    )
    cases.append(
        Case(
            "a",
            "genesis sha256",
            "PASS" if compute_hash(a["hash_input"]) == a["expected_sha256"] else "FAIL",
            compute_hash(a["hash_input"]),
        )
    )

    b = _load(directory / "b-chain.json")
    previous = None
    for art in b["artifacts"]:
        n = art["sequence_number"]
        hi = art["hash_input"]
        canon_ok = canonicalize(hi) == art["canonical_json"].encode()
        computed = compute_hash(hi)
        hash_ok = computed == art["current_hash"]
        link_ok = hi["previous_hash"] == previous
        sig_ok, reason = verify_signature(public, art["current_hash"], art["server_signature"])
        resign_ok = sign_hash(private, art["current_hash"]) == art["server_signature"]
        for name, ok, detail in (
            ("canonical bytes", canon_ok, ""),
            ("current_hash", hash_ok, computed),
            ("previous_hash link", link_ok, ""),
            ("server_signature verifies", sig_ok, reason or ""),
            ("server_signature reproduced from seed", resign_ok, ""),
        ):
            cases.append(
                Case(
                    "b",
                    f"artifact {n} ({hi['artifact_type']}) {name}",
                    "PASS" if ok else "FAIL",
                    detail,
                )
            )
        previous = art["current_hash"]
    auth = next(x for x in b["artifacts"] if x["artifact_type"] == "authorization")
    cases.append(
        Case(
            "b",
            "sealed_bundle_hash == authorization current_hash (§2.5)",
            "PASS" if b["sealed_bundle_hash"] == auth["current_hash"] else "FAIL",
        )
    )
    result = verify_chain(
        b["artifacts"],
        public,
        transaction_type=b["transaction_type"],
        sealed_bundle_hash=b["sealed_bundle_hash"],
    )
    cases.append(
        Case(
            "b", "verify_chain valid", "PASS" if result.valid else "FAIL", "; ".join(result.errors)
        )
    )
    cases.append(
        Case("b", "verify_chain hash_chain_intact", "PASS" if result.hash_chain_intact else "FAIL")
    )
    cases.append(
        Case("b", "verify_chain signatures_valid", "PASS" if result.signatures_valid else "FAIL")
    )
    cases.append(
        Case(
            "b",
            "verify_chain artifacts_verified == 8",
            "PASS" if result.artifacts_verified == 8 else "FAIL",
            str(result.artifacts_verified),
        )
    )
    cases.append(Case("b", "verify_chain seal_valid", "PASS" if result.seal_valid else "FAIL"))
    cases.append(
        Case(
            "b",
            "chain_complete (Appendix B, protocol-based)",
            "NOTE",
            f"chain_complete={result.chain_complete} "
            f"expected={result.expected_artifact_count} total={result.total_artifacts}",
        )
    )
    for w in result.warnings:
        cases.append(Case("b", "warning", "NOTE", w))
    return cases


def format_report(cases: list[Case]) -> str:
    lines = [
        f"{c.status:4} ({c.vector}) {c.name}" + (f" -- {c.detail}" if c.detail else "")
        for c in cases
    ]
    passed = sum(c.status == "PASS" for c in cases)
    failed = sum(c.status == "FAIL" for c in cases)
    lines.append(
        f"\n{passed} passed, {failed} failed, {sum(c.status == 'NOTE' for c in cases)} notes"
    )
    return "\n".join(lines)
