"""Conformance vectors requested upstream on 2026-11-17, for proposals not yet in v1.0.3-rc.2.

* #98, layer presence: `chain_complete` is true when every layer expected for the transaction
  type is present at least once among artifacts whose hash and signature checks pass. Two
  `direct_web` chains, as the editor specified: a repeat fulfillment (6 artifacts, complete) and
  a chain missing its cart (5 artifacts, incomplete). Both are built from vector (b)'s payloads
  and signed with the published test key in `vectors/v1.0.3-rc.2/keys.json`.
* #101, the ingestion gate: the proposed §8.3 text runs the Luhn check field by field and skips a
  closed list of exempt field paths. Seven §3.6 Authorization payloads, each with an expected
  `accept` or `reject`, in the `h-canonicalization.json` layout.

Neither rule is in rc.2: under rc.2 as written, the two layer chains get the opposite
`chain_complete` (Appendix B compares counts), and the ingestion cases that put Luhn-passing
digits in an exempt field are rejects. `run()` reports both readings side by side.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonicalize
from .chain import compute_hash, sign_hash, verify_chain
from .keys import private_key_from_seed_base64, public_key_to_base64
from .produce import check_payload

RC2_DIR = Path(__file__).resolve().parent.parent / "vectors" / "v1.0.3-rc.2"
SPEC_VERSION = "aep-1.0.3-rc.2"
VERIFIED_AT = "2026-11-20T12:00:00Z"

# --------------------------------------------------------------------------------------------
# #98: layer presence
# --------------------------------------------------------------------------------------------

# Proposed layer sets (#98 layer rule, #103 discovery line, #96 delegation by presence). Only the
# types the thread has settled; ai_referral_standard_checkout waits on #79.
PROPOSED_REQUIRED_LAYERS: dict[str, frozenset[str]] = {
    "direct_web": frozenset({"intent", "policy", "cart", "authorization", "fulfillment"}),
    "ai_referral_agent_session": frozenset(
        {"referral", "intent", "policy", "cart", "authorization", "fulfillment"}
    ),
}


def required_layers(transaction_type: str, delegation_present: bool) -> frozenset[str]:
    """The proposed `requiredLayers`: discovery never counts; delegation counts when present."""
    if transaction_type not in PROPOSED_REQUIRED_LAYERS:
        raise ValueError(f"no settled layer set for {transaction_type!r} (see upstream #79)")
    layers = PROPOSED_REQUIRED_LAYERS[transaction_type]
    if delegation_present and transaction_type != "direct_web":
        layers = layers | {"delegation"}
    return layers


def chain_complete_by_layers(
    records: list[dict[str, Any]], public_key_b64: str, transaction_type: str
) -> tuple[bool, list[str]]:
    """(chain_complete, missing_layers) under the proposed rule; only verified artifacts count."""
    from .keys import public_key_from_base64

    result = verify_chain(
        records,
        public_key_from_base64(public_key_b64),
        transaction_type=transaction_type,
        verified_at=VERIFIED_AT,
    )
    present = {
        str(check.artifact_type)
        for check in result.artifact_checks
        if check.hash_matches and check.signature_valid and check.link_valid
    }
    delegation = any(r["artifact_type"] == "delegation" for r in records)
    missing = sorted(required_layers(transaction_type, delegation) - present)
    return not missing, missing


def _test_key() -> tuple[Ed25519PrivateKey, str]:
    keys = json.loads((RC2_DIR / "keys.json").read_text())
    private = private_key_from_seed_base64(keys["seed_base64"])
    public = public_key_to_base64(private.public_key())
    if public != keys["public_key_base64"]:
        raise RuntimeError("keys.json seed does not derive its published public key")
    return private, public


def _b_inputs() -> dict[str, dict[str, Any]]:
    b = json.loads((RC2_DIR / "b-chain.json").read_text())
    return {a["artifact_type"]: a["hash_input"] for a in b["artifacts"]}


def _direct_web_steps() -> dict[str, dict[str, Any]]:
    """Vector (b)'s payloads, re-homed to direct_web: no agent, so the buyer is the actor and
    interaction_channel is null (§2.4). Two fulfillment events share one fulfillment_id."""
    b = _b_inputs()
    buyer = b["cart"]["actor_id"]
    steps: dict[str, dict[str, Any]] = {}
    for kind in ("intent", "policy", "cart", "authorization"):
        step = copy.deepcopy(b[kind])
        if kind in ("intent", "cart"):
            step["actor_type"] = "user"
            step["actor_id"] = buyer
        step["interaction_channel"] = None
        steps[kind] = step

    # Vector (b)'s authorization omits the §3.6 cross-artifact fields; add them so the only
    # thing these vectors test is layer presence.
    steps["authorization"]["payload"]["captured_at"] = steps["authorization"]["timestamp"]
    steps["authorization"]["payload"]["idempotency_key"] = "vec-authorization-001"

    delivered = copy.deepcopy(b["fulfillment"])
    delivered["timestamp"] = delivered["payload"]["captured_at"]
    in_transit = copy.deepcopy(delivered)
    in_transit["payload"].update(
        status="in_transit",
        delivered_at=None,
        captured_at="2026-07-01T12:31:00Z",
        idempotency_key="vec-fulfillment-in-transit-001",
    )
    in_transit["timestamp"] = "2026-07-01T12:31:00Z"
    delivered["payload"]["idempotency_key"] = "vec-fulfillment-delivered-001"
    steps["fulfillment:in_transit"] = in_transit
    steps["fulfillment:delivered"] = delivered
    return steps


def _sign_chain(steps: list[dict[str, Any]], private: Ed25519PrivateKey) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    previous: str | None = None
    for i, step in enumerate(steps, start=1):
        hash_input = copy.deepcopy(step)
        hash_input["previous_hash"] = previous
        current = compute_hash(hash_input)
        records.append(
            {
                "sequence_number": i,
                "artifact_type": hash_input["artifact_type"],
                "hash_input": hash_input,
                "canonical_json": canonicalize(hash_input).decode("utf-8"),
                "current_hash": current,
                "server_signature": sign_hash(private, current),
            }
        )
        previous = current
    return records


LAYER_VECTORS: tuple[tuple[str, str, tuple[str, ...], bool], ...] = (
    (
        "98-direct-web-repeat-fulfillment",
        "Repeat fulfillment: intent, policy, cart, authorization, fulfillment (in_transit), "
        "fulfillment (delivered). Every expected layer is present and fulfillment repeats, so "
        "chain_complete is true under the proposed layer rule. Under rc.2 as written, Appendix B "
        "compares the count (6) with 5 and returns false.",
        (
            "intent",
            "policy",
            "cart",
            "authorization",
            "fulfillment:in_transit",
            "fulfillment:delivered",
        ),
        True,
    ),
    (
        "98-direct-web-missing-cart",
        "Missing cart: intent, policy, authorization, fulfillment (in_transit), fulfillment "
        "(delivered). Five artifacts, but the cart layer is absent and fulfillment repeats, so "
        "chain_complete is false under the proposed layer rule. Under rc.2 as written, Appendix B "
        "compares the count (5) with 5 and returns true.",
        ("intent", "policy", "authorization", "fulfillment:in_transit", "fulfillment:delivered"),
        False,
    ),
)


def layer_vectors() -> dict[str, dict[str, Any]]:
    private, public = _test_key()
    steps = _direct_web_steps()
    out: dict[str, dict[str, Any]] = {}
    for name, description, order, complete in LAYER_VECTORS:
        records = _sign_chain([steps[s] for s in order], private)
        seal = next(r["current_hash"] for r in records if r["artifact_type"] == "authorization")
        out[name] = {
            "description": description,
            "spec_version": SPEC_VERSION,
            "proposal": "upstream #98 layer rule (not in v1.0.3-rc.2); direct_web expected "
            "layers per §2.2 until #77 is decided",
            "transaction_type": "direct_web",
            "ed25519_public_key_base64": public,
            "sealed_bundle_hash": seal,
            "artifacts": records,
            "expected_verification": {
                "valid": True,
                "hash_chain_intact": True,
                "signatures_valid": True,
                "chain_complete": complete,
                "artifacts_verified": len(records),
            },
        }
    return out


# --------------------------------------------------------------------------------------------
# #101: field-by-field ingestion gate
# --------------------------------------------------------------------------------------------

# §8.3 reference regex, verbatim from rc.2: /\b(\d[ -]?){13,19}\b/g
RC2_PAN_REGEX = re.compile(r"\b(?:\d[ -]?){13,19}\b")

# Proposed §8.3 closed list (#101, 2026-11-13): exact field paths in the §3.6 payload.
PROPOSED_EXEMPT_PATHS: frozenset[str] = frozenset(
    {
        "network_transaction_id",
        "charge_id",
        "payment_intent_id",
        "ds_transaction_id",
        "idempotency_key",
        "mit_mandate_ref",
        "stablecoin.amount_atomic",
    }
)


def passes_luhn(digits: str) -> bool:
    """§8.3 passesLuhn, ported line for line (non-digits are stripped first)."""
    d = re.sub(r"\D", "", digits)
    total = 0
    odd = False
    for ch in reversed(d):
        n = int(ch)
        if odd:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        odd = not odd
    return total % 10 == 0


def rc2_gate(payload: dict[str, Any]) -> list[str]:
    """§8.3 containsRawPaymentCredentials as written: one scan over JSON.stringify(payload)."""
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return [m.group() for m in RC2_PAN_REGEX.finditer(text) if passes_luhn(m.group())]


def _leaves(value: Any, path: str) -> list[tuple[str, str]]:
    if isinstance(value, dict):
        out: list[tuple[str, str]] = []
        for key, item in value.items():
            out += _leaves(item, f"{path}.{key}" if path else str(key))
        return out
    if isinstance(value, list):
        out = []
        for i, item in enumerate(value):
            out += _leaves(item, f"{path}[{i}]")
        return out
    if isinstance(value, bool) or value is None:
        return []
    if isinstance(value, (int, str)):
        return [(path, str(value))]
    return []


def field_gate(payload: dict[str, Any]) -> list[str]:
    """Proposed §8.3: the same regex and Luhn test, field by field, skipping exempt paths."""
    hits = []
    for path, text in _leaves(payload, ""):
        if path in PROPOSED_EXEMPT_PATHS:
            continue
        for m in RC2_PAN_REGEX.finditer(text):
            if passes_luhn(m.group()):
                hits.append(f"{path}: {m.group()!r}")
    return hits


def luhn_complete(prefix: str) -> str:
    """Append the check digit that makes prefix + digit pass Luhn."""
    for check in "0123456789":
        if passes_luhn(prefix + check):
            return prefix + check
    raise AssertionError("unreachable")


DIGITS_15 = luhn_complete("82910456712345")  # 15 digits; leading 8 is no card network prefix
DIGITS_12 = luhn_complete("82910456712")
DIGITS_20 = luhn_complete("8291045671234567890")
# 19 base units of an 18-decimal token: $5.05 = 5.05e18. 505 x 10^16 passes Luhn exactly
# (5 + 2*0 + 5 = 10, zeros add nothing), so the amount and the base units agree.
AMOUNT_ATOMIC_19 = "5050000000000000000"


def _grouped(digits: str, sep: str) -> str:
    return sep.join(digits[i : i + 4] for i in range(0, len(digits), 4))


def _card_authorization() -> dict[str, Any]:
    """Vector (b)'s card authorization, with the §3.6 cross-artifact fields it omits."""
    payload: dict[str, Any] = copy.deepcopy(_b_inputs()["authorization"]["payload"])
    payload["captured_at"] = "2026-07-01T12:06:00Z"
    payload["idempotency_key"] = "vec-authorization-001"
    return payload


def _stablecoin_authorization() -> dict[str, Any]:
    payload = _card_authorization()
    for name in (
        "network_transaction_id", "card_brand", "card_last4", "card_funding", "card_country",
        "avs_result", "cvv_result", "three_ds_result", "three_ds_version", "fraud_score",
        "fraud_engine",
    ):  # fmt: skip
        payload[name] = None
    payload.update(
        psp="vector_stablecoin_psp",
        payment_method_type="wallet_other",
        amount=505,
        settlement_rail="stablecoin",
        stablecoin={
            "chain": "eip155:1",
            "asset": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
            "transaction_hash": "0x" + "a1b2c3d4" * 8,
            "amount_atomic": AMOUNT_ATOMIC_19,
        },
    )
    return payload


@dataclass(frozen=True)
class IngestionCase:
    name: str
    description: str
    payload: dict[str, Any]
    expected: str


def ingestion_cases() -> list[IngestionCase]:
    def card(**changes: Any) -> dict[str, Any]:
        p = _card_authorization()
        p.update(changes)
        return p

    return [
        IngestionCase(
            "network-transaction-id-15-digit-luhn",
            "A Luhn-passing 15-digit network_transaction_id. The field is on the closed list, so "
            "the field-by-field gate skips it. rc.2's serialized scan rejects it.",
            card(network_transaction_id=DIGITS_15),
            "accept",
        ),
        IngestionCase(
            "payment-method-token-same-digits",
            "The same 15 digits in payment_method_token, which is not on the list.",
            card(payment_method_token=DIGITS_15),
            "reject",
        ),
        IngestionCase(
            "stablecoin-amount-atomic-19-digit-luhn",
            "A Luhn-passing 19-digit stablecoin.amount_atomic ($5.05 of an 18-decimal token). "
            "The path is on the closed list. rc.2's serialized scan rejects it.",
            _stablecoin_authorization(),
            "accept",
        ),
        IngestionCase(
            "payment-method-token-digits-with-spaces",
            "The digits from the previous token case grouped by single spaces; the regex allows "
            "one space between digits.",
            card(payment_method_token=_grouped(DIGITS_15, " ")),
            "reject",
        ),
        IngestionCase(
            "payment-method-token-digits-with-hyphens",
            "The same digits grouped by single hyphens; the regex allows one hyphen between "
            "digits.",
            card(payment_method_token=_grouped(DIGITS_15, "-")),
            "reject",
        ),
        IngestionCase(
            "payment-method-token-12-digit-luhn",
            "A Luhn-passing 12-digit value in payment_method_token: below the 13-digit floor.",
            card(payment_method_token=DIGITS_12),
            "accept",
        ),
        IngestionCase(
            "payment-method-token-20-digit-luhn",
            "A Luhn-passing 20-digit value in payment_method_token: above the 19-digit ceiling, "
            "and \\b stops the regex matching any 13-19 digit slice of it.",
            card(payment_method_token=DIGITS_20),
            "accept",
        ),
    ]


def ingestion_vector() -> dict[str, Any]:
    return {
        "description": "Ingestion-gate vectors for the proposed §8.3 field list (upstream #101). "
        "Each case is a §3.6 Authorization payload and the expected result of the Luhn gate run "
        "field by field: every leaf string or integer is scanned with the §8.3 PAN regex "
        "(/\\b(\\d[ -]?){13,19}\\b/) and passesLuhn, except the exact paths "
        + ", ".join(sorted(PROPOSED_EXEMPT_PATHS))
        + ". Not valid under v1.0.3-rc.2: rc.2 rejects both accept cases that use a listed field.",
        "spec_version": "aep-1.0.3-rc.2 + proposed §8.3 field list (#101)",
        "exempt_paths": sorted(PROPOSED_EXEMPT_PATHS),
        "cases": [
            {
                "name": c.name,
                "description": c.description,
                "payload": c.payload,
                "expected": c.expected,
            }
            for c in ingestion_cases()
        ],
    }


# --------------------------------------------------------------------------------------------
# Run and report
# --------------------------------------------------------------------------------------------


def run(out_dir: Path) -> dict[str, Any]:
    """Write the three vector files, re-verify each from disk, and return the results."""
    from .keys import public_key_from_base64

    out_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, Any] = {"layer": [], "ingestion": []}

    for name, vector in layer_vectors().items():
        path = out_dir / f"{name}.json"
        path.write_text(json.dumps(vector, indent=2, ensure_ascii=False) + "\n")
        loaded = json.loads(path.read_text())
        rc2 = verify_chain(
            loaded["artifacts"],
            public_key_from_base64(loaded["ed25519_public_key_base64"]),
            transaction_type=loaded["transaction_type"],
            sealed_bundle_hash=loaded["sealed_bundle_hash"],
            verified_at=VERIFIED_AT,
        )
        complete, missing = chain_complete_by_layers(
            loaded["artifacts"], loaded["ed25519_public_key_base64"], loaded["transaction_type"]
        )
        observed = {
            "valid": rc2.valid,
            "hash_chain_intact": rc2.hash_chain_intact,
            "signatures_valid": rc2.signatures_valid,
            "chain_complete": complete,
            "artifacts_verified": rc2.artifacts_verified,
        }
        results["layer"].append(
            {
                "vector": name,
                "artifacts": [a["artifact_type"] for a in loaded["artifacts"]],
                "expected": loaded["expected_verification"],
                "layer_rule": observed,
                "missing_layers": missing,
                "rc2_chain_complete": rc2.chain_complete,
                "rc2_errors": rc2.errors,
                "seal_valid": rc2.seal_valid,
                "match": observed == loaded["expected_verification"],
            }
        )

    vector = ingestion_vector()
    path = out_dir / "101-ingestion-gate.json"
    path.write_text(json.dumps(vector, indent=2, ensure_ascii=False) + "\n")
    loaded = json.loads(path.read_text())
    for case in loaded["cases"]:
        hits = field_gate(case["payload"])
        rc2_hits = rc2_gate(case["payload"])
        other = [p for p in check_payload("authorization", case["payload"]) if "Luhn" not in p]
        got = "reject" if hits else "accept"
        results["ingestion"].append(
            {
                "case": case["name"],
                "expected": case["expected"],
                "field_gate": got,
                "field_gate_hits": hits,
                "rc2_gate": "reject" if rc2_hits else "accept",
                "other_schema_problems": other,
                "match": got == case["expected"] and not other,
            }
        )
    (out_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    return results


def format_report(results: dict[str, Any]) -> str:
    lines = ["#98 layer presence (direct_web, test key from keys.json)", ""]
    lines.append("| vector | artifacts | valid | hash | sigs | layer rule | rc.2 count | match |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for r in results["layer"]:
        o = r["layer_rule"]
        lines.append(
            f"| {r['vector']} | {o['artifacts_verified']} | {o['valid']} | "
            f"{o['hash_chain_intact']} | {o['signatures_valid']} | {o['chain_complete']} | "
            f"{r['rc2_chain_complete']} | {'PASS' if r['match'] else 'FAIL'} |"
        )
    lines += ["", "#101 ingestion gate (field by field vs rc.2 serialized scan)", ""]
    lines.append("| case | expected | field gate | rc.2 | match |")
    lines.append("|---|---|---|---|---|")
    for r in results["ingestion"]:
        lines.append(
            f"| {r['case']} | {r['expected']} | {r['field_gate']} | {r['rc2_gate']} | "
            f"{'PASS' if r['match'] else 'FAIL'} |"
        )
    return "\n".join(lines)
