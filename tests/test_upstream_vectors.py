"""Vectors requested upstream on 2026-11-17: #98 layer presence and #101 field-by-field gate."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from aep_verify.upstream_vectors import (
    AMOUNT_ATOMIC_19,
    DIGITS_12,
    DIGITS_15,
    DIGITS_20,
    PROPOSED_EXEMPT_PATHS,
    chain_complete_by_layers,
    field_gate,
    ingestion_vector,
    layer_vectors,
    passes_luhn,
    rc2_gate,
    required_layers,
    run,
)

COMMITTED = Path(__file__).resolve().parent.parent / "vectors" / "proposals"


def test_every_vector_matches_its_expected_result(tmp_path: Path) -> None:
    results = run(tmp_path)
    assert [r["match"] for r in results["layer"]] == [True, True]
    assert all(r["match"] for r in results["ingestion"])
    assert len(results["ingestion"]) == 7


def test_committed_files_are_the_generated_ones(tmp_path: Path) -> None:
    run(tmp_path)
    for name in (
        "98-direct-web-repeat-fulfillment.json",
        "98-direct-web-missing-cart.json",
        "101-ingestion-gate.json",
    ):
        assert (COMMITTED / name).read_text() == (tmp_path / name).read_text(), name


def test_rc2_counts_give_the_opposite_answer(tmp_path: Path) -> None:
    results = run(tmp_path)
    by_name = {r["vector"]: r for r in results["layer"]}
    repeat = by_name["98-direct-web-repeat-fulfillment"]
    missing = by_name["98-direct-web-missing-cart"]
    assert (repeat["layer_rule"]["chain_complete"], repeat["rc2_chain_complete"]) == (True, False)
    assert (missing["layer_rule"]["chain_complete"], missing["rc2_chain_complete"]) == (False, True)
    assert missing["missing_layers"] == ["cart"]
    assert repeat["rc2_errors"] == [] and missing["rc2_errors"] == []
    assert repeat["seal_valid"] is True and missing["seal_valid"] is True


def test_a_tampered_artifact_cannot_fill_a_layer() -> None:
    vector = layer_vectors()["98-direct-web-repeat-fulfillment"]
    records = copy.deepcopy(vector["artifacts"])
    cart = next(r for r in records if r["artifact_type"] == "cart")
    cart["hash_input"]["payload"]["tax"] += 1  # hash no longer matches
    complete, missing = chain_complete_by_layers(
        records, vector["ed25519_public_key_base64"], "direct_web"
    )
    assert (complete, missing) == (False, ["cart"])


def test_vectors_use_the_published_test_key() -> None:
    keys = json.loads((COMMITTED.parent / "v1.0.3-rc.2" / "keys.json").read_text())
    for vector in layer_vectors().values():
        assert vector["ed25519_public_key_base64"] == keys["public_key_base64"]
        assert vector["transaction_type"] == "direct_web"


def test_required_layers() -> None:
    assert "discovery" not in required_layers("ai_referral_agent_session", False)
    assert "delegation" in required_layers("ai_referral_agent_session", True)
    assert "delegation" not in required_layers("direct_web", True)
    with pytest.raises(ValueError):
        required_layers("ai_referral_standard_checkout", False)  # waits on upstream #79


def test_case_digits_have_the_lengths_and_luhn_status_claimed() -> None:
    for digits, length in ((DIGITS_15, 15), (DIGITS_12, 12), (DIGITS_20, 20)):
        assert len(digits) == length and digits.isdigit() and passes_luhn(digits)
    assert len(AMOUNT_ATOMIC_19) == 19 and passes_luhn(AMOUNT_ATOMIC_19)
    assert int(AMOUNT_ATOMIC_19) == 505 * 10**16  # $5.05 of an 18-decimal token


def test_ingestion_cases_follow_the_editors_list() -> None:
    cases = {c["name"]: c for c in ingestion_vector()["cases"]}
    assert cases["network-transaction-id-15-digit-luhn"]["payload"]["network_transaction_id"] == (
        DIGITS_15
    )
    assert cases["payment-method-token-same-digits"]["payload"]["payment_method_token"] == DIGITS_15
    spaced = cases["payment-method-token-digits-with-spaces"]["payload"]["payment_method_token"]
    hyphen = cases["payment-method-token-digits-with-hyphens"]["payload"]["payment_method_token"]
    assert spaced.replace(" ", "") == DIGITS_15 == hyphen.replace("-", "")
    stable = cases["stablecoin-amount-atomic-19-digit-luhn"]["payload"]
    assert stable["settlement_rail"] == "stablecoin"
    assert stable["stablecoin"]["amount_atomic"] == AMOUNT_ATOMIC_19


def test_rc2_rejects_the_two_listed_field_accepts() -> None:
    cases = {c["name"]: c for c in ingestion_vector()["cases"]}
    assert rc2_gate(cases["network-transaction-id-15-digit-luhn"]["payload"])
    assert rc2_gate(cases["stablecoin-amount-atomic-19-digit-luhn"]["payload"])
    assert not field_gate(cases["network-transaction-id-15-digit-luhn"]["payload"])


def test_field_gate_still_catches_a_card_number_off_the_list() -> None:
    payload = ingestion_vector()["cases"][0]["payload"]
    payload = copy.deepcopy(payload)
    payload["auth_code"] = "4242 4242 4242 4242"
    assert field_gate(payload)
    assert "auth_code" not in PROPOSED_EXEMPT_PATHS


def test_exempt_paths_are_exact_not_suffixes() -> None:
    payload = copy.deepcopy(ingestion_vector()["cases"][0]["payload"])
    payload["stablecoin"] = None
    payload["metadata_note"] = {"network_transaction_id": DIGITS_15}  # nested, not the listed path
    assert field_gate(payload)
