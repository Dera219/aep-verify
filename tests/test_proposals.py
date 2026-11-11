"""Prototypes of upstream #102 (bound transaction type) and #104 (tail coverage)."""

from __future__ import annotations

import copy
import json

import pytest

from aep_verify.__main__ import main
from aep_verify.chain import BOUND_TYPE_FIELD, verify_chain
from aep_verify.demo import CHAIN_ID, MERCHANT_KEY, VERIFIED_AT, build_records, export
from aep_verify.produce import ChainBuilder
from aep_verify.proposals import (
    HOLDER_ID,
    HOLDER_KEY,
    _record_heads,
    _six,
    tail_vectors,
    type_vectors,
)
from aep_verify.tail import (
    NO_RECORD,
    ROUTE_MEMBER,
    StaticHolder,
    sign_head_record,
    tail_coverage,
)

# ---------------------------------------------------------------------------------------------
# #104
# ---------------------------------------------------------------------------------------------

TAIL = {v.name: v for v in tail_vectors()}


@pytest.mark.parametrize("name", sorted(TAIL))
def test_tail_vector_outcome(name: str) -> None:
    vector = TAIL[name]
    assert vector.as_expected, vector.observed
    # Every vector's chain verifies: what separates them is evidence outside the bundle.
    assert vector.chain_valid is True


def test_failing_statuses_carry_errors_and_others_do_not() -> None:
    for vector in TAIL.values():
        status, errors = vector.observed["status"], vector.observed["errors"]
        assert bool(errors) == (status in {"short", "mismatch"}), vector.name


def test_mismatch_names_the_seq_and_both_hashes() -> None:
    (error,) = TAIL["mismatch"].observed["errors"]
    assert "seq 8" in error and error.count("sha256:") == 2


def test_unreachable_holder_is_not_a_failure() -> None:
    observed = TAIL["unreachable-holder"].observed
    assert observed["status"] == NO_RECORD and observed["errors"] == []
    assert observed["recorded_through_seq"] is None


def test_fake_holder_would_pass_if_its_key_came_from_the_bundle() -> None:
    vector = TAIL["fake-holder"]
    assert vector.observed["status"] == NO_RECORD
    assert vector.contrast == {"if_the_key_were_taken_from_the_bundle_route": "covered"}


def test_result_reports_reach_and_age_but_sets_no_limit() -> None:
    observed = TAIL["covered"].observed
    assert observed["recorded_through_seq"] == 8
    assert observed["recorded_at"] == "2026-09-25T16:20:00Z"
    assert observed["head_record_age_seconds"] == 2_238_000  # 25 days 21h40m before VERIFIED_AT
    assert observed["statement"].startswith("covered: recorded through seq 8 as of")


def _honest() -> tuple[dict, StaticHolder]:
    records = build_records("returned")
    holder = StaticHolder(HOLDER_ID, HOLDER_KEY)
    _record_heads(holder, records, through=8)
    bundle = export(records)
    bundle[ROUTE_MEMBER] = {"holder": HOLDER_ID}
    return bundle, holder


class _Answer:
    def __init__(self, records: list[dict]) -> None:
        self.records = records

    def query(self, chain_id: str) -> list[dict]:
        return copy.deepcopy(self.records)


def _run(bundle: dict, client) -> str:
    return tail_coverage(
        bundle,
        trusted_holder_keys={HOLDER_ID: HOLDER_KEY.public_key()},
        holders={HOLDER_ID: client},
        verified_at=VERIFIED_AT,
    ).status


def test_altered_head_record_is_no_verified_answer() -> None:
    bundle, holder = _honest()
    answer = holder.query(CHAIN_ID)
    answer[-1]["sequence_number"] = 7  # an edit after signing: the signature no longer covers it
    assert _run(bundle, _Answer(answer)) == NO_RECORD


def test_record_signed_by_another_key_is_no_verified_answer() -> None:
    bundle, holder = _honest()
    answer = holder.query(CHAIN_ID)
    last = answer[-1]
    answer[-1] = sign_head_record(
        MERCHANT_KEY,
        holder=HOLDER_ID,
        chain_id=CHAIN_ID,
        sequence_number=last["sequence_number"],
        current_hash=last["current_hash"],
        recorded_at=last["recorded_at"],
    )
    assert _run(bundle, _Answer(answer)) == NO_RECORD


def test_holder_that_signed_two_hashes_at_one_seq_is_not_usable() -> None:
    bundle, holder = _honest()
    answer = holder.query(CHAIN_ID)
    first = answer[0]
    answer.append(
        sign_head_record(
            HOLDER_KEY,
            holder=HOLDER_ID,
            chain_id=CHAIN_ID,
            sequence_number=first["sequence_number"],
            current_hash="sha256:" + "0" * 64,
            recorded_at=first["recorded_at"],
        )
    )
    assert _run(bundle, _Answer(answer)) == NO_RECORD


@pytest.mark.parametrize(
    "answer",
    [[{"not": "a record"}], ["string"], [{}]],
)
def test_hostile_holder_answers_never_crash(answer: list) -> None:
    bundle, _ = _honest()
    assert _run(bundle, _Answer(answer)) == NO_RECORD


def test_record_for_another_chain_is_rejected() -> None:
    bundle, holder = _honest()
    answer = holder.query(CHAIN_ID)
    other = StaticHolder(HOLDER_ID, HOLDER_KEY)
    rec = answer[-1]
    answer[-1] = other.record(
        "chain_other", rec["sequence_number"], rec["current_hash"], rec["recorded_at"]
    )
    assert _run(bundle, _Answer(answer)) == NO_RECORD


# ---------------------------------------------------------------------------------------------
# #102
# ---------------------------------------------------------------------------------------------

TYPES = {v.name: v for v in type_vectors()}


@pytest.mark.parametrize("name", sorted(TYPES))
def test_type_vector_outcome(name: str) -> None:
    assert TYPES[name].as_expected, TYPES[name].observed


def test_unbound_chain_lists_both_fitting_types() -> None:
    candidates = TYPES["unbound-six-artifact"].observed["type_binding"]["candidates"]
    assert candidates == [
        {
            "transaction_type": "ai_referral_agent_session",
            "expected_artifact_count": 7,
            "chain_complete": False,
        },
        {
            "transaction_type": "ai_referral_standard_checkout",
            "expected_artifact_count": 6,
            "chain_complete": True,
        },
    ]


def test_relabel_keeps_the_bound_answer() -> None:
    observed = TYPES["bound-type-differs-from-bundle"].observed
    assert observed["chain_complete"] is False and observed["expected_artifact_count"] == 7
    assert observed["exportable"] is False


def test_producer_binds_the_type_on_every_artifact() -> None:
    records = _six("ai_referral_standard_checkout", bind=True)
    assert {r["hash_input"]["metadata"][BOUND_TYPE_FIELD] for r in records} == {
        "ai_referral_standard_checkout"
    }
    # With no type supplied at all, the bound one decides completeness.
    result = verify_chain(records, MERCHANT_KEY.public_key(), verified_at=VERIFIED_AT)
    assert result.valid and result.chain_complete
    assert result.type_binding is not None and result.type_binding["source"] == "metadata"


def test_producer_still_refuses_a_layer_outside_the_bound_type() -> None:
    builder = ChainBuilder(
        transaction_type="direct_web",
        chain_id="c",
        merchant_id="m",
        session_id_hash="sha256:" + "a" * 64,
        signing_key=MERCHANT_KEY,
        bind_transaction_type=True,
    )
    with pytest.raises(ValueError, match="not a layer of direct_web"):
        builder.append(
            "referral",
            actor_type="user",
            actor_id="user:x",
            timestamp="2026-09-14T15:00:00Z",
            payload={},
        )


def _rebind(records: list[dict], values: list[object | None]) -> list[dict]:
    from aep_verify.demo import _resign_from

    out = copy.deepcopy(records)
    for record, value in zip(out, values, strict=True):
        meta = record["hash_input"]["metadata"]
        if value is None:
            meta.pop(BOUND_TYPE_FIELD, None)
        else:
            meta[BOUND_TYPE_FIELD] = value
    _resign_from(out, 0, MERCHANT_KEY)
    return out


def test_partial_binding_is_an_error() -> None:
    records = _six("ai_referral_standard_checkout", bind=True)
    partial = _rebind(records, ["ai_referral_standard_checkout"] * 5 + [None])
    result = verify_chain(partial, MERCHANT_KEY.public_key(), verified_at=VERIFIED_AT)
    assert not result.valid
    assert any("on 5 of 6 artifacts" in e for e in result.errors)


def test_conflicting_binding_is_an_error() -> None:
    records = _six("ai_referral_standard_checkout", bind=True)
    mixed = _rebind(records, ["ai_referral_standard_checkout"] * 5 + ["ai_referral_agent_session"])
    result = verify_chain(mixed, MERCHANT_KEY.public_key(), verified_at=VERIFIED_AT)
    assert any("conflicting metadata.transaction_type" in e for e in result.errors)


@pytest.mark.parametrize("value", ["storefront", 7, {"t": 1}])
def test_unknown_or_malformed_bound_type_is_an_error(value: object) -> None:
    records = _six("ai_referral_standard_checkout", bind=True)
    bad = _rebind(records, [value] * 6)
    result = verify_chain(bad, MERCHANT_KEY.public_key(), verified_at=VERIFIED_AT)
    assert not result.valid
    assert any("unknown bound metadata.transaction_type" in e for e in result.errors)


def test_unbound_chains_behave_exactly_as_before() -> None:
    honest = export(build_records("honest"))
    result = verify_chain(
        honest["artifacts"],
        MERCHANT_KEY.public_key(),
        transaction_type="ai_referral_agent_session",
        verified_at=VERIFIED_AT,
    )
    assert result.valid and result.chain_complete and result.warnings == []


# ---------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------


def test_cli_writes_the_vectors(tmp_path, capsys) -> None:
    assert main(["proposals", "--out", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "NOT AS EXPECTED" not in out
    tail_results = json.loads((tmp_path / "104-tail-coverage" / "results.json").read_text())
    assert [r["observed"]["status"] for r in tail_results] == [
        "covered",
        "short",
        "mismatch",
        "no_record",
        "no_record",
        "no_record",
        "beyond_record",
        "short",
    ]
    assert (tmp_path / "102-bound-type" / "bound-type-matches.bundle.json").is_file()
