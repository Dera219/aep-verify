"""The demo is a test: every attack must land exactly where it says it lands."""

import hashlib
import json
import re

import pytest

from aep_verify.__main__ import main
from aep_verify.demo import (
    ATTACKS,
    FLAGGED,
    MERCHANT_KEY,
    OUTCOME_MEANINGS,
    OUTSIDER_KEY,
    REFUSED_ANCHOR,
    REFUSED_EVIDENCE,
    REFUSED_LOG,
    UNDETECTED,
    VARIANTS,
    run_demo,
    write_demo,
)
from aep_verify.keys import public_key_to_base64


@pytest.fixture(scope="module")
def run():
    return run_demo()


def _result(run, attack_id):
    return next(r for r in run.results if r.attack.id == attack_id)


@pytest.mark.parametrize("attack", ATTACKS, ids=[a.id for a in ATTACKS])
def test_attack_lands_where_declared(run, attack):
    r = _result(run, attack.id)
    observed = (r.plain.outcome, r.anchored.outcome, r.logged.outcome)
    declared = (attack.expected, attack.expected_anchored, attack.expected_logged)
    assert observed == declared, (r.plain.evidence, r.anchored.evidence, r.logged.evidence)
    if r.plain.outcome != UNDETECTED:
        assert r.plain.evidence  # every detection names its reason


def test_attack_ids_are_unique_and_outcomes_known():
    assert len({a.id for a in ATTACKS}) == len(ATTACKS)
    for a in ATTACKS:
        for outcome in (a.expected, a.expected_anchored, a.expected_logged):
            assert outcome in OUTCOME_MEANINGS
        assert a.variant in VARIANTS


def test_honest_bundles_verify_with_no_noise(run):
    for name, outcome in run.honest.items():
        v = outcome.verification
        assert v.valid and outcome.exportable, (name, v.errors, outcome.gate_reasons)
        assert outcome.warnings == [] and v.warnings == [] and v.errors == []
        assert outcome.wrapper_contradictions == [] and outcome.embedded_disagreements == []
    assert run.honest["returned"].verification.chain_complete is False
    assert run.honest["unattributed"].verification.chain_complete is False  # §3.1 vs App. B


def test_two_forgeries_are_byte_identical_to_the_honest_export(run):
    """No verifier reading only the bundle can tell these from the honest one."""
    twins = {r.attack.id: run.identical_honest(r) for r in run.results}
    assert {k: v for k, v in twins.items() if v} == {
        "forge-delivery-address": "honest",
        "hide-return": "honest",
    }


def test_truncation_raises_chain_complete(run):
    r = _result(run, "hide-return")
    assert run.honest["returned"].verification.chain_complete is False
    assert r.plain.chain_complete is True and r.plain.exportable


def test_relabelling_the_type_makes_the_count_fit(run):
    r = _result(run, "retype-transaction")
    assert run.honest["unattributed"].verification.chain_complete is False
    assert r.plain.chain_complete is True and r.plain.exportable
    assert r.bundle["transaction"]["transactionType"] == "ai_referral_standard_checkout"


def test_each_variant_is_anchored_at_its_own_seal(run):
    assert run.seals["honest"] == run.seals["misdelivered"] == run.seals["returned"]
    assert run.seals["unattributed"] != run.seals["honest"]  # no discovery: different chain
    for name, bundle in run.bundles.items():
        assert bundle["transaction"]["sealedBundleHash"] == run.seals[name]


def test_anchor_catches_exactly_the_pre_seal_rewrite(run):
    gained = [r.attack.id for r in run.results if r.plain.outcome != r.anchored.outcome]
    assert gained == ["upgrade-3ds"]
    assert _result(run, "upgrade-3ds").anchored.outcome == REFUSED_ANCHOR


def test_head_log_closes_the_post_seal_gaps(run):
    undetected = {r.attack.id for r in run.results if r.logged.outcome == UNDETECTED}
    assert undetected == {"unbound-fields", "retype-transaction"}  # wrapper and type: #3, G
    for attack_id in ("hide-return", "forge-delivery-address", "upgrade-3ds"):
        assert _result(run, attack_id).logged.outcome == REFUSED_LOG
    assert "early" in _result(run, "hide-return").logged.evidence
    assert "post-seal head 1" in _result(run, "forge-delivery-address").logged.evidence
    assert "the seal is" in _result(run, "upgrade-3ds").logged.evidence


def test_each_log_starts_at_its_seal(run):
    for name, log in run.heads.items():
        assert log[0] == run.seals[name]
        assert len(log) == 1 + sum(
            a["artifact_type"] in ("fulfillment", "refund") for a in run.bundles[name]["artifacts"]
        )


def test_merchant_rewrites_are_signed_with_the_merchant_key(run):
    from aep_verify.chain import verify_signature

    public = MERCHANT_KEY.public_key()
    for attack_id in ("forge-delivery-address", "upgrade-3ds", "hide-return"):
        for record in _result(run, attack_id).bundle["artifacts"]:
            ok, _ = verify_signature(public, record["current_hash"], record["server_signature"])
            assert ok, attack_id


def test_outsider_key_is_not_the_merchant_key():
    assert public_key_to_base64(OUTSIDER_KEY.public_key()) != public_key_to_base64(
        MERCHANT_KEY.public_key()
    )


def test_the_detection_messages_are_the_specific_ones(run):
    evidence = {r.attack.id: r.plain.evidence for r in run.results}
    assert "recomputed hash does not equal" in evidence["edit-price"]
    assert "server_signature does not verify" in evidence["resign-outsider-key"]
    assert "previous_hash does not equal" in evidence["delete-policy"]
    assert "sealed_bundle_hash does not equal" in evidence["swap-seal"]
    assert "chainComplete=True but re-verification gives False" in evidence["stale-verification"]
    assert "conflicting spec_version" in evidence["spec-version"]
    assert "sealed cart total is 5500" in evidence["shrink-total"]
    assert "delivery_address_match=True" in evidence["flip-address-match"]
    assert "customerHistory" in evidence["fabricate-history"]
    assert _result(run, "fabricate-history").plain.outcome == FLAGGED
    assert _result(run, "flip-address-match").plain.outcome == REFUSED_EVIDENCE


def test_write_demo_is_deterministic_and_self_describing(tmp_path, run):
    first, second = tmp_path / "a", tmp_path / "b"
    write_demo(first, run)
    write_demo(second)
    files = sorted(p.relative_to(first).as_posix() for p in first.rglob("*") if p.is_file())
    assert files == sorted(
        p.relative_to(second).as_posix() for p in second.rglob("*") if p.is_file()
    )
    for name in files:
        assert (first / name).read_bytes() == (second / name).read_bytes(), name

    report = (first / "REPORT.md").read_text()
    for attack in ATTACKS:
        assert f"`{attack.id}`" in report
        assert (first / "attacks" / f"{attack.id}.json").is_file()
    for name, digest in re.findall(r"\| `([^`]+)` \| `([0-9a-f]{64})` \|", report):
        assert hashlib.sha256((first / name).read_bytes()).hexdigest() == digest, name
    assert len(re.findall(r"\| `[^`]+` \| `[0-9a-f]{64}` \|", report)) == len(files) - 1

    results = json.loads((first / "results.json").read_text())
    assert all(a["as_expected"] for a in results["attacks"])
    assert (first / "anchored-seal.txt").read_text().strip() == run.anchored_seal
    assert results["seals"] == run.seals
    assert results["heads"] == run.heads
    assert (first / "anchored-heads" / "returned.txt").read_text().split() == run.heads["returned"]


def test_cli_demo_and_bundle_round_trip(tmp_path, capsys):
    out = tmp_path / "demo"
    assert main(["demo", "--out", str(out)]) == 0
    assert "NOT AS EXPECTED" not in capsys.readouterr().out
    key = str(out / "merchant-public-key.txt")
    seal = (out / "anchored-seal.txt").read_text().strip()
    honest, upgraded = (
        str(out / "bundles" / "honest.json"),
        str(out / "attacks" / "upgrade-3ds.json"),
    )
    assert main(["bundle", honest, "--key", key]) == 0
    assert main(["bundle", honest, "--key", key, "--anchored-seal", seal]) == 0
    assert main(["bundle", upgraded, "--key", key]) == 0  # a forgery the key alone cannot see
    assert main(["bundle", upgraded, "--key", key, "--anchored-seal", seal]) == 1
    assert main(["bundle", honest, "--key", key, "--anchored-seal", "sha256:nope"]) == 2
    log = str(out / "anchored-heads" / "returned.txt")
    returned, cut = (
        str(out / "bundles" / "returned.json"),
        str(out / "attacks" / "hide-return.json"),
    )
    assert main(["bundle", returned, "--key", key, "--anchored-heads", log]) == 0
    assert main(["bundle", cut, "--key", key]) == 0  # truncation the key alone cannot see
    assert main(["bundle", cut, "--key", key, "--anchored-heads", log]) == 1
    inline = ",".join(run_heads := (out / "anchored-heads" / "honest.txt").read_text().split())
    assert main(["bundle", honest, "--key", key, "--anchored-heads", inline]) == 0
    assert len(run_heads) == 2


def test_cli_demo_refuses_a_file_as_output(tmp_path, capsys):
    target = tmp_path / "file"
    target.write_text("x")
    assert main(["demo", "--out", str(target)]) == 2
    assert "not a directory" in capsys.readouterr().err
