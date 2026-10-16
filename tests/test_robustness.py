"""Hostile input. A verifier may refuse anything; it may never crash, hang or amplify.

Each targeted case below is a crash a structural fuzzer found in an earlier version. The seeded
fuzz at the end keeps the class closed: every mutation must end in a verification result or a
documented format error, never another exception.
"""

import copy
import json
import random

import pytest

from aep_verify.__main__ import main
from aep_verify.bundle import BundleFormatError, verify_bundle
from aep_verify.canonical import MAX_DEPTH, CanonicalizationError, canonicalize
from aep_verify.chain import show, verify_chain
from aep_verify.demo import MERCHANT_KEY, build_records, export
from aep_verify.produce import ChainBuilder, ProducerError, check_payload

PUBLIC = MERCHANT_KEY.public_key()
AT = "2026-10-21T14:00:00Z"


@pytest.fixture(scope="module")
def honest():
    return export(build_records("honest"))


def _deep(levels):
    value = []
    for _ in range(levels):
        value = [value]
    return value


# -- verifier: values of the wrong JSON type -------------------------------------------------


@pytest.mark.parametrize(
    "field",
    ["artifact_type", "actor_type", "interaction_channel"],
)
@pytest.mark.parametrize("value", [{}, [], {"a": 1}, [1, 2]])
def test_unhashable_names_fail_verification_without_crashing(honest, field, value):
    bundle = copy.deepcopy(honest)
    bundle["artifacts"][2]["hash_input"][field] = value
    outcome = verify_bundle(bundle, PUBLIC, verified_at=AT)
    assert not outcome.verification.valid and not outcome.exportable


@pytest.mark.parametrize("field", ["merchant_id", "spec_version"])
def test_unhashable_metadata_fails_verification_without_crashing(honest, field):
    bundle = copy.deepcopy(honest)
    bundle["artifacts"][0]["hash_input"]["metadata"][field] = {"nested": ["value"]}
    outcome = verify_bundle(bundle, PUBLIC, verified_at=AT)
    assert not outcome.verification.valid


def test_non_string_merchant_id_is_named(honest):
    records = copy.deepcopy(honest["artifacts"])
    records[0]["hash_input"]["metadata"]["merchant_id"] = 7
    result = verify_chain(records, PUBLIC, verified_at=AT)
    assert any("metadata.merchant_id must be a string" in e for e in result.errors)


# -- depth and size --------------------------------------------------------------------------


def test_canonicalize_refuses_excessive_nesting():
    canonicalize(_deep(MAX_DEPTH))  # the limit itself is fine
    with pytest.raises(CanonicalizationError, match="nesting deeper than"):
        canonicalize(_deep(MAX_DEPTH + 1))


def test_deep_payload_fails_the_artifact_instead_of_the_process(honest):
    bundle = copy.deepcopy(honest)
    bundle["artifacts"][3]["hash_input"]["payload"]["rules_triggered"] = _deep(20_000)
    outcome = verify_bundle(bundle, PUBLIC, verified_at=AT)
    assert not outcome.verification.valid
    assert any("nesting deeper than" in e for e in outcome.verification.errors)


def test_huge_values_are_not_amplified_into_messages(honest):
    bundle = copy.deepcopy(honest)
    bundle["artifacts"][5]["hash_input"]["artifact_type"] = "x" * 1_000_000
    bundle["merchantContext"]["currency"] = "y" * 1_000_000
    outcome = verify_bundle(bundle, PUBLIC, verified_at=AT)
    messages = (
        outcome.errors
        + outcome.warnings
        + outcome.wrapper_contradictions
        + outcome.verification.errors
        + outcome.verification.warnings
    )
    assert messages and max(len(m) for m in messages) < 400


@pytest.mark.parametrize(
    "value, expected",
    [
        ("USD", "'USD'"),
        (None, "None"),
        (5500, "5500"),
        (["AP2", "TAP"], "['AP2', 'TAP']"),
        ({"a": 1}, "<object with 1 members>"),
        (list(range(50)), "<array of 50 items>"),
        ([{"x": 1}], "<array of 1 items>"),
    ],
)
def test_show_matches_repr_for_small_values(value, expected):
    assert show(value) == expected


def test_show_bounds_and_never_recurses():
    assert len(show("z" * 10_000)) == 96 and show("z" * 10_000).endswith("…")
    assert show(_deep(100_000)) == "<array of 1 items>"


def test_cli_rejects_deeply_nested_json(tmp_path, capsys):
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 50_000 + "]" * 50_000)
    assert main(["canon", str(deep)]) == 2
    assert "nest" in capsys.readouterr().err


# -- producer: wrong types are refusals, not crashes -----------------------------------------


def _builder():
    meta = build_records("honest")[0]["hash_input"]["metadata"]
    return ChainBuilder(
        transaction_type="ai_referral_agent_session",
        chain_id=meta["chain_id"],
        merchant_id=meta["merchant_id"],
        session_id_hash=meta["session_id_hash"],
        signing_key=MERCHANT_KEY,
    )


def _discovery(**changes):
    record = build_records("honest")[0]["hash_input"]
    kwargs = {k: record[k] for k in ("actor_type", "actor_id", "timestamp", "payload")}
    kwargs["interaction_channel"] = None
    kwargs.update(changes)
    return kwargs


@pytest.mark.parametrize(
    "changes, needle",
    [
        ({"payload": 1.5}, "payload must be an object"),
        ({"actor_type": {}}, "is not permitted for discovery"),
        ({"interaction_channel": []}, "is not a §2.4 value"),
        ({"timestamp": {"t": 1}}, "must be RFC 3339 UTC whole seconds"),
    ],
)
def test_producer_refuses_wrong_types(changes, needle):
    with pytest.raises(ProducerError, match=needle):
        _builder().append("discovery", **_discovery(**changes))


@pytest.mark.parametrize("artifact_type", [{}, ["discovery"], None])
def test_producer_refuses_unhashable_artifact_type(artifact_type):
    with pytest.raises(ProducerError, match="unknown artifact_type"):
        _builder().append(artifact_type, **_discovery())


@pytest.mark.parametrize(
    "extra, needle",
    [
        (2**60, r"exceeds 2\*\*53-1"),
        (float("inf"), "is not an integer"),
        ("\ud800", "lone surrogate"),
        (_deep(MAX_DEPTH + 5), "nesting deeper than"),
    ],
)
def test_values_without_a_canonical_form_are_refused(extra, needle):
    kwargs = _discovery()
    kwargs["payload"] = dict(kwargs["payload"], extra=extra)
    with pytest.raises(ProducerError, match=needle):
        _builder().append("discovery", **kwargs)


def test_check_payload_tolerates_any_enum_value():
    problems = check_payload("discovery", {"platform": {"name": "x"}, "attribution_method": []})
    assert any("platform=<object with 1 members> is not one of" in p for p in problems)
    assert check_payload("cart", {1: "non-string key"})  # reported, not raised


# -- seeded structural fuzz ------------------------------------------------------------------

_SCALARS = [None, True, 0, -1, 2**53 + 1, 1.5, "", "x", "sha256:" + "0" * 64, "4111111111111111"]


def _random_value(r, depth=0):
    roll = r.randrange(4)
    if roll == 0 and depth < 3:
        return [_random_value(r, depth + 1) for _ in range(r.randrange(3))]
    if roll == 1 and depth < 3:
        return {r.choice(["a", "payload", "total"]): _random_value(r, depth + 1)}
    return r.choice(_SCALARS)


def _paths(value, path=()):
    yield path
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _paths(item, path + (key,))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from _paths(item, path + (i,))


def _mutate(r, bundle):
    out = copy.deepcopy(bundle)
    for _ in range(r.randrange(1, 4)):
        paths = [p for p in _paths(out) if p]
        path = r.choice(paths)
        parent = out
        for step in path[:-1]:
            parent = parent[step]
        if isinstance(parent, dict) and r.random() < 0.3:
            del parent[path[-1]]
        else:
            parent[path[-1]] = _random_value(r)
    return out


@pytest.mark.parametrize("seed", range(4))
def test_structural_fuzz_never_crashes(honest, seed):
    r = random.Random(seed)
    seal = honest["transaction"]["sealedBundleHash"]
    for _ in range(150):
        bundle = _mutate(r, honest)
        try:
            outcome = verify_bundle(bundle, PUBLIC, verified_at=AT, anchored_seal=seal)
        except BundleFormatError:
            continue
        json.dumps(outcome.to_dict())  # the result itself must serialize
