import json

import pytest

from aep_verify.canonical import CanonicalizationError, canonicalize, parse_json, sha256_of
from tests.conftest import load


def test_vector_h_every_case():
    for case in load("h-canonicalization.json")["cases"]:
        outputs = set()
        for item in case["inputs"]:
            assert canonicalize(item) == case["expected_canonical"].encode("utf-8"), case["name"]
            assert sha256_of(item) == case["expected_sha256"], case["name"]
            outputs.add(canonicalize(item))
        if case.get("all_inputs_must_match"):
            assert len(outputs) == 1


def test_control_characters_and_non_escapes():
    text = 'a\x00\x01\x1f\x7f /"\\\b\f\n\r\t'
    out = canonicalize({"s": text}).decode("utf-8")
    assert out == '{"s":"a\\u0000\\u0001\\u001f\x7f /\\"\\\\\\b\\f\\n\\r\\t"}'
    # Byte-identical to stock json.dumps with ensure_ascii=False, which is RFC 8785-compatible
    # for strings; this guards the hand-written escaper against drift.
    assert out == json.dumps({"s": text}, ensure_ascii=False, separators=(",", ":"))


def test_utf16_order_differs_from_code_point_order():
    # The issue #17 case: U+10000 (surrogates D800 DC00) sorts before U+E000 by UTF-16 units,
    # after it by code point.
    out = canonicalize({"": 1, "\U00010000": 2}).decode("utf-8")
    assert out == '{"\U00010000":2,"":1}'
    assert sorted(["", "\U00010000"]) == ["", "\U00010000"]  # code-point order differs


def test_nfc_applies_to_member_names_and_detects_collisions():
    composed, decomposed = "café", "café"
    assert canonicalize({decomposed: 1}) == canonicalize({composed: 1})
    with pytest.raises(CanonicalizationError, match="duplicate member name after NFC"):
        canonicalize({composed: 1, decomposed: 2})


def test_numbers_must_be_integers():
    assert (
        canonicalize({"n": 0, "m": -5, "big": 2**53 - 1})
        == b'{"big":9007199254740991,"m":-5,"n":0}'
    )
    for bad in (5500.0, 1e3, 0.5, float("inf")):
        with pytest.raises(CanonicalizationError):
            canonicalize({"n": bad})
    with pytest.raises(CanonicalizationError, match="2\\*\\*53"):
        canonicalize({"n": 2**53})


def test_booleans_are_not_integers():
    assert canonicalize([True, False, None, 1, 0]) == b"[true,false,null,1,0]"


def test_empty_containers_and_nesting():
    assert canonicalize({}) == b"{}"
    assert canonicalize([]) == b"[]"
    assert canonicalize({"b": [{"z": {}, "a": []}], "a": {}}) == b'{"a":{},"b":[{"a":[],"z":{}}]}'


def test_lone_surrogate_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize({"s": "\ud800"})
    with pytest.raises(CanonicalizationError):
        canonicalize({"\ud800": 1})


def test_parse_json_rejects_duplicates_and_nonfinite():
    with pytest.raises(CanonicalizationError, match="duplicate"):
        parse_json('{"a":1,"a":2}')
    with pytest.raises(CanonicalizationError, match="non-finite"):
        parse_json('{"a":NaN}')
    with pytest.raises(CanonicalizationError, match="invalid JSON"):
        parse_json("{")
    assert parse_json('{"a":[1,"x",null]}') == {"a": [1, "x", None]}


def test_json_text_fraction_or_exponent_is_rejected_at_canonicalization():
    for text in ('{"amount":5500.0}', '{"amount":55e2}'):
        with pytest.raises(CanonicalizationError, match="not an integer"):
            canonicalize(parse_json(text))


def test_cross_check_against_stock_rfc8785():
    rfc8785 = pytest.importorskip("rfc8785")
    samples = [
        load("a-genesis.json")["hash_input"],
        *[a["hash_input"] for a in load("b-chain.json")["artifacts"]],
        {"": 1, "\U00010000": 2, "B": [3, {"b": None, "a": True}], "a": 'x "\\\n'},
        {"zero": 0, "neg": -1, "big": 2**53 - 1, "s": "éあ\U0001f600"},
    ]
    for sample in samples:
        # Stock JCS does no NFC; every sample above is already NFC so the forms must agree.
        assert canonicalize(sample) == rfc8785.dumps(sample)
