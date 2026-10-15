"""Every mutation here must be caught. A verifier that passes the vectors but misses one of
these is worse than none, because it lends a signature's weight to a forged bundle."""

import base64

import pytest

from aep_verify.chain import compute_hash, sign_hash, verify_chain

TT = "ai_referral_agent_session"


def _verify(artifacts, public_key, **kw):
    return verify_chain(artifacts, public_key, transaction_type=TT, **kw)


def _resign(art, private_key):
    art["current_hash"] = compute_hash(art["hash_input"])
    art["server_signature"] = sign_hash(private_key, art["current_hash"])


def test_payload_edit_breaks_hash(artifacts, public_key):
    artifacts[5]["hash_input"]["payload"]["total"] = 5400
    artifacts[5]["hash_input"]["payload"]["tax"] = 301
    result = _verify(artifacts, public_key)
    assert not result.valid
    assert result.hash_chain_intact  # links still agree: the edit is caught by recomputation
    assert not result.artifact_checks[5].hash_matches
    assert any("artifact 6: recomputed hash" in e for e in result.errors)


def test_metadata_edit_is_hashed_too(artifacts, public_key):
    # Issue #3 territory: the vectors hash merchant_id/spec_version via metadata.
    artifacts[0]["hash_input"]["metadata"]["merchant_id"] = "acct_other"
    result = _verify(artifacts, public_key)
    assert not result.artifact_checks[0].hash_matches
    assert any("disagree on metadata.merchant_id" in e for e in result.errors)


def test_edit_then_rehash_and_resign_is_caught_by_the_next_link(artifacts, public_key, private_key):
    artifacts[5]["hash_input"]["payload"]["shipping"] = 0
    artifacts[5]["hash_input"]["payload"]["total"] = 5000
    _resign(artifacts[5], private_key)
    result = _verify(artifacts, public_key)
    assert result.artifact_checks[5].hash_matches and result.artifact_checks[5].signature_valid
    assert not result.hash_chain_intact
    assert not result.artifact_checks[6].link_valid
    # and the §3.6 amount match now fails as well
    assert any("§3.6 MUST-1" in e for e in result.errors)


def test_edit_then_rechain_everything_fails_the_seal(artifacts, public_key, private_key):
    # Attacker holds the signing key and rebuilds the whole chain: only the stored seal catches it.
    sealed = artifacts[6]["current_hash"]
    artifacts[2]["hash_input"]["payload"]["unit_price"] = 1
    previous = None
    for art in artifacts:
        art["hash_input"]["previous_hash"] = previous
        _resign(art, private_key)
        previous = art["current_hash"]
    clean = _verify(artifacts, public_key)
    assert clean.hash_chain_intact and clean.signatures_valid
    sealed_result = _verify(artifacts, public_key, sealed_bundle_hash=sealed)
    assert sealed_result.seal_valid is False and not sealed_result.valid


def test_deleted_artifact(artifacts, public_key):
    del artifacts[3]
    result = _verify(artifacts, public_key)
    assert not result.hash_chain_intact
    assert any("sequence_number 5 at position 4" in e for e in result.errors)


def test_reordered_artifacts(artifacts, public_key):
    artifacts[1], artifacts[2] = artifacts[2], artifacts[1]
    result = _verify(artifacts, public_key)
    assert not result.hash_chain_intact
    assert any("out of order" in e for e in result.errors)


def test_inserted_duplicate_cart_after_seal(artifacts, public_key):
    artifacts.insert(7, dict(artifacts[5]))
    result = _verify(artifacts, public_key)
    assert any("follows the authorization seal" in e for e in result.errors)


def test_signature_bit_flip(artifacts, public_key):
    raw = bytearray(base64.b64decode(artifacts[2]["server_signature"]))
    raw[10] ^= 0x01
    artifacts[2]["server_signature"] = base64.b64encode(bytes(raw)).decode()
    result = _verify(artifacts, public_key)
    assert not result.signatures_valid
    assert result.hash_chain_intact
    assert result.artifacts_verified == 7


def test_missing_signature(artifacts, public_key):
    del artifacts[7]["server_signature"]
    result = _verify(artifacts, public_key)
    assert not result.signatures_valid
    assert any("unsigned artifacts are non-conformant" in e for e in result.errors)


def test_wrong_public_key(artifacts):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    other = Ed25519PrivateKey.generate().public_key()
    result = _verify(artifacts, other)
    assert not result.signatures_valid and result.hash_chain_intact
    assert result.artifacts_verified == 0


def test_signature_over_hex_string_instead_of_raw_digest_is_rejected(
    artifacts, public_key, private_key
):
    # The §4.1 encoding trap: signing the "sha256:..." text instead of the 32 raw bytes.
    wrong = private_key.sign(artifacts[0]["current_hash"].encode("ascii"))
    artifacts[0]["server_signature"] = base64.b64encode(wrong).decode()
    assert not _verify(artifacts, public_key).artifact_checks[0].signature_valid


def test_previous_hash_rewritten_to_sibling(artifacts, public_key, private_key):
    artifacts[4]["hash_input"]["previous_hash"] = artifacts[1]["current_hash"]
    _resign(artifacts[4], private_key)
    artifacts[5]["hash_input"]["previous_hash"] = artifacts[4]["current_hash"]
    _resign(artifacts[5], private_key)
    result = _verify(artifacts, public_key)
    assert not result.artifact_checks[4].link_valid  # 5 no longer points at 4
    assert result.artifact_checks[5].link_valid  # 6 was re-linked to the rebuilt 5
    assert not result.artifact_checks[6].link_valid  # 7 still points at the original 6
    assert not result.hash_chain_intact


def test_genesis_with_previous_hash_and_nongenesis_without(artifacts, public_key):
    artifacts[0]["hash_input"]["previous_hash"] = artifacts[1]["current_hash"]
    artifacts[1]["hash_input"]["previous_hash"] = None
    result = _verify(artifacts, public_key)
    assert any("genesis previous_hash must be null" in e for e in result.errors)
    assert any("non-genesis previous_hash missing" in e for e in result.errors)


def test_unsupported_spec_version_is_refused(artifacts, public_key):
    for art in artifacts:
        art["hash_input"]["metadata"]["spec_version"] = "aep-1.0.1"
    result = _verify(artifacts, public_key)
    assert not result.valid and result.artifacts_verified == 0
    assert "MUST refuse" in result.errors[0]


def test_conflicting_spec_versions(artifacts, public_key):
    artifacts[3]["hash_input"]["metadata"]["spec_version"] = "aep-1.0.2"
    result = _verify(artifacts, public_key)
    assert any("conflicting spec_version" in e for e in result.errors)


def test_wrong_seal(artifacts, public_key):
    result = _verify(artifacts, public_key, sealed_bundle_hash="sha256:" + "0" * 64)
    assert result.seal_valid is False and not result.valid


def test_timestamp_format_enforced(artifacts, public_key, private_key):
    artifacts[2]["hash_input"]["timestamp"] = "2026-07-01T12:02:00.000Z"
    _resign(artifacts[2], private_key)
    result = _verify(artifacts, public_key)
    assert any("not RFC 3339 UTC 'Z' whole-second" in e for e in result.errors)


def test_captured_at_must_not_decrease(artifacts, public_key, private_key):
    artifacts[4]["hash_input"]["payload"]["captured_at"] = "2026-07-01T11:00:00Z"
    _resign(artifacts[4], private_key)
    result = _verify(artifacts, public_key)
    assert any("captured_at decreases" in e for e in result.errors)


def test_actor_not_permitted_for_type(artifacts, public_key, private_key):
    artifacts[6]["hash_input"]["actor_type"] = "merchant"  # authorization must be psp
    _resign(artifacts[6], private_key)
    result = _verify(artifacts, public_key)
    assert any("not permitted for 'authorization'" in e for e in result.errors)


def test_layer_not_in_transaction_type(chain_vector, public_key):
    result = verify_chain(chain_vector["artifacts"], public_key, transaction_type="direct_web")
    assert any("not a layer of transaction type 'direct_web'" in e for e in result.errors)


def test_cart_total_integrity_and_integer_rule(artifacts, public_key, private_key):
    cart = artifacts[5]["hash_input"]["payload"]
    cart["discounts"] = 100  # total no longer adds up
    _resign(artifacts[5], private_key)
    result = _verify(artifacts, public_key)
    assert any("§3.5 MUST-1" in e for e in result.errors)
    cart["discounts"] = "0"
    _resign(artifacts[5], private_key)
    result = _verify(artifacts, public_key)
    assert any("not integer minor units" in e for e in result.errors)


def test_extra_hash_input_field_is_flagged(artifacts, public_key):
    artifacts[0]["hash_input"]["chain_id"] = "abc"
    result = _verify(artifacts, public_key)
    assert any("outside the §4.1 eight" in e for e in result.errors)


def test_merchant_scope(artifacts, public_key):
    ok = _verify(artifacts, public_key, expected_merchant_id="acct_vector_merchant")
    assert ok.valid
    bad = _verify(artifacts, public_key, expected_merchant_id="acct_someone_else")
    assert not bad.valid and any("MUST be rejected" in e for e in bad.errors)


@pytest.mark.parametrize("mutation", ["refund_before_seal", "fulfillment_first"])
def test_post_seal_type_before_seal(artifacts, public_key, mutation):
    moved = artifacts.pop(7)
    artifacts.insert(0 if mutation == "fulfillment_first" else 3, moved)
    result = _verify(artifacts, public_key)
    assert any("post-seal but no authorization precedes it" in e for e in result.errors)
