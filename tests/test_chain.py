import pytest

from aep_verify.chain import (
    ArtifactRecord,
    ChainFormatError,
    compute_hash,
    expected_artifact_count,
    expected_count_by_presence,
    sign_hash,
    verify_chain,
    verify_signature,
)
from tests.conftest import load


def test_expected_artifact_count_matches_appendix_b():
    table = {
        "ai_referral_agent_session": (7, 8),
        "ai_referral_standard_checkout": (6, 7),
        "agent_session_only": (5, 6),
        "direct_web": (5, 5),
    }
    for kind, (without, with_delegation) in table.items():
        assert expected_artifact_count(kind, "GENERIC") == without
        assert expected_artifact_count(kind, "AP2") == with_delegation
        assert expected_count_by_presence(kind, False) == without
        assert expected_count_by_presence(kind, True) == with_delegation
    with pytest.raises(ChainFormatError):
        expected_artifact_count("nope")


def test_vector_a_hash_and_signature_roundtrip(public_key, private_key):
    genesis = load("a-genesis.json")
    digest = compute_hash(genesis["hash_input"])
    assert digest == genesis["expected_sha256"]
    signature = sign_hash(private_key, digest)
    assert verify_signature(public_key, digest, signature) == (True, None)
    assert verify_signature(public_key, digest, signature[:-4] + "AAA=")[0] is False
    assert verify_signature(public_key, digest, "not base64!")[0] is False
    assert verify_signature(public_key, digest, "AAAA")[0] is False  # 3 bytes


def test_vector_b_full_chain_is_valid(chain_vector, public_key):
    result = verify_chain(
        chain_vector["artifacts"],
        public_key,
        transaction_type=chain_vector["transaction_type"],
        sealed_bundle_hash=chain_vector["sealed_bundle_hash"],
    )
    assert result.valid
    assert result.hash_chain_intact and result.signatures_valid
    assert result.artifacts_verified == 8
    assert result.seal_valid is True
    assert result.sealed_bundle_hash == chain_vector["sealed_bundle_hash"]
    assert result.spec_version == "aep-1.0.3-rc.2"
    assert result.evidence_tier == "D"
    assert result.protocol == "GENERIC"
    assert result.protocol_envelopes_verified == []
    assert result.cart_payment_binding_verified is None
    assert result.errors == []
    # Documented discrepancy: Appendix B keys the count on protocol, so the official
    # 8-artifact GENERIC chain is "incomplete" under the literal function.
    assert result.expected_artifact_count == 7
    assert result.chain_complete is False
    assert any("§2.2 prose" in w for w in result.warnings)
    assert any("§3.9.2" in w for w in result.warnings)


def test_flat_record_shape_is_accepted(artifacts, public_key):
    flat = []
    for art in artifacts:
        record = dict(art["hash_input"])
        record.update(
            sequence_number=art["sequence_number"],
            current_hash=art["current_hash"],
            server_signature=art["server_signature"],
        )
        flat.append(record)
    parsed = ArtifactRecord.from_json(flat[0])
    assert parsed.hash_input == artifacts[0]["hash_input"]
    result = verify_chain(flat, public_key, transaction_type="ai_referral_agent_session")
    assert result.valid and result.artifacts_verified == 8


def test_result_dict_has_section5_keys(chain_vector, public_key):
    payload = verify_chain(chain_vector["artifacts"], public_key).to_dict()
    for key in (
        "valid",
        "hash_chain_intact",
        "signatures_valid",
        "chain_complete",
        "artifacts_verified",
        "spec_version",
        "verified_at",
        "verification_mode",
        "evidence_tier",
        "protocol_envelopes_verified",
        "cart_payment_binding_verified",
        "errors",
    ):
        assert key in payload
    assert payload["verification_mode"] == "full"
    assert payload["x_aep_verify"]["artifacts"][6]["artifact_type"] == "authorization"


def test_empty_chain_and_unknown_transaction_type(public_key):
    assert verify_chain([], public_key).valid is False
    result = verify_chain(load("b-chain.json")["artifacts"], public_key, transaction_type="bogus")
    assert not result.valid
    assert any("unknown transaction_type" in e for e in result.errors)


def test_version_strings_agree():
    import tomllib
    from pathlib import Path

    import aep_verify
    from aep_verify.chain import VERIFIER_ID

    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    version = tomllib.loads(pyproject.read_text())["project"]["version"]
    assert aep_verify.__version__ == version
    assert VERIFIER_ID == f"aep-verify/{version}"
    conformance = (pyproject.parent / "CONFORMANCE.md").read_text().splitlines()[0]
    assert f"aep-verify {version} " in conformance
