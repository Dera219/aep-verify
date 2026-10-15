import base64
import copy
import hashlib

import pytest

from aep_verify.bundle import BundleFormatError, verify_bundle
from aep_verify.chain import compute_hash, sign_hash, verify_chain


def _bundle(chain_vector, public_key, **overrides):
    recomputed = verify_chain(
        chain_vector["artifacts"],
        public_key,
        transaction_type=chain_vector["transaction_type"],
        sealed_bundle_hash=chain_vector["sealed_bundle_hash"],
    )
    bundle = {
        "transaction": {
            "id": "txn_vector_001",
            "transactionType": chain_vector["transaction_type"],
            "status": "completed",
            "interactionChannel": "text_chat",
            "createdAt": "2026-07-01T12:00:00Z",
            "completedAt": "2026-07-01T12:46:00Z",
            "sealedBundleHash": chain_vector["sealed_bundle_hash"],
        },
        "verification": {
            "valid": recomputed.valid,
            "hashChainIntact": recomputed.hash_chain_intact,
            "signaturesValid": recomputed.signatures_valid,
            "chainComplete": recomputed.chain_complete,
            "artifactsVerified": recomputed.artifacts_verified,
            "verifiedAt": "2026-07-01T12:06:30Z",
            "verificationMode": "full",
            "errors": [],
        },
        "artifacts": copy.deepcopy(chain_vector["artifacts"]),
        "merchantContext": {
            "merchantId": "acct_vector_merchant",
            "merchantName": "Vector Merchant",
            "totalValue": "55.00",
            "currency": "USD",
        },
        "evidenceTier": "D",
        "protocolEnvelopesVerified": [],
        "customerHistory": None,
        "exportedAt": "2026-07-02T09:00:00Z",
    }
    bundle.update(overrides)
    return bundle


def test_clean_bundle_is_exportable(chain_vector, public_key):
    outcome = verify_bundle(_bundle(chain_vector, public_key), public_key)
    assert outcome.exportable, outcome.gate_reasons
    assert outcome.embedded_disagreements == []
    assert outcome.verification.seal_valid is True
    payload = outcome.to_dict()
    assert payload["exportable"] is True and payload["verification"]["valid"] is True


def test_cached_mode_blocks_representment_export(chain_vector, public_key):
    bundle = _bundle(chain_vector, public_key)
    bundle["verification"]["verificationMode"] = "cached"
    outcome = verify_bundle(bundle, public_key)
    assert not outcome.exportable
    assert any("cached" in r for r in outcome.gate_reasons)
    bundle["verification"]["verifiedAt"] = None
    outcome = verify_bundle(bundle, public_key)
    assert any("non-null verifiedAt" in e for e in outcome.errors)


def test_embedded_claim_of_validity_over_tampered_artifacts(chain_vector, public_key):
    bundle = _bundle(chain_vector, public_key)
    bundle["artifacts"][6]["hash_input"]["payload"]["amount"] = 1
    outcome = verify_bundle(bundle, public_key)
    assert not outcome.exportable
    assert any(
        "verification.valid=True but re-verification gives False" in d
        for d in outcome.embedded_disagreements
    )
    assert any("artifactsVerified=8" in d for d in outcome.embedded_disagreements)


def test_unsealed_bundle_not_exportable(chain_vector, public_key):
    bundle = _bundle(chain_vector, public_key)
    bundle["transaction"]["sealedBundleHash"] = None
    outcome = verify_bundle(bundle, public_key)
    assert not outcome.exportable and any("not sealed" in r for r in outcome.gate_reasons)


def test_misordered_artifacts(chain_vector, public_key):
    bundle = _bundle(chain_vector, public_key)
    bundle["artifacts"].reverse()
    outcome = verify_bundle(bundle, public_key)
    assert any("ordered by sequence_number ASC" in e for e in outcome.errors)


def test_merchant_context_scopes_the_chain(chain_vector, public_key):
    bundle = _bundle(chain_vector, public_key)
    bundle["merchantContext"]["merchantId"] = "acct_other"
    outcome = verify_bundle(bundle, public_key)
    assert not outcome.exportable
    assert any("MUST be rejected" in e for e in outcome.verification.errors)
    outcome = verify_bundle(
        _bundle(chain_vector, public_key), public_key, expected_merchant_id="acct_x"
    )
    assert any("not the expected" in e for e in outcome.errors)


def test_bundle_format_errors(public_key):
    with pytest.raises(BundleFormatError):
        verify_bundle([], public_key)
    with pytest.raises(BundleFormatError):
        verify_bundle({"transaction": {}, "artifacts": []}, public_key)
    with pytest.raises(BundleFormatError):
        verify_bundle({"transaction": {}, "artifacts": ["x"]}, public_key)


def test_missing_verification_and_exported_at_are_warnings(chain_vector, public_key):
    bundle = _bundle(chain_vector, public_key)
    del bundle["verification"]
    del bundle["exportedAt"]
    outcome = verify_bundle(bundle, public_key)
    assert outcome.exportable
    assert any("no verification object" in w for w in outcome.warnings)
    assert any("exportedAt missing" in w for w in outcome.warnings)


def test_ap2_rule4_binding(chain_vector, public_key, private_key):
    artifacts = copy.deepcopy(chain_vector["artifacts"])
    jwt = "eyJhbGciOiJFUzI1NiJ9.eyJjYXJ0Ijoidm"
    digest = base64.urlsafe_b64encode(hashlib.sha256(jwt.encode()).digest()).decode().rstrip("=")
    meta = artifacts[3]["hash_input"]["payload"]["protocol_metadata"]
    meta["protocol"] = "AP2"
    meta["consumer_authorization"] = {"ap2_checkout_jwt": jwt, "ap2_checkout_hash": digest}
    artifacts[5]["hash_input"]["payload"]["cart_payment_binding"] = {
        "binding_method": "checkout_hash",
        "binding_value": digest,
    }
    previous = None
    for art in artifacts:
        art["hash_input"]["previous_hash"] = previous
        art["current_hash"] = compute_hash(art["hash_input"])
        art["server_signature"] = sign_hash(private_key, art["current_hash"])
        previous = art["current_hash"]
    result = verify_chain(artifacts, public_key, transaction_type="ai_referral_agent_session")
    assert result.cart_payment_binding_verified is True
    assert result.chain_complete is True  # AP2 protocol -> expected 8
    assert result.evidence_tier is None
    assert [e["envelope"] for e in result.protocol_envelopes_verified] == ["AP2"]
    assert result.protocol_envelopes_verified[0]["status"] is None
    assert result.valid  # unverified envelopes do not make the chain invalid under §5

    artifacts[5]["hash_input"]["payload"]["cart_payment_binding"]["binding_value"] = "zzz"
    artifacts[5]["current_hash"] = compute_hash(artifacts[5]["hash_input"])
    artifacts[5]["server_signature"] = sign_hash(private_key, artifacts[5]["current_hash"])
    for art in artifacts[6:]:
        art["hash_input"]["previous_hash"] = artifacts[artifacts.index(art) - 1]["current_hash"]
        art["current_hash"] = compute_hash(art["hash_input"])
        art["server_signature"] = sign_hash(private_key, art["current_hash"])
    result = verify_chain(artifacts, public_key, transaction_type="ai_referral_agent_session")
    assert result.cart_payment_binding_verified is False
    assert any("rule 4" in e for e in result.errors)
