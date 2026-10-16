import base64
import copy
import hashlib

import pytest

from aep_verify.bundle import BundleFormatError, verify_bundle
from aep_verify.canonical import canonicalize
from aep_verify.chain import compute_hash, sign_hash, verify_chain


def _sign(art, private_key):
    """Re-sign an edited record the way a producer would, unsigned copy included."""
    art["canonical_json"] = canonicalize(art["hash_input"]).decode()
    art["current_hash"] = compute_hash(art["hash_input"])
    art["server_signature"] = sign_hash(private_key, art["current_hash"])


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
        _sign(art, private_key)
        previous = art["current_hash"]
    result = verify_chain(artifacts, public_key, transaction_type="ai_referral_agent_session")
    assert result.cart_payment_binding_verified is True
    assert result.chain_complete is True  # AP2 protocol -> expected 8
    assert result.evidence_tier is None
    assert [e["envelope"] for e in result.protocol_envelopes_verified] == ["AP2"]
    assert result.protocol_envelopes_verified[0]["status"] is None
    assert result.valid  # unverified envelopes do not make the chain invalid under §5

    artifacts[5]["hash_input"]["payload"]["cart_payment_binding"]["binding_value"] = "zzz"
    _sign(artifacts[5], private_key)
    for art in artifacts[6:]:
        art["hash_input"]["previous_hash"] = artifacts[artifacts.index(art) - 1]["current_hash"]
        _sign(art, private_key)
    result = verify_chain(artifacts, public_key, transaction_type="ai_referral_agent_session")
    assert result.cart_payment_binding_verified is False
    assert any("rule 4" in e for e in result.errors)


# -- wrapper cross-checks (aep-verify extension; §6.1 binds no wrapper field) -----------------


def _contradictions(bundle, public_key):
    outcome = verify_bundle(bundle, public_key)
    assert outcome.verification.valid  # the chain itself is untouched in every case below
    return outcome


@pytest.mark.parametrize(
    "path, value, needle",
    [
        (("merchantContext", "totalValue"), "5.50", "is 550 minor units, but the sealed cart"),
        (("merchantContext", "totalValue"), "55.001", "is not an exact USD amount"),
        (("merchantContext", "totalValue"), "fifty-five", "is not an exact USD amount"),
        (("merchantContext", "currency"), "EUR", "currency 'EUR' but the sealed cart is in"),
        (("evidenceTier",), "A", "evidenceTier 'A' but the chain recomputes to 'D'"),
        (("protocolEnvelopesVerified",), [{"envelope": "AP2"}], "lists ['AP2'], but the chain"),
    ],
)
def test_wrapper_contradicting_the_chain_is_not_certified(
    chain_vector, public_key, path, value, needle
):
    bundle = _bundle(chain_vector, public_key)
    target = bundle
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    outcome = _contradictions(bundle, public_key)
    assert not outcome.exportable
    assert any(needle in c for c in outcome.wrapper_contradictions), outcome.wrapper_contradictions
    assert any("extension" in r and "#16" in r for r in outcome.gate_reasons)
    assert outcome.to_dict()["wrapper_contradictions"] == outcome.wrapper_contradictions


def test_null_wrapper_values_are_not_contradictions(chain_vector, public_key):
    bundle = _bundle(chain_vector, public_key)
    bundle["merchantContext"]["totalValue"] = None
    bundle["merchantContext"]["currency"] = None
    del bundle["evidenceTier"]
    outcome = _contradictions(bundle, public_key)
    assert outcome.exportable and outcome.wrapper_contradictions == []


def test_embedded_tier_and_spec_version_are_compared(chain_vector, public_key):
    bundle = _bundle(chain_vector, public_key)
    bundle["verification"]["evidenceTier"] = "S"
    bundle["verification"]["specVersion"] = "aep-1.0.2"
    outcome = verify_bundle(bundle, public_key)
    assert not outcome.exportable
    assert any("evidenceTier='S'" in d for d in outcome.embedded_disagreements)
    assert any("specVersion='aep-1.0.2'" in d for d in outcome.embedded_disagreements)


def test_claimed_verified_envelope_is_flagged_as_unconfirmed(chain_vector, public_key):
    bundle = _bundle(chain_vector, public_key)
    bundle["protocolEnvelopesVerified"] = [{"envelope": "TAP", "verified": True}]
    outcome = _contradictions(bundle, public_key)
    assert any("claims 'TAP' verified" in w for w in outcome.warnings)


@pytest.mark.parametrize(
    "path, value, needle",
    [
        (("transaction", "interactionChannel"), "voice", "interactionChannel 'voice' but"),
        (("transaction", "createdAt"), "2027-01-01T00:00:00Z", "createdAt postdates"),
        (("transaction", "completedAt"), "2020-01-01T00:00:00Z", "completedAt predates"),
        (("customerHistory",), {"prior_transactions": []}, "not hash-chained (§6.1)"),
    ],
)
def test_soft_wrapper_checks_warn_but_do_not_block(chain_vector, public_key, path, value, needle):
    bundle = _bundle(chain_vector, public_key)
    target = bundle
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    outcome = _contradictions(bundle, public_key)
    assert outcome.exportable, outcome.gate_reasons
    assert any(needle in w for w in outcome.warnings), outcome.warnings


def test_completed_at_without_a_delivery_is_flagged(chain_vector, public_key):
    bundle = _bundle(chain_vector, public_key)
    fulfillment = bundle["artifacts"][7]["hash_input"]["payload"]
    assert fulfillment["status"] == "delivered"
    bundle["artifacts"] = bundle["artifacts"][:7]
    bundle["verification"] = {}
    outcome = verify_bundle(bundle, public_key)
    assert any("no fulfillment artifact says delivered" in w for w in outcome.warnings)


def test_wrapper_binding_names_every_section_6_1_member(chain_vector, public_key):
    binding = verify_bundle(_bundle(chain_vector, public_key), public_key).to_dict()[
        "wrapper_binding"
    ]
    members = {
        "transaction.id", "transaction.transactionType", "transaction.status",
        "transaction.interactionChannel", "transaction.createdAt", "transaction.completedAt",
        "transaction.sealedBundleHash", "verification", "merchantContext.merchantId",
        "merchantContext.merchantName", "merchantContext.totalValue", "merchantContext.currency",
        "evidenceTier", "protocolEnvelopesVerified", "customerHistory", "exportedAt",
    }  # fmt: skip
    assert set(binding) == members
    assert {b["binding"] for b in binding.values()} == {"chain-bound", "cross-checked", "unbound"}
    assert binding["customerHistory"]["binding"] == "unbound"


# -- §4.3 external existence anchor ----------------------------------------------------------


def test_anchored_seal_must_match(chain_vector, public_key):
    bundle = _bundle(chain_vector, public_key)
    seal = chain_vector["sealed_bundle_hash"]
    outcome = verify_bundle(bundle, public_key, anchored_seal=seal)
    assert outcome.exportable and outcome.anchor_matches is True
    outcome = verify_bundle(bundle, public_key, anchored_seal="sha256:" + "0" * 64)
    assert not outcome.exportable and outcome.anchor_matches is False
    assert any("does not match the externally anchored seal" in r for r in outcome.gate_reasons)
    assert any("is not the externally anchored seal" in e for e in outcome.errors)
    assert verify_bundle(bundle, public_key).anchor_matches is None


def test_anchor_against_an_unsealed_chain_fails(chain_vector, public_key):
    bundle = _bundle(chain_vector, public_key, transaction={"transactionType": "direct_web"})
    bundle["artifacts"] = bundle["artifacts"][:6]  # up to the cart: no authorization, no seal
    outcome = verify_bundle(bundle, public_key, anchored_seal=chain_vector["sealed_bundle_hash"])
    assert outcome.anchor_matches is False and not outcome.exportable


@pytest.mark.parametrize("bad", ["", "sha256:XYZ", "sha256:" + "A" * 64, "md5:" + "0" * 64])
def test_malformed_anchor_is_refused(chain_vector, public_key, bad):
    with pytest.raises(BundleFormatError, match="anchored_seal"):
        verify_bundle(_bundle(chain_vector, public_key), public_key, anchored_seal=bad)


def test_uncomputable_tier_is_a_warning_not_a_disagreement(chain_vector, public_key, private_key):
    """With a populated sub-wrapper the tier is not computed here (§3.9.11 unimplemented), so a
    claimed tier can be neither confirmed nor refuted: say so, and do not call it a lie."""
    artifacts = copy.deepcopy(chain_vector["artifacts"])
    meta = artifacts[3]["hash_input"]["payload"]["protocol_metadata"]
    meta["protocol"] = "TAP"
    meta["agent_identity"] = {"tap_signature": "sig", "tap_key_id": "k1"}
    previous = None
    for art in artifacts:
        art["hash_input"]["previous_hash"] = previous
        _sign(art, private_key)
        previous = art["current_hash"]
    bundle = _bundle(chain_vector, public_key, artifacts=artifacts)
    bundle["transaction"]["sealedBundleHash"] = artifacts[6]["current_hash"]
    bundle["verification"]["chainComplete"] = True  # TAP: delegation counts (Appendix B)
    bundle["verification"]["evidenceTier"] = "A"
    bundle["evidenceTier"] = "A"
    bundle["protocolEnvelopesVerified"] = [{"envelope": "TAP"}]
    outcome = verify_bundle(bundle, public_key)
    assert outcome.verification.valid and outcome.verification.evidence_tier is None
    assert outcome.embedded_disagreements == [] and outcome.wrapper_contradictions == []
    assert outcome.exportable, outcome.gate_reasons
    assert any("evidenceTier 'A' cannot be recomputed" in w for w in outcome.warnings)


# -- anchored head log (proposed in draft Issue I; not in v1.0.3-rc.2) ------------------------


def _heads(bundle):
    hashes = [a["current_hash"] for a in bundle["artifacts"]]
    return hashes[6:]  # vector (b): authorization is artifact 7, then one fulfillment


def test_head_log_match_and_truncation(chain_vector, public_key):
    bundle = _bundle(chain_vector, public_key)
    log = _heads(bundle)
    assert len(log) == 2
    outcome = verify_bundle(bundle, public_key, anchored_heads=log)
    assert outcome.exportable and outcome.heads_match is True
    assert outcome.to_dict()["heads_match"] is True

    longer = log + ["sha256:" + "1" * 64]
    outcome = verify_bundle(bundle, public_key, anchored_heads=longer)
    assert outcome.heads_match is False and not outcome.exportable
    assert any("ends 1 anchored post-seal event(s) early" in e for e in outcome.errors)
    assert any("anchored head log" in r for r in outcome.gate_reasons)


def test_head_log_detects_unlogged_and_altered_heads(chain_vector, public_key):
    bundle = _bundle(chain_vector, public_key)
    log = _heads(bundle)
    outcome = verify_bundle(bundle, public_key, anchored_heads=log[:1])
    assert any("carries 1 post-seal artifact(s) never anchored" in e for e in outcome.errors)
    outcome = verify_bundle(bundle, public_key, anchored_heads=[log[0], "sha256:" + "2" * 64])
    assert any("post-seal head 1 is" in e for e in outcome.errors)
    outcome = verify_bundle(bundle, public_key, anchored_heads=["sha256:" + "3" * 64, log[1]])
    assert any("the seal is" in e for e in outcome.errors)


def test_head_log_against_an_unsealed_chain(chain_vector, public_key):
    bundle = _bundle(chain_vector, public_key)
    bundle["artifacts"] = bundle["artifacts"][:6]
    outcome = verify_bundle(bundle, public_key, anchored_heads=["sha256:" + "4" * 64])
    assert outcome.heads_match is False
    assert any("no authorization artifact" in e for e in outcome.errors)


@pytest.mark.parametrize(
    "bad", ["sha256:" + "0" * 64, [], ["sha256:XYZ"], [None], ["sha256:" + "0" * 64, 7]]
)
def test_malformed_head_log_is_refused(chain_vector, public_key, bad):
    with pytest.raises(BundleFormatError, match="anchored"):
        verify_bundle(_bundle(chain_vector, public_key), public_key, anchored_heads=bad)
