"""The producer must refuse every non-conformant artifact, and everything it emits must verify."""

import copy

import pytest

from aep_verify.chain import verify_chain
from aep_verify.demo import MERCHANT_KEY, build_records, export
from aep_verify.produce import (
    ChainBuilder,
    ExportRefused,
    ProducerError,
    _luhn_ok,
    check_payload,
    export_dispute_bundle,
    hmac_ref,
    idempotency_fallback,
    signing_key_id,
)

PUBLIC = MERCHANT_KEY.public_key()


def _events(variant="honest"):
    """The demo's honest events as (artifact_type, append kwargs), safe to mutate."""
    out = []
    for r in build_records(variant):
        hi = r["hash_input"]
        out.append(
            (
                r["artifact_type"],
                {
                    "actor_type": hi["actor_type"],
                    "actor_id": hi["actor_id"],
                    "interaction_channel": hi["interaction_channel"],
                    "timestamp": hi["timestamp"],
                    "payload": copy.deepcopy(hi["payload"]),
                },
            )
        )
    return out


def _builder(**overrides):
    meta = build_records("honest")[0]["hash_input"]["metadata"]
    args = {
        "transaction_type": "ai_referral_agent_session",
        "chain_id": meta["chain_id"],
        "merchant_id": meta["merchant_id"],
        "session_id_hash": meta["session_id_hash"],
        "signing_key": MERCHANT_KEY,
    }
    args.update(overrides)
    return ChainBuilder(**args)


def _replay(events, upto=None):
    b = _builder()
    for artifact_type, kwargs in events[:upto]:
        b.append(artifact_type, **kwargs)
    return b


def _index(events, artifact_type):
    return next(i for i, (t, _) in enumerate(events) if t == artifact_type)


def _refused(events, at, *needles):
    """Replaying events[:at] succeeds and appending events[at] is refused with every needle."""
    b = _replay(events, at)
    artifact_type, kwargs = events[at]
    with pytest.raises(ProducerError) as info:
        b.append(artifact_type, **kwargs)
    for needle in needles:
        assert needle in str(info.value), str(info.value)


# -- what it emits ---------------------------------------------------------------------------


@pytest.mark.parametrize("variant", ["honest", "misdelivered", "returned"])
def test_every_produced_chain_verifies_cleanly(variant):
    records = build_records(variant)
    result = verify_chain(
        records,
        PUBLIC,
        transaction_type="ai_referral_agent_session",
        sealed_bundle_hash=records[5]["current_hash"],
        expected_merchant_id="merchant_demo_outfitters",
    )
    assert result.valid, result.errors
    assert result.errors == [] and result.warnings == []
    assert result.chain_complete is (variant != "returned")  # Issue C: == penalizes 2 events


def test_production_is_deterministic():
    assert build_records("honest") == build_records("honest")


def test_records_property_is_a_copy():
    b = _replay(_events(), 3)
    b.records[0]["hash_input"]["payload"]["platform"] = "gemini"
    assert b.records[0]["hash_input"]["payload"]["platform"] == "perplexity"


def test_metadata_carries_the_chain_level_fields():
    meta = build_records("honest")[0]["hash_input"]["metadata"]
    assert meta["protocol"] == "GENERIC" and meta["spec_version"] == "aep-1.0.3-rc.2"
    assert meta["signing_key_id"] == signing_key_id(PUBLIC)
    assert meta["signing_key_id"].startswith("ed25519:") and len(meta["signing_key_id"]) == 24


# -- builder construction --------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides, needle",
    [
        ({"transaction_type": "kiosk"}, "unknown transaction_type"),
        ({"spec_version": "aep-1.0.2"}, "emits aep-1.0.3-rc.2 only"),
        ({"chain_id": ""}, "chain_id must be a non-empty string"),
        ({"session_id_hash": "raw-session-token"}, "session_id_hash"),
    ],
)
def test_builder_refuses_bad_construction(overrides, needle):
    with pytest.raises(ProducerError, match=needle):
        _builder(**overrides)


# -- chain rules -----------------------------------------------------------------------------


def test_delegation_is_never_produced():
    b = _replay(_events(), 3)
    with pytest.raises(ProducerError, match="GENERIC chain MUST omit it"):
        b.append("delegation", actor_type="agent", actor_id="a", timestamp="2026-09-14T15:05:30Z",
                 payload={})  # fmt: skip


def test_pre_seal_type_after_the_seal_is_refused():
    events = _events()
    b = _replay(events, 6)
    kwargs = copy.deepcopy(events[2][1])
    kwargs["timestamp"] = kwargs["payload"]["captured_at"] = "2026-09-14T15:08:00Z"
    kwargs["payload"]["idempotency_key"] = "new-intent"
    with pytest.raises(ProducerError, match="cannot follow the authorization seal"):
        b.append("intent", **kwargs)


def test_post_seal_type_before_the_seal_is_refused():
    events = _events()
    b = _replay(events, 5)
    with pytest.raises(ProducerError, match="post-seal; no authorization precedes it"):
        b.append("fulfillment", **events[6][1])


def test_out_of_order_is_refused():
    events = _events()
    events[3], events[4] = events[4], events[3]  # cart before policy
    b = _replay(events, 3)
    b.append(*events[3][:1], **events[3][1])  # cart
    with pytest.raises(ProducerError, match="out of order after cart"):
        b.append(events[4][0], **events[4][1])


def test_layer_outside_the_transaction_type_is_refused():
    events = _events()
    b = _builder(transaction_type="direct_web")
    with pytest.raises(ProducerError, match="not a layer of direct_web"):
        b.append(events[0][0], **events[0][1])


def test_actor_not_permitted_is_refused():
    events = _events()
    events[5][1]["actor_type"] = "merchant"
    _refused(events, 5, "not permitted for authorization (§3.8)")


def test_channel_on_a_psp_artifact_is_refused():
    events = _events()
    events[5][1]["interaction_channel"] = "text_chat"
    _refused(events, 5, "must be null for actor 'psp'")


def test_channel_on_a_user_artifact_is_refused():
    """Stricter than vector (b), which sets text_chat on user artifacts: §2.4 says non-agent."""
    events = _events()
    events[1][1]["interaction_channel"] = "text_chat"  # the referral, actor 'user'
    _refused(events, 1, "must be null for actor 'user'")


def test_channel_in_a_direct_web_chain_is_refused():
    events = _events()
    b = _builder(transaction_type="direct_web")
    with pytest.raises(ProducerError, match="null in a direct_web chain"):
        b.append(events[2][0], **events[2][1])  # the intent, actor 'agent', text_chat


def test_unknown_channel_is_refused():
    events = _events()
    events[2][1]["interaction_channel"] = "carrier_pigeon"
    _refused(events, 2, "not a §2.4 value")


def test_timestamp_format_and_order():
    events = _events()
    events[2][1]["timestamp"] = "2026-09-14 15:05:12"
    _refused(events, 2, "RFC 3339 UTC whole seconds")
    events = _events()
    events[2][1]["timestamp"] = "2026-09-14T15:03:00Z"  # before the referral
    _refused(events, 2, "precedes the previous artifact's")


def test_captured_at_must_not_decrease():
    events = _events()
    events[2][1]["payload"]["captured_at"] = "2026-09-14T15:03:00Z"
    _refused(events, 2, "MUST be monotonically non-decreasing")


# -- cross-artifact rules --------------------------------------------------------------------


def test_authorization_needs_a_policy_and_a_cart():
    events = [e for e in _events() if e[0] != "policy"]
    _refused(events, _index(events, "authorization"), "without a preceding policy artifact")


def test_blocked_policy_forbids_authorization():
    events = _events()
    policy = events[_index(events, "policy")][1]["payload"]
    policy.update(outcome="blocked", reason="velocity rule")
    _refused(events, _index(events, "authorization"), "outcome is 'blocked'")


@pytest.mark.parametrize(
    "field, value, needle",
    [
        ("amount", 5400, "authorization.amount != cart.total"),
        ("currency", "EUR", "authorization.currency != cart.currency"),
        ("payment_method_token", "pm_other", "payment_method_token != cart's token"),
    ],
)
def test_authorization_must_settle_the_cart(field, value, needle):
    events = _events()
    events[_index(events, "authorization")][1]["payload"][field] = value
    _refused(events, _index(events, "authorization"), needle)


def test_cart_currency_must_match_the_intent():
    events = _events()
    events[_index(events, "cart")][1]["payload"]["currency"] = "CAD"
    _refused(events, _index(events, "cart"), "cart.currency differs from the intent's")


def test_fulfillment_address_match_must_be_computed_not_claimed():
    events = _events("misdelivered")
    events[6][1]["payload"]["delivery_address_match"] = True
    _refused(events, 6, "delivery_address_match MUST equal")


# -- payload rules ---------------------------------------------------------------------------


def test_cart_arithmetic():
    events = _events()
    cart = events[4][1]["payload"]
    cart["total"] = 5600
    _refused(events, 4, "subtotal + shipping + tax - discounts != total (§3.5 MUST-1)")
    events = _events()
    cart = events[4][1]["payload"]
    cart["subtotal"], cart["total"] = 4900, 5600
    _refused(events, 4, "subtotal 4900 != sum of lines 4800")
    events = _events()
    events[4][1]["payload"]["confirmed"] = False
    _refused(events, 4, "confirmed MUST be true")
    events = _events()
    events[4][1]["payload"]["tax"] = 2.0
    _refused(events, 4, "must be integer minor units")


def test_required_fields_and_enums():
    events = _events()
    del events[3][1]["payload"]["risk_score"]
    _refused(events, 3, "policy.payload.risk_score is required")
    events = _events()
    events[0][1]["payload"]["platform"] = "altavista"
    _refused(events, 0, "platform='altavista' is not one of")
    events = _events()
    events[0][1]["payload"]["attribution_confidence"] = "medium"
    _refused(events, 0, "must be 'high' for attribution_method 'url_params'")


def test_card_rail_representment_set():
    events = _events()
    del events[5][1]["payload"]["avs_result"]
    _refused(events, 5, "must be present, null where the PSP omits them")
    events = _events()
    events[5][1]["payload"]["card_last4"] = None
    _refused(events, 5, "cannot be null for a card authorization")
    events = _events()
    events[5][1]["payload"]["three_ds_version"] = None
    _refused(events, 5, "three_ds_version is required when 3DS applied")
    events = _events()
    events[5][1]["payload"]["auth_code"] = None
    _refused(events, 5, "auth_code is required when result is 'approved'")


@pytest.mark.parametrize(
    "where, value",
    [
        ("auth_code", "4242 4242 4242 4242"),
        ("auth_code", "4242-4242-4242-4242"),
        ("fraud_engine", "engine note: 4111111111111111"),
    ],
)
def test_pan_in_authorization_is_refused(where, value):
    events = _events()
    events[5][1]["payload"][where] = value
    _refused(events, 5, "Luhn-valid 16-digit sequence")


def test_pan_as_an_integer_is_refused():
    events = _events()
    events[5][1]["payload"]["fraud_score"] = 4111111111111111
    _refused(events, 5, "Luhn-valid 16-digit sequence")


def _luhn_complete(prefix):
    return next(prefix + d for d in "0123456789" if _luhn_ok(prefix + d))


def test_luhn_valid_network_transaction_id_is_refused_as_the_spec_requires():
    """§3.6 requires the NTI and §3.6/§8.3 reject any Luhn-valid 13-19 digit run: a conflict."""
    nti = _luhn_complete("30501937281946")
    assert len(nti) == 15 and _luhn_ok(nti)
    events = _events()
    events[5][1]["payload"]["network_transaction_id"] = nti
    _refused(events, 5, "network_transaction_id: contains a Luhn-valid 15-digit sequence")
    assert not _luhn_ok(
        build_records("honest")[5]["hash_input"]["payload"]["network_transaction_id"]
    )


def test_luhn_gate_is_scoped_to_authorization():
    """A 15-digit tracking number passes Luhn one time in ten; it must not be refused."""
    events = _events()
    events[6][1]["payload"]["tracking_number"] = _luhn_complete("79412345678901")
    _replay(events)  # no exception


def test_secret_field_names_are_refused_everywhere():
    events = _events()
    events[2][1]["payload"]["notes"] = {"cvv": "123"}
    _refused(events, 2, "field name 'cvv' is a forbidden secret")


def test_check_payload_on_a_non_object():
    assert check_payload("cart", ["not", "an", "object"]) == ["cart payload must be an object"]


# -- refunds ---------------------------------------------------------------------------------


def _refund(amount, key, charge_ref="ch_demo_7f3a", currency="USD", ts="2026-09-20T09:00:00Z"):
    return {
        "actor_type": "psp",
        "actor_id": "psp:demo-psp",
        "timestamp": ts,
        "payload": {
            "refund_id": f"re_{key}",
            "charge_ref": charge_ref,
            "amount": amount,
            "currency": currency,
            "reason": "goodwill",
            "processed_at": ts,
            "refund_method": "original_payment_method",
            "captured_at": ts,
            "idempotency_key": key,
        },
    }


def test_refunds_are_bounded_by_the_authorization():
    b = _replay(_events())
    b.append("refund", **_refund(2000, "r1"))
    b.append("refund", **_refund(3500, "r2", ts="2026-09-21T09:00:00Z"))
    with pytest.raises(ProducerError, match="refunds would total 5501, more than the 5500"):
        b.append("refund", **_refund(1, "r3", ts="2026-09-22T09:00:00Z"))
    result = verify_chain(b.records, PUBLIC, transaction_type="ai_referral_agent_session")
    assert result.valid and result.chain_complete  # refunds do not count (§3.10)


@pytest.mark.parametrize(
    "kwargs, needle",
    [
        ({"charge_ref": "ch_other"}, "charge_ref must be the §3.6 charge_id"),
        ({"currency": "EUR"}, "refund.currency must match"),
        ({}, None),
    ],
)
def test_refund_must_reference_the_charge(kwargs, needle):
    b = _replay(_events())
    if needle is None:
        b.append("refund", **_refund(100, "ok", **kwargs))
        return
    with pytest.raises(ProducerError, match=needle):
        b.append("refund", **_refund(100, "bad", **kwargs))


def test_refund_before_the_seal_is_refused():
    b = _replay(_events(), 5)
    with pytest.raises(ProducerError, match="post-seal; no authorization precedes it"):
        b.append("refund", **_refund(100, "early", ts="2026-09-14T15:08:00Z"))


# -- idempotency (§8.4) ----------------------------------------------------------------------


def test_identical_replay_is_idempotent():
    events = _events()
    b = _replay(events)
    again = b.append(events[6][0], **events[6][1])
    assert again == b.records[6] and len(b.records) == 7


def test_reused_key_for_a_different_event_is_refused():
    events = _events()
    b = _replay(events)
    kwargs = copy.deepcopy(events[6][1])
    kwargs["payload"]["status"] = "failed"
    with pytest.raises(ProducerError, match="already identifies a different event"):
        b.append("fulfillment", **kwargs)


def test_idempotency_fallback_is_per_minute():
    same = idempotency_fallback("t", "cart", "a", "2026-09-14T15:07:02Z")
    assert same == idempotency_fallback("t", "cart", "a", "2026-09-14T15:07:59Z")
    assert same != idempotency_fallback("t", "cart", "a", "2026-09-14T15:08:00Z")
    assert len(same) == 64 and int(same, 16) >= 0


def test_hmac_ref_needs_a_real_salt():
    with pytest.raises(ProducerError, match="at least 16 bytes"):
        hmac_ref(b"short", "x")
    assert hmac_ref(b"0123456789abcdef", "x").startswith("sha256:")


# -- export (§6.1, §6.2) ---------------------------------------------------------------------


def test_export_derives_the_wrapper_from_the_chain():
    records = build_records("honest")
    bundle = export(records)
    assert bundle["transaction"]["sealedBundleHash"] == records[5]["current_hash"]
    assert bundle["transaction"]["interactionChannel"] == "text_chat"
    assert bundle["transaction"]["createdAt"] == records[0]["hash_input"]["timestamp"]
    assert bundle["transaction"]["completedAt"] == records[6]["hash_input"]["timestamp"]
    assert bundle["merchantContext"] == {
        "merchantId": "merchant_demo_outfitters",
        "merchantName": "Demo Outfitters (fictional)",
        "totalValue": "55.00",
        "currency": "USD",
    }
    assert bundle["verification"]["valid"] is True
    assert bundle["evidenceTier"] == bundle["verification"]["evidenceTier"] == "D"
    assert bundle["customerHistory"] is None


def test_export_refuses_an_invalid_chain_for_submission():
    records = build_records("honest")
    records[2]["hash_input"]["payload"]["unit_price"] = 1
    with pytest.raises(ExportRefused) as info:
        export(records)
    assert any("recomputed hash" in e for e in info.value.errors)
    inquiry = export(records, for_submission=False)
    assert inquiry["verification"]["valid"] is False


def test_export_of_an_unsealed_chain_carries_no_seal():
    records = _replay(_events(), 5).records
    bundle = export_dispute_bundle(
        records,
        PUBLIC,
        transaction_id="t",
        transaction_type="ai_referral_agent_session",
        status="open",
        merchant_name="m",
        exported_at="2026-09-15T00:00:00Z",
        verified_at="2026-09-15T00:00:00Z",
    )
    assert bundle["transaction"]["sealedBundleHash"] is None
    assert bundle["transaction"]["completedAt"] is None
    assert bundle["verification"]["chainComplete"] is False
