"""A worked dispute, end to end: produce a chain, export it, attack it, re-verify every attack.

The scenario is one AI-referred purchase, a pair of hiking boots for $55.00, that the customer
later disputes as "item not received". `run_demo` builds the honest evidence with
`produce.ChainBuilder`, exports it with `produce.export_dispute_bundle`, then applies each of
`ATTACKS` to a copy of it and re-verifies the result with `bundle.verify_bundle` twice: once as a
recipient holding only the merchant's published key, and once as a recipient who also holds
the seal from an independent §4.3 existence anchor.

Each attack declares the outcome it should get, so the demo is a test: `aep-verify demo` exits
non-zero if any attack lands differently. The point is not that everything is caught. Some
attacks cannot be caught under v1.0.3-rc.2 by any verifier, and the report says which ones,
why, and what in the specification's open work would catch them.

Every key, salt, name, address and identifier here is synthetic. The keys are derived from
public labels, so anyone can re-derive them: they sign demo evidence and nothing else.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .bundle import BundleVerification, verify_bundle
from .canonical import canonicalize
from .chain import SPEC_VERSION, VERIFIER_ID, compute_hash, sign_hash
from .keys import public_key_to_base64
from .produce import (
    ChainBuilder,
    ExportRefused,
    export_dispute_bundle,
    hmac_ref,
    idempotency_fallback,
)


def _material(label: str) -> bytes:
    text = f"aep-verify demo/{label}: public test material, never real evidence"
    return hashlib.sha256(text.encode("utf-8")).digest()


MERCHANT_KEY = Ed25519PrivateKey.from_private_bytes(_material("merchant signing key"))
OUTSIDER_KEY = Ed25519PrivateKey.from_private_bytes(_material("outsider signing key"))
SALT = _material("merchant HMAC salt")

TRANSACTION_TYPE = "ai_referral_agent_session"
TRANSACTION_ID = "txn_demo_7f3a"
CHAIN_ID = "chain_demo_7f3a"
MERCHANT_ID = "merchant_demo_outfitters"
MERCHANT_NAME = "Demo Outfitters (fictional)"
EXPORTED_AT = "2026-10-21T14:00:00Z"
VERIFIED_AT = "2026-10-21T14:00:00Z"
CHARGE_ID = "ch_demo_7f3a"
PAYMENT_TOKEN = "pm_demo_tok_9Kx2"
# A 15-digit network transaction ID chosen to FAIL the Luhn check. One in ten 15-digit IDs
# passes it, and §3.6/§8.3 would then require the whole authorization to be rejected.
NETWORK_TRANSACTION_ID = "305019372819465"


def _ref(text: str) -> str:
    return hmac_ref(SALT, text)


CONSUMER = _ref("203.0.113.24")  # §3.2: the consumer actor id is the HMAC of the IP
SHIPPING_ADDRESS = _ref("742 Example Ave|Unit 4|Springfield|IL|62704|US")
OTHER_ADDRESS = _ref("17 Other Rd|Springfield|IL|62702|US")
RETURNS_ADDRESS = _ref("Demo Outfitters Returns|9 Dock Ln|Columbus|OH|43215|US")
SHOP_AGENT = "agent:demo-outfitters-shopping-assistant"

VARIANTS: dict[str, str] = {
    "honest": "delivered to the address the customer confirmed in the cart",
    "misdelivered": "the carrier left the parcel at a different address",
    "returned": "delivered, then shipped back by the customer; no refund issued yet",
    "unattributed": "no AI platform attested the citation, so no discovery artifact (§3.1)",
}


# ---------------------------------------------------------------------------------------------
# The honest evidence
# ---------------------------------------------------------------------------------------------


def _fallback_key(artifact_type: str, actor_id: str, ts: str) -> str:
    return idempotency_fallback(TRANSACTION_ID, artifact_type, actor_id, ts)


def _sealed_prefix(*, discovery: bool = True) -> ChainBuilder:
    """Discovery through authorization: everything the §2.5 seal commits to.

    §3.1: only the AI platform can emit discovery, so it "is absent from most chains". The
    `unattributed` variant omits it, as most real referral chains will.
    """
    b = ChainBuilder(
        transaction_type=TRANSACTION_TYPE,
        chain_id=CHAIN_ID,
        merchant_id=MERCHANT_ID,
        session_id_hash=_ref("session:demo-7f3a"),
        signing_key=MERCHANT_KEY,
    )
    if discovery:
        b.append(
            "discovery",
            actor_type="agent",
            actor_id="platform:perplexity",
            timestamp="2026-09-14T15:02:05Z",
            payload={
                "platform": "perplexity",
                "attribution_method": "url_params",
                "attribution_confidence": "high",
                "product_url_cited": "https://outfitters.example/p/trail-boot-42",
                "captured_at": "2026-09-14T15:02:05Z",
                "idempotency_key": "platform_evt_demo_0001",
            },
        )
    b.append(
        "referral",
        actor_type="user",
        actor_id=CONSUMER,
        timestamp="2026-09-14T15:03:40Z",
        payload={
            "referral_event_id": "ref_demo_0001",
            "consumer_ip_hash": CONSUMER,
            "consumer_ip_country": "US",
            "user_agent_hash": _ref("Mozilla/5.0 (demo)"),
            "consent_gpc": False,
            "consent_cookie": "granted",
            "referrer_domain": "perplexity.ai",
            "captured_at": "2026-09-14T15:03:40Z",
            "idempotency_key": _fallback_key("referral", CONSUMER, "2026-09-14T15:03:40Z"),
        },
    )
    b.append(
        "intent",
        actor_type="agent",
        actor_id=SHOP_AGENT,
        interaction_channel="text_chat",
        timestamp="2026-09-14T15:05:12Z",
        payload={
            "intent_id": "int_demo_0001",
            "product_id": "sku_trail_boot_42",
            "product_name": "Trailhead waterproof hiking boot",
            "variant_id": "size-10-brown",
            "quantity": 1,
            "unit_price": 4800,
            "currency": "USD",
            "price_displayed_at": "2026-09-14T15:05:10Z",
            "captured_at": "2026-09-14T15:05:12Z",
            "idempotency_key": _fallback_key("intent", SHOP_AGENT, "2026-09-14T15:05:12Z"),
        },
    )
    b.append(
        "policy",
        actor_type="merchant",
        actor_id="merchant:risk-engine",
        timestamp="2026-09-14T15:06:30Z",
        payload={
            "decision_id": "dec_demo_0001",
            "policy_engine_vendor": "in_house",
            "policy_version": "2026.09.1",
            "outcome": "approved",
            "escalated": False,
            "risk_score": 12,
            "rules_triggered": [],
            "evaluated_at": "2026-09-14T15:06:29Z",
            "captured_at": "2026-09-14T15:06:30Z",
            "idempotency_key": "risk_evt_demo_0001",
        },
    )
    b.append(
        "cart",
        actor_type="agent",
        actor_id=SHOP_AGENT,
        interaction_channel="text_chat",
        timestamp="2026-09-14T15:07:02Z",
        payload={
            "cart_id": "cart_demo_0001",
            "confirmed": True,
            "items": [
                {
                    "product_id": "sku_trail_boot_42",
                    "product_name": "Trailhead waterproof hiking boot",
                    "variant_id": "size-10-brown",
                    "quantity": 1,
                    "unit_price": 4800,
                }
            ],
            "subtotal": 4800,
            "shipping": 500,
            "tax": 200,
            "discounts": 0,
            "total": 5500,
            "currency": "USD",
            "shipping_address_hash": SHIPPING_ADDRESS,
            "billing_address_hash": SHIPPING_ADDRESS,
            "payment_method_token": PAYMENT_TOKEN,
            "cart_confirmed_at": "2026-09-14T15:07:01Z",
            "captured_at": "2026-09-14T15:07:02Z",
            "idempotency_key": _fallback_key("cart", SHOP_AGENT, "2026-09-14T15:07:02Z"),
        },
    )
    b.append(
        "authorization",
        actor_type="psp",
        actor_id="psp:demo-psp",
        timestamp="2026-09-14T15:07:09Z",
        payload={
            "psp": "demo_psp",
            "payment_intent_id": "pi_demo_7f3a",
            "charge_id": CHARGE_ID,
            "payment_method_token": PAYMENT_TOKEN,
            "payment_method_type": "card",
            "result": "approved",
            "auth_code": "A7Q2K9",
            "amount": 5500,
            "currency": "USD",
            "authorized_at": "2026-09-14T15:07:08Z",
            "settlement_rail": "card",
            "network_transaction_id": NETWORK_TRANSACTION_ID,
            "card_brand": "visa",
            "card_last4": "4242",
            "card_funding": "credit",
            "card_country": "US",
            "avs_result": "Y",
            "cvv_result": "M",
            "three_ds_result": "attempted",
            "three_ds_version": "2.2.0",
            "fraud_score": 9,
            "fraud_engine": "demo_fraud_engine",
            "stablecoin": None,
            "captured_at": "2026-09-14T15:07:09Z",
            "idempotency_key": "psp_evt_demo_0001",
        },
    )
    return b


def _deliver(b: ChainBuilder, address_hash: str) -> None:
    b.append(
        "fulfillment",
        actor_type="fulfillment_provider",
        actor_id="carrier:ups",
        timestamp="2026-09-16T18:40:00Z",
        payload={
            "fulfillment_id": "ful_demo_0001",
            "platform_order_id": "order_demo_7f3a",
            "carrier": "ups",
            "tracking_number": "1Z999AA10123456784",
            "status": "delivered",
            "shipped_at": "2026-09-15T13:10:00Z",
            "delivered_at": "2026-09-16T18:39:00Z",
            "delivery_address_hash": address_hash,
            "delivery_address_match": address_hash == SHIPPING_ADDRESS,
            "captured_at": "2026-09-16T18:40:00Z",
            "idempotency_key": "carrier_evt_demo_0001",
        },
    )


def _return(b: ChainBuilder) -> None:
    b.append(
        "fulfillment",
        actor_type="fulfillment_provider",
        actor_id="carrier:ups",
        timestamp="2026-09-25T16:20:00Z",
        payload={
            "fulfillment_id": "ful_demo_0002",
            "platform_order_id": "order_demo_7f3a",
            "carrier": "ups",
            "tracking_number": "1Z999AA10123456795",
            "status": "returned",
            "shipped_at": "2026-09-23T10:05:00Z",
            "delivery_address_hash": RETURNS_ADDRESS,
            "delivery_address_match": False,
            "captured_at": "2026-09-25T16:20:00Z",
            "idempotency_key": "carrier_evt_demo_0002",
        },
    )


def build_records(variant: str) -> list[dict[str, Any]]:
    """The signed artifact records for one variant. Deterministic: Ed25519 signing is."""
    if variant not in VARIANTS:
        raise ValueError(f"unknown variant {variant!r}; expected one of {sorted(VARIANTS)}")
    b = _sealed_prefix(discovery=variant != "unattributed")
    _deliver(b, OTHER_ADDRESS if variant == "misdelivered" else SHIPPING_ADDRESS)
    if variant == "returned":
        _return(b)
    return b.records


def export(records: list[dict[str, Any]], *, for_submission: bool = True) -> dict[str, Any]:
    return export_dispute_bundle(
        records,
        MERCHANT_KEY.public_key(),
        transaction_id=TRANSACTION_ID,
        transaction_type=TRANSACTION_TYPE,
        status="disputed",
        merchant_name=MERCHANT_NAME,
        exported_at=EXPORTED_AT,
        verified_at=VERIFIED_AT,
        for_submission=for_submission,
    )


# ---------------------------------------------------------------------------------------------
# Attacks
# ---------------------------------------------------------------------------------------------

REFUSED_EVIDENCE = "refused: evidence"
REFUSED_ANCHOR = "refused: anchor"
REFUSED_WRAPPER = "refused: wrapper"
REFUSED_GATE = "refused: §6.2 gate"
REFUSED_LOG = "refused: head log"
FLAGGED = "flagged"
UNDETECTED = "undetected"
OUTCOME_MEANINGS: dict[str, str] = {
    REFUSED_EVIDENCE: "the chain itself fails §5 re-verification (`valid=false`).",
    REFUSED_ANCHOR: "the chain verifies, but its seal is not the independently anchored one.",
    REFUSED_LOG: (
        "the chain verifies, but its seal or a post-seal artifact is not what the independent "
        "head log recorded (the mechanism draft Issue I proposes; not in v1.0.3-rc.2)."
    ),
    REFUSED_WRAPPER: (
        "the chain verifies, but the unsigned wrapper contradicts it (aep-verify extension)."
    ),
    REFUSED_GATE: "the chain verifies, but the bundle fails the §6.2 export gate.",
    FLAGGED: "exportable, with a warning the honest bundle does not get.",
    UNDETECTED: "exportable, with nothing that tells it apart from the honest bundle.",
}

OUTSIDER = "anyone handling the bundle"
MERCHANT = "the merchant (holds the signing key)"


@dataclass(frozen=True)
class Attack:
    id: str
    actor: str
    variant: str
    title: str
    apply: Callable[[dict[str, Any]], dict[str, Any]]
    expected: str
    expected_anchored: str
    expected_logged: str
    note: str


def _of_type(bundle: dict[str, Any], artifact_type: str, nth: int = 0) -> dict[str, Any]:
    matches: list[dict[str, Any]] = [
        a for a in bundle["artifacts"] if a["artifact_type"] == artifact_type
    ]
    return matches[nth]


def _payload(record: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = record["hash_input"]["payload"]
    return payload


def _recopy(record: dict[str, Any]) -> None:
    """Keep the unsigned canonical_json copy in step with an edit, as a careful forger would."""
    record["canonical_json"] = canonicalize(record["hash_input"]).decode("utf-8")


def _renumber(bundle: dict[str, Any]) -> None:
    for position, record in enumerate(bundle["artifacts"], start=1):
        record["sequence_number"] = position


def _resign_from(records: list[dict[str, Any]], start: int, key: Ed25519PrivateKey) -> None:
    """Re-link, re-hash and re-sign records[start:] with `key`: a full rewrite from there on."""
    previous = records[start - 1]["current_hash"] if start else None
    for record in records[start:]:
        record["hash_input"]["previous_hash"] = previous
        _recopy(record)
        record["current_hash"] = compute_hash(record["hash_input"])
        record["server_signature"] = sign_hash(key, record["current_hash"])
        previous = record["current_hash"]


def _position(records: list[dict[str, Any]], artifact_type: str) -> int:
    return next(i for i, r in enumerate(records) if r["artifact_type"] == artifact_type)


def _reexport(bundle: dict[str, Any], records: list[dict[str, Any]]) -> dict[str, Any]:
    """The merchant re-exports a rewritten chain. If its own exporter refuses (§6.2), it lies:
    the embedded verification block is copied from the honest bundle."""
    try:
        return export(records)
    except ExportRefused:
        forged = export(records, for_submission=False)
        forged["verification"] = copy.deepcopy(bundle["verification"])
        return forged


def _edit_price(b: dict[str, Any]) -> dict[str, Any]:
    intent = _of_type(b, "intent")
    _payload(intent)["unit_price"] = 2400
    _recopy(intent)
    return b


def _resign_outsider(b: dict[str, Any]) -> dict[str, Any]:
    records = b["artifacts"]
    cart, auth = _payload(_of_type(b, "cart")), _payload(_of_type(b, "authorization"))
    cart["items"][0]["unit_price"] = cart["subtotal"] = 2400
    cart["total"] = auth["amount"] = 3100
    _resign_from(records, _position(records, "cart"), OUTSIDER_KEY)
    b["transaction"]["sealedBundleHash"] = _of_type(b, "authorization")["current_hash"]
    b["merchantContext"]["totalValue"] = "31.00"
    return b


def _delete_policy(b: dict[str, Any]) -> dict[str, Any]:
    b["artifacts"] = [a for a in b["artifacts"] if a["artifact_type"] != "policy"]
    _renumber(b)
    return b


def _reorder(b: dict[str, Any]) -> dict[str, Any]:
    records = b["artifacts"]
    records[0], records[1] = records[1], records[0]
    _renumber(b)
    return b


def _backdate_delivery(b: dict[str, Any]) -> dict[str, Any]:
    fulfillment = _of_type(b, "fulfillment")
    _payload(fulfillment)["delivered_at"] = "2026-09-15T18:39:00Z"
    _recopy(fulfillment)
    return b


def _swap_seal(b: dict[str, Any]) -> dict[str, Any]:
    b["transaction"]["sealedBundleHash"] = _of_type(b, "cart")["current_hash"]
    return b


def _relabel_merchant(b: dict[str, Any]) -> dict[str, Any]:
    b["merchantContext"]["merchantId"] = "merchant_demo_rival"
    return b


def _stale_verification(b: dict[str, Any]) -> dict[str, Any]:
    b["artifacts"] = b["artifacts"][:-1]
    return b


def _cached(b: dict[str, Any]) -> dict[str, Any]:
    b["verification"]["verificationMode"] = "cached"
    return b


def _spec_version(b: dict[str, Any]) -> dict[str, Any]:
    b["specVersion"] = "aep-1.0.2"
    return b


def _shrink_total(b: dict[str, Any]) -> dict[str, Any]:
    b["merchantContext"]["totalValue"] = "5.50"
    return b


def _swap_currency(b: dict[str, Any]) -> dict[str, Any]:
    b["merchantContext"]["currency"] = "EUR"
    return b


def _inflate_tier(b: dict[str, Any]) -> dict[str, Any]:
    b["evidenceTier"] = "A"
    return b


def _claim_ap2(b: dict[str, Any]) -> dict[str, Any]:
    b["protocolEnvelopesVerified"] = [{"envelope": "AP2", "verified": True, "status": "verified"}]
    return b


def _relabel_channel(b: dict[str, Any]) -> dict[str, Any]:
    b["transaction"]["interactionChannel"] = "voice"
    return b


def _unbound_fields(b: dict[str, Any]) -> dict[str, Any]:
    b["transaction"]["id"] = "txn_demo_9c1e"
    b["transaction"]["status"] = "resolved_for_merchant"
    b["merchantContext"]["merchantName"] = "Demo Outfitters Premium (fictional)"
    b["exportedAt"] = "2026-09-17T09:00:00Z"
    return b


def _fabricate_history(b: dict[str, Any]) -> dict[str, Any]:
    """Two prior undisputed purchases 120-365 days old: the §6.1 qualification pattern."""
    b["customerHistory"] = {
        "identity_keys": {
            "account_login_id_ref": _ref("login:demo-customer"),
            "ip_ref": CONSUMER,
            "device_id_ref": None,
            "device_fingerprint": None,
            "shipping_address_ref": SHIPPING_ADDRESS,
        },
        "prior_transactions": [
            {
                "chain_id": "chain_demo_1a01",
                "charge_ref": "ch_demo_prior_01",
                "processed_date": "2026-03-02T10:00:00Z",
                "amount": 6200,
                "currency": "USD",
                "matched_elements": ["ip_ref", "shipping_address_ref"],
                "disputed": False,
            },
            {
                "chain_id": "chain_demo_1a02",
                "charge_ref": "ch_demo_prior_02",
                "processed_date": "2025-12-11T10:00:00Z",
                "amount": 3900,
                "currency": "USD",
                "matched_elements": ["account_login_id_ref", "shipping_address_ref"],
                "disputed": False,
            },
        ],
        "dispute_count": 0,
        "refund_count": 0,
        "window_days": 365,
    }
    return b


def _flip_address_match(b: dict[str, Any]) -> dict[str, Any]:
    records = copy.deepcopy(b["artifacts"])
    at = _position(records, "fulfillment")
    _payload(records[at])["delivery_address_match"] = True
    _resign_from(records, at, MERCHANT_KEY)
    return _reexport(b, records)


def _forge_delivery_address(b: dict[str, Any]) -> dict[str, Any]:
    records = copy.deepcopy(b["artifacts"])
    at = _position(records, "fulfillment")
    _payload(records[at])["delivery_address_hash"] = SHIPPING_ADDRESS
    _payload(records[at])["delivery_address_match"] = True
    _resign_from(records, at, MERCHANT_KEY)
    return _reexport(b, records)


def _upgrade_3ds(b: dict[str, Any]) -> dict[str, Any]:
    records = copy.deepcopy(b["artifacts"])
    at = _position(records, "authorization")
    _payload(records[at])["three_ds_result"] = "authenticated"
    _resign_from(records, at, MERCHANT_KEY)
    return _reexport(b, records)


def _hide_return(b: dict[str, Any]) -> dict[str, Any]:
    return _reexport(b, copy.deepcopy(b["artifacts"][:-1]))


def _retype(b: dict[str, Any]) -> dict[str, Any]:
    """Six artifacts are incomplete for an agent session (7) but complete for a storefront
    checkout (6). No artifact records the type, so the exporter picks the one that fits."""
    b["transaction"]["transactionType"] = "ai_referral_standard_checkout"
    b["verification"]["chainComplete"] = True
    return b


ATTACKS: tuple[Attack, ...] = (
    Attack(
        "edit-price",
        OUTSIDER,
        "honest",
        "Halve the intent's unit_price, no re-signing",
        _edit_price,
        REFUSED_EVIDENCE,
        REFUSED_EVIDENCE,
        REFUSED_EVIDENCE,
        "The recomputed §4.1 hash no longer equals the stored one.",
    ),
    Attack(
        "resign-outsider-key",
        OUTSIDER,
        "honest",
        "Rewrite cart and authorization to $31.00, re-sign everything after with another key",
        _resign_outsider,
        REFUSED_EVIDENCE,
        REFUSED_EVIDENCE,
        REFUSED_EVIDENCE,
        "Hashes and links are consistent; the signatures are not the merchant's published key.",
    ),
    Attack(
        "delete-policy",
        OUTSIDER,
        "honest",
        "Delete the policy artifact and renumber",
        _delete_policy,
        REFUSED_EVIDENCE,
        REFUSED_EVIDENCE,
        REFUSED_EVIDENCE,
        "The cart's previous_hash names an artifact that is gone (§4.2).",
    ),
    Attack(
        "reorder",
        OUTSIDER,
        "honest",
        "Swap the discovery and referral artifacts",
        _reorder,
        REFUSED_EVIDENCE,
        REFUSED_EVIDENCE,
        REFUSED_EVIDENCE,
        "Genesis and link rules break, and §3.9.2 order is violated.",
    ),
    Attack(
        "backdate-delivery",
        OUTSIDER,
        "honest",
        "Move delivered_at one day earlier",
        _backdate_delivery,
        REFUSED_EVIDENCE,
        REFUSED_EVIDENCE,
        REFUSED_EVIDENCE,
        "Post-seal artifacts are hashed and signed like any other.",
    ),
    Attack(
        "swap-seal",
        OUTSIDER,
        "honest",
        "Point transaction.sealedBundleHash at the cart",
        _swap_seal,
        REFUSED_EVIDENCE,
        REFUSED_EVIDENCE,
        REFUSED_EVIDENCE,
        "The seal must be the authorization artifact's current_hash (§2.5).",
    ),
    Attack(
        "relabel-merchant",
        OUTSIDER,
        "honest",
        "Claim the bundle for another merchantId",
        _relabel_merchant,
        REFUSED_EVIDENCE,
        REFUSED_EVIDENCE,
        REFUSED_EVIDENCE,
        "Every artifact's hashed metadata.merchant_id disagrees (§2.7).",
    ),
    Attack(
        "stale-verification",
        OUTSIDER,
        "honest",
        "Drop the delivery and keep the old verification block",
        _stale_verification,
        REFUSED_GATE,
        REFUSED_GATE,
        REFUSED_LOG,
        "The shorter chain still verifies; re-verification disagrees with the embedded claim "
        "(§6.2). The wrapper alone would not have caught it: see hide-return.",
    ),
    Attack(
        "cached-mode",
        OUTSIDER,
        "honest",
        "Mark the verification as cached",
        _cached,
        REFUSED_GATE,
        REFUSED_GATE,
        REFUSED_GATE,
        "§6.2: a cached result MUST NOT be exported for submission.",
    ),
    Attack(
        "spec-version",
        OUTSIDER,
        "honest",
        "Declare spec_version aep-1.0.2 at bundle level",
        _spec_version,
        REFUSED_EVIDENCE,
        REFUSED_EVIDENCE,
        REFUSED_EVIDENCE,
        "The bundle-level version conflicts with every artifact's hashed one (§2.7).",
    ),
    Attack(
        "shrink-total",
        OUTSIDER,
        "honest",
        "Restate merchantContext.totalValue as 5.50",
        _shrink_total,
        REFUSED_WRAPPER,
        REFUSED_WRAPPER,
        REFUSED_WRAPPER,
        "No signature covers the wrapper; aep-verify checks it against the sealed cart.",
    ),
    Attack(
        "swap-currency",
        OUTSIDER,
        "honest",
        "Restate merchantContext.currency as EUR",
        _swap_currency,
        REFUSED_WRAPPER,
        REFUSED_WRAPPER,
        REFUSED_WRAPPER,
        "Checked against the sealed cart's currency (aep-verify extension).",
    ),
    Attack(
        "inflate-tier",
        OUTSIDER,
        "honest",
        "Restate evidenceTier D as A",
        _inflate_tier,
        REFUSED_WRAPPER,
        REFUSED_WRAPPER,
        REFUSED_WRAPPER,
        "Recomputed from the chain: no delegation sub-wrapper, tier D (§3.9.12).",
    ),
    Attack(
        "claim-ap2",
        OUTSIDER,
        "honest",
        "Claim a verified AP2 envelope",
        _claim_ap2,
        REFUSED_WRAPPER,
        REFUSED_WRAPPER,
        REFUSED_WRAPPER,
        "The chain carries no delegation artifact, so no envelope exists to verify.",
    ),
    Attack(
        "relabel-channel",
        OUTSIDER,
        "honest",
        "Restate interactionChannel text_chat as voice",
        _relabel_channel,
        FLAGGED,
        FLAGGED,
        FLAGGED,
        "§6.1 defines no derivation, so a mismatch is a warning, not a refusal.",
    ),
    Attack(
        "unbound-fields",
        OUTSIDER,
        "honest",
        "Rewrite transaction.id, status, merchantName and exportedAt",
        _unbound_fields,
        UNDETECTED,
        UNDETECTED,
        UNDETECTED,
        "No artifact carries these values and nothing signs the wrapper. Upstream #3 scopes an "
        "export hash and exporter signature; #16 an export record.",
    ),
    Attack(
        "fabricate-history",
        OUTSIDER,
        "honest",
        "Add a customerHistory with two prior undisputed purchases, 120-365 days old",
        _fabricate_history,
        FLAGGED,
        FLAGGED,
        FLAGGED,
        "§6.1: customerHistory is computed across chains and is not hash-chained. aep-verify "
        "says so on every bundle that carries one; nothing can check the claim itself.",
    ),
    Attack(
        "flip-address-match",
        MERCHANT,
        "misdelivered",
        "Set delivery_address_match true beside the real, different hashes; re-sign",
        _flip_address_match,
        REFUSED_EVIDENCE,
        REFUSED_EVIDENCE,
        REFUSED_EVIDENCE,
        "Caught only because aep-verify recomputes the §3.7 MUST. The merchant signs the "
        "boolean, so without recomputation nothing breaks.",
    ),
    Attack(
        "forge-delivery-address",
        MERCHANT,
        "misdelivered",
        "Replace the delivery address hash with the cart's, set the match true, re-sign",
        _forge_delivery_address,
        UNDETECTED,
        UNDETECTED,
        REFUSED_LOG,
        "Fulfillment is post-seal and signed with the merchant's key. Only the carrier's own "
        "record refutes it; the payload has no field for a carrier signature (§3.7).",
    ),
    Attack(
        "upgrade-3ds",
        MERCHANT,
        "honest",
        "Rewrite three_ds_result 'attempted' as 'authenticated'; re-sign from the seal on",
        _upgrade_3ds,
        UNDETECTED,
        REFUSED_ANCHOR,
        REFUSED_LOG,
        "Signatures attest integrity, not existence, as against the signer (§4.3). An "
        "externally anchored seal catches the rewrite; so would the issuer's 3DS record.",
    ),
    Attack(
        "hide-return",
        MERCHANT,
        "returned",
        "Drop the returned-shipment event and re-export",
        _hide_return,
        UNDETECTED,
        UNDETECTED,
        REFUSED_LOG,
        "Nothing commits to the last artifact, and the seal covers only the pre-seal chain. "
        "The truncated bundle reports chain_complete true where the honest one reports false.",
    ),
    Attack(
        "retype-transaction",
        OUTSIDER,
        "unattributed",
        "Relabel an agent session as a storefront checkout so the artifact count fits",
        _retype,
        UNDETECTED,
        UNDETECTED,
        UNDETECTED,
        "No artifact carries the transaction type (§2.7 lists no such field), yet it alone "
        "sets the expected count. The honest bundle reports chain_complete false; the "
        "relabelled one, true.",
    ),
)


# ---------------------------------------------------------------------------------------------
# Running and classifying
# ---------------------------------------------------------------------------------------------


@dataclass
class Observation:
    outcome: str
    evidence: str
    chain_complete: bool
    exportable: bool


@dataclass
class AttackResult:
    attack: Attack
    bundle: dict[str, Any]
    plain: Observation
    anchored: Observation
    logged: Observation

    @property
    def as_expected(self) -> bool:
        return (
            self.plain.outcome == self.attack.expected
            and self.anchored.outcome == self.attack.expected_anchored
            and self.logged.outcome == self.attack.expected_logged
        )


@dataclass
class DemoRun:
    bundles: dict[str, dict[str, Any]]
    honest: dict[str, BundleVerification]
    seals: dict[str, str]
    heads: dict[str, list[str]]
    results: list[AttackResult] = field(default_factory=list)

    @property
    def all_as_expected(self) -> bool:
        return all(r.as_expected for r in self.results)

    @property
    def anchored_seal(self) -> str:
        """The seal the main (honest) transaction's merchant anchored."""
        return self.seals["honest"]

    def identical_honest(self, result: AttackResult) -> str | None:
        """The honest variant a forged bundle is indistinguishable from, if any."""
        return next((name for name, b in self.bundles.items() if b == result.bundle), None)


def _warnings(outcome: BundleVerification) -> set[str]:
    return set(outcome.warnings) | set(outcome.verification.warnings)


def classify(outcome: BundleVerification, baseline: BundleVerification) -> Observation:
    """Map a verification outcome to the strongest thing a recipient learns from it."""
    v = outcome.verification
    if not v.valid:
        result, evidence = REFUSED_EVIDENCE, v.errors[0] if v.errors else "valid=false"
    elif outcome.anchor_matches is False:
        result = REFUSED_ANCHOR
        evidence = next(e for e in outcome.errors if "anchored seal" in e)
    elif outcome.heads_match is False:
        result = REFUSED_LOG
        evidence = next(e for e in outcome.errors if "head log" in e)
    elif outcome.wrapper_contradictions:
        result, evidence = REFUSED_WRAPPER, outcome.wrapper_contradictions[0]
    elif not outcome.exportable:
        details = outcome.embedded_disagreements + outcome.errors + outcome.gate_reasons
        result, evidence = REFUSED_GATE, details[0]
    else:
        new = sorted(_warnings(outcome) - _warnings(baseline))
        result, evidence = (FLAGGED, new[0]) if new else (UNDETECTED, "")
    return Observation(result, evidence, v.chain_complete, outcome.exportable)


def logged_heads(bundle: dict[str, Any]) -> list[str]:
    """What an append-time head log would hold for an honest bundle: the seal, then each
    post-seal artifact's hash as it arrived (the mechanism draft Issue I proposes)."""
    hashes = [str(a["current_hash"]) for a in bundle["artifacts"]]
    seal_at = next(
        i for i, a in enumerate(bundle["artifacts"]) if a["artifact_type"] == "authorization"
    )
    return hashes[seal_at:]


def run_demo() -> DemoRun:
    public_key = MERCHANT_KEY.public_key()
    bundles = {name: export(build_records(name)) for name in VARIANTS}
    # Each variant is anchored at its own seal, and logged at its own heads, as its merchant
    # would have done when each event happened.
    seals = {name: b["transaction"]["sealedBundleHash"] for name, b in bundles.items()}
    heads = {name: logged_heads(b) for name, b in bundles.items()}

    def check(
        bundle: dict[str, Any], *, seal: str | None = None, log: list[str] | None = None
    ) -> BundleVerification:
        return verify_bundle(
            bundle, public_key, verified_at=VERIFIED_AT, anchored_seal=seal, anchored_heads=log
        )

    honest = {name: check(b) for name, b in bundles.items()}
    honest_anchored = {name: check(b, seal=seals[name]) for name, b in bundles.items()}
    honest_logged = {name: check(b, log=heads[name]) for name, b in bundles.items()}
    run = DemoRun(bundles=bundles, honest=honest, seals=seals, heads=heads)
    for attack in ATTACKS:
        tampered = attack.apply(copy.deepcopy(bundles[attack.variant]))
        v = attack.variant
        run.results.append(
            AttackResult(
                attack=attack,
                bundle=tampered,
                plain=classify(check(tampered), honest[v]),
                anchored=classify(check(tampered, seal=seals[v]), honest_anchored[v]),
                logged=classify(check(tampered, log=heads[v]), honest_logged[v]),
            )
        )
    return run


# ---------------------------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------------------------


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _timeline(records: list[dict[str, Any]]) -> list[str]:
    facts = {
        "discovery": lambda p: f"cited by {p['platform']}, {p['attribution_method']}",
        "referral": lambda p: (
            f"arrived from {p.get('referrer_domain')}, {p['consumer_ip_country']}"
        ),
        "intent": lambda p: f"{p['product_name']} x{p['quantity']} at {p['unit_price']} minor",
        "policy": lambda p: f"{p['outcome']}, risk {p['risk_score']}",
        "cart": lambda p: (
            f"total {p['total']} {p['currency']} = {p['subtotal']} + {p['shipping']} + "
            f"{p['tax']} - {p['discounts']}"
        ),
        "authorization": lambda p: (
            f"{p['result']} {p['amount']} {p['currency']}, AVS {p['avs_result']}, "
            f"CVV {p['cvv_result']}, 3DS {p['three_ds_result']}"
        ),
        "fulfillment": lambda p: (
            f"{p['status']}, address match {str(p['delivery_address_match']).lower()}"
        ),
    }
    rows = [
        "| # | artifact | actor | channel | timestamp | what it records |",
        "|---|---|---|---|---|---|",
    ]
    for r in records:
        hi = r["hash_input"]
        fact = facts.get(r["artifact_type"], lambda p: "")(hi["payload"])
        rows.append(
            f"| {r['sequence_number']} | {r['artifact_type']} | {hi['actor_type']} | "
            f"{hi['interaction_channel'] or '-'} | {hi['timestamp']} | {_cell(fact)} |"
        )
    return rows


RECIPIENTS: tuple[tuple[str, str], ...] = (
    ("key only", "holds the merchant's published key, which is all v1.0.3-rc.2 assumes."),
    (
        "key + anchored seal",
        "also holds the seal from an independent §4.3 existence anchor taken when the "
        "transaction was sealed.",
    ),
    (
        "key + head log",
        "also holds an append-time log of the chain head: the seal, then each post-seal "
        "artifact's hash as it arrived. v1.0.3-rc.2 defines no such log; draft Issue I proposes "
        "it, so this column is what the proposal would buy, not what the text provides.",
    ),
)


def _observations(r: AttackResult) -> tuple[Observation, Observation, Observation]:
    return r.plain, r.anchored, r.logged


def render_report(run: DemoRun, files: dict[str, str]) -> str:
    honest = run.honest["honest"]
    v = honest.verification
    columns = list(zip(*(_observations(r) for r in run.results), strict=True))
    tally_rows = []
    for (name, _), column in zip(RECIPIENTS, columns, strict=True):
        refused = sum(o.outcome.startswith("refused") for o in column)
        flagged = sum(o.outcome == FLAGGED for o in column)
        undetected = [r.attack.id for r, o in zip(run.results, column, strict=True)
                      if o.outcome == UNDETECTED]  # fmt: skip
        tally_rows.append(
            f"| {name} | {refused} | {flagged} | {len(undetected)}: "
            + ", ".join(f"`{a}`" for a in undetected)
            + " |"
        )
    lines = [
        "# AEP dispute-bundle demo: what the bundle proves, and what it cannot",
        "",
        f"Generated by `{VERIFIER_ID}` against `{SPEC_VERSION}`. Regenerate with "
        "`aep-verify demo --out DIR`; the output is byte-for-byte deterministic.",
        "",
        "> **Synthetic data.** The merchant, customer, addresses, carrier events and charge are "
        "invented. The signing keys are derived from public labels in `aep_verify/demo.py`, so "
        "anyone can re-derive them; they sign demo evidence and nothing else.",
        "",
        "## The transaction",
        "",
        "A shopper asks an AI assistant for waterproof hiking boots, follows its citation to the "
        "merchant, and buys one pair through the merchant's shopping agent in a text chat: "
        "$48.00, plus $5.00 shipping and $2.00 tax. The carrier delivers two days later. Five "
        "weeks on, the cardholder disputes the charge as *item not received*, and the merchant "
        "exports its AEP evidence.",
        "",
        *_timeline(run.bundles["honest"]["artifacts"]),
        "",
        f"`{TRANSACTION_TYPE}` without a delegation artifact: no agentic payment protocol was "
        "in play, so the chain is `GENERIC` and §3.9.2 requires delegation to be omitted. "
        "Seven artifacts, the Appendix B count for that case.",
        "",
        "## The honest bundle",
        "",
        "`aep-verify bundle bundles/honest.json --key merchant-public-key.txt` gives "
        f"`valid={v.valid}`, `chain_complete={v.chain_complete}`, "
        f"`artifacts_verified={v.artifacts_verified}`, `evidence_tier={v.evidence_tier}`, "
        f"`exportable={honest.exportable}`.",
        "",
        "What that establishes, and nothing more:",
        "",
        "- Every artifact is exactly what the merchant's published key signed, in this order, "
        "with nothing inserted, removed or reordered between the first artifact and the last "
        "one present (§2.3, §4.2, §4.3).",
        "- `sealedBundleHash` is the authorization artifact's hash (§2.5), so it commits to "
        "everything from discovery through authorization.",
        "- The cart adds up (§3.5 MUST-1), the charge equals the cart in amount and currency "
        "(§3.6 MUST-1), and the delivery address hash equals the cart's shipping address hash "
        "(§3.7).",
        "- The wrapper's total, currency, evidence tier and envelope list agree with the sealed "
        "chain. This last check is an aep-verify extension: §6.1 binds no wrapper field.",
        "",
        f"## {len(run.results)} attacks, three recipients",
        "",
        "Each attack edits a copy of an honest bundle, and three recipients re-verify it. Each "
        "recipient:",
        "",
        *(f"- **{name}** {meaning}" for name, meaning in RECIPIENTS),
        "",
        "| recipient | refused | flagged | undetected |",
        "|---|---|---|---|",
        *tally_rows,
        "",
        *(f"- **{outcome}**: {meaning}" for outcome, meaning in OUTCOME_MEANINGS.items()),
        "",
        "| attack | who can do it | key only | + anchored seal | + head log (proposed) | why |",
        "|---|---|---|---|---|---|",
    ]
    for r in run.results:
        a = r.attack
        lines.append(
            f"| `{a.id}`: {_cell(a.title)} | {a.actor} | **{r.plain.outcome}** | "
            f"**{r.anchored.outcome}** | **{r.logged.outcome}** | {_cell(a.note)} |"
        )
    twins = [(r.attack.id, twin) for r in run.results if (twin := run.identical_honest(r))]
    lines += [
        "",
        "Bases: `misdelivered` attacks start from a bundle where the carrier left the parcel at "
        "a different address; `hide-return` from one where the customer shipped the boots back; "
        "`retype-transaction` from one with no discovery artifact, because no AI platform "
        "attested the citation. Each recipient's seal and log belong to the bundle under "
        "attack (the main transaction's seal is "
        f"`{run.anchored_seal}`). Every tampered bundle is in `attacks/`, the logs are in "
        "`anchored-heads/`, and `results.json` holds the exact message each verification "
        "produced.",
        "",
    ]
    if twins:
        named = " and ".join(f"`{attack}`" for attack, _ in twins)
        targets = sorted({f"`bundles/{twin}.json`" for _, twin in twins})
        lines += [
            f"**{named} produce bytes identical to {' and '.join(targets)}.** Compare the "
            "SHA-256 column below. A forged export that is byte-for-byte an honest export cannot "
            "be told apart by any verifier that reads only the bundle, now or later: that is a "
            "proof, not a test result. Only evidence from outside the bundle can separate them, "
            "and the head-log column is one such piece of evidence: it refuses both.",
            "",
        ]
    lines += [
        "## What no v1.0.3-rc.2 verifier can establish",
        "",
        "1. **When.** A signature proves which key signed, not when. §4.3 says so: the chain "
        'and its signature "attest to integrity, not to existence at a point in time as '
        'against that party". The merchant can rebuild its own chain at will (`upgrade-3ds`). '
        "An externally anchored seal closes that for the pre-seal chain.",
        "2. **That nothing came after.** No hash commits to the last artifact. §2.3 says a "
        'deletion is detectable "at every subsequent artifact"; a deleted tail has none. '
        "Neither anchoring target §4.3 names closes this: the seal stops at authorization, "
        "and an export hash is computed after the exporter has chosen what to include. Cutting "
        "the tail can even *raise* `chain_complete`: the honest returned-parcel chain counts "
        "eight artifacts against an expected seven and reports false; the truncated one reports "
        "true (`hide-return`). A head log written as each event arrives closes it (third "
        "column). Upstream #16's disclosure manifest (deferred to v1.0.4) lets an honest "
        "exporter declare omissions, but the exporter writes it.",
        "3. **That the delivery happened.** The fulfillment artifact is signed by the "
        'merchant\'s server. §3.7 says the carrier "contributes attested data", but the payload '
        "has no field for a carrier signature, so `delivered` is as strong as the merchant's "
        "word until a reviewer checks the tracking number with the carrier "
        "(`forge-delivery-address`). A head log stops the merchant rewriting a delivery after "
        "the fact, but not logging a false one at the time; only the carrier's own signature "
        "does that. Upstream #35 makes merchant-relayed carrier data Asserted in v1.0.3-final "
        "and defers carrier-signed tracking events to v1.0.4.",
        "4. **That the address is the cardholder's.** Address hashes are HMACs under the "
        "merchant's salt (§2.7). Without the salt a recipient can check only that two hashes "
        "are equal, which is why §2.8 classes them Asserted for that recipient.",
        "5. **Anything the wrapper says that the chain does not.** `transaction.id`, `status`, "
        "`merchantName`, `exportedAt` and `customerHistory` are unsigned (`unbound-fields`, "
        "`fabricate-history`). Upstream #3 and #16 scope the export hash and export record "
        "for v1.0.3-final.",
        "6. **Whether the chain is complete.** `chain_complete` compares the artifact count "
        "with the count Appendix B expects for the transaction type, and no artifact records "
        'the type. §3.1 says discovery "is absent from most chains", yet the expected count '
        "for an agent session assumes it, so the honest `unattributed` chain reports false; "
        "relabelled as a storefront checkout it reports true (`retype-transaction`).",
        "",
        "## What closes each gap",
        "",
        "| gap | attacks | closed by | where it stands |",
        "|---|---|---|---|",
        "| pre-seal rewrite by the key holder | `upgrade-3ds` | an externally anchored seal | "
        "§4.3, RECOMMENDED in rc.2 |",
        "| post-seal truncation or rewrite | `hide-return`, `forge-delivery-address`, "
        "`stale-verification` | the chain head anchored at each append | draft Issue I |",
        "| a false event logged at the time | (none; out of a bundle's reach) | a signature "
        "from the event's source, e.g. the carrier | #35, deferred to v1.0.4 |",
        "| unsigned wrapper | `unbound-fields`, `fabricate-history` | an export hash and "
        "exporter signature | #3, #16, v1.0.3-final |",
        "| unbound transaction type | `retype-transaction` | the type in hashed `metadata` | "
        "draft Issue G |",
        "",
        "## Notes for the specification (drafts, not filed)",
        "",
        '- §3.7 calls `delivery_address_match` impossible to forge "without breaking the hash '
        'chain upstream". The merchant computes and signs that boolean, so a signed `true` '
        "beside two different hashes breaks nothing. The claim holds only if verifiers "
        "recompute it, and §5 does not list that step. aep-verify recomputes it "
        "(`flip-address-match`).",
        "- §3.6 requires `network_transaction_id` on card authorizations, and §3.6/§8.3 require "
        "rejecting any authorization payload containing a 13-19 digit run that passes Luhn. "
        "Exactly one in ten 15-digit numbers passes Luhn, so a numeric 15-digit network ID "
        "fails that gate one time in ten. Upstream #34's move to an NTI digest in the shared "
        "plane would remove the conflict there; the raw plane keeps it.",
        "- §4.3's two anchoring targets, the sealed hash and the exported bundle hash, both "
        "leave post-seal truncation by the exporter undetectable (item 2 above). A third "
        "target, the chain head at each post-seal append, would not; the third column runs it.",
        "- The transaction type is not a §2.7 chain-level field, so the input that decides "
        "`chain_complete` is covered by no hash. Carrying it in the hashed `metadata`, like "
        "`merchant_id`, would bind it.",
        "- §3.1 makes discovery platform-only and absent from most chains, while Appendix B's "
        "`ai_referral_agent_session` count includes it, so most honest chains of that type "
        "report `chain_complete: false`. Related: §5 tests `==` against counts §2.2 calls "
        "minimums (`notes/issues-draft.md` in aep-verify, Issue C).",
        "",
        "## Files",
        "",
        "| file | SHA-256 |",
        "|---|---|",
        *(f"| `{name}` | `{digest}` |" for name, digest in sorted(files.items())),
        "",
        "Verify any of them yourself:",
        "",
        "```",
        "aep-verify bundle bundles/honest.json --key merchant-public-key.txt",
        "aep-verify bundle attacks/upgrade-3ds.json --key merchant-public-key.txt",
        "aep-verify bundle attacks/upgrade-3ds.json --key merchant-public-key.txt \\",
        f"  --anchored-seal {run.anchored_seal}",
        "aep-verify bundle attacks/hide-return.json --key merchant-public-key.txt \\",
        "  --anchored-heads anchored-heads/returned.txt",
        "```",
        "",
    ]
    return "\n".join(lines)


def _results_json(run: DemoRun) -> dict[str, Any]:
    def observed(o: Observation) -> dict[str, Any]:
        return {
            "outcome": o.outcome,
            "evidence": o.evidence,
            "exportable": o.exportable,
            "chain_complete": o.chain_complete,
        }

    return {
        "verifier": VERIFIER_ID,
        "spec_version": SPEC_VERSION,
        "anchored_seal": run.anchored_seal,
        "seals": dict(run.seals),
        "heads": {name: list(log) for name, log in run.heads.items()},
        "honest": {name: outcome.to_dict() for name, outcome in run.honest.items()},
        "attacks": [
            {
                "id": r.attack.id,
                "actor": r.attack.actor,
                "variant": r.attack.variant,
                "title": r.attack.title,
                "note": r.attack.note,
                "expected": r.attack.expected,
                "expected_anchored": r.attack.expected_anchored,
                "expected_logged": r.attack.expected_logged,
                "key_only": observed(r.plain),
                "key_and_anchored_seal": observed(r.anchored),
                "key_and_head_log": observed(r.logged),
                "identical_to": (
                    f"bundles/{twin}.json" if (twin := run.identical_honest(r)) else None
                ),
                "as_expected": r.as_expected,
            }
            for r in run.results
        ],
    }


def write_demo(out_dir: Path, run: DemoRun | None = None) -> DemoRun:
    """Write bundles, attacks, seal and head logs, the key, results.json and REPORT.md."""
    run = run or run_demo()
    out_dir.mkdir(parents=True, exist_ok=True)
    outputs: dict[str, bytes] = {
        "merchant-public-key.txt": (
            public_key_to_base64(MERCHANT_KEY.public_key()) + "\n"
        ).encode(),
        "anchored-seal.txt": (run.anchored_seal + "\n").encode(),
    }
    for name, bundle in run.bundles.items():
        outputs[f"bundles/{name}.json"] = _json_bytes(bundle)
        outputs[f"anchored-heads/{name}.txt"] = ("\n".join(run.heads[name]) + "\n").encode()
    for r in run.results:
        outputs[f"attacks/{r.attack.id}.json"] = _json_bytes(r.bundle)
    outputs["results.json"] = _json_bytes(_results_json(run))
    digests = {name: hashlib.sha256(data).hexdigest() for name, data in outputs.items()}
    outputs["REPORT.md"] = render_report(run, digests).encode("utf-8")
    for name, data in outputs.items():
        target = out_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return run
