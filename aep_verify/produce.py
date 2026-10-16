"""Evidence production: build a conformant AEP v1.0.3-rc.2 chain and export a §6.1 DisputeBundle.

The rest of this package checks evidence. This module creates it, and holds itself to
the same text: a producer that can emit something the verifier would reject is a producer
that will, one day, in a dispute. Every rule enforced here cites the section it comes from;
where this module is stricter than the text, the docstring of the check says so.

Scope, deliberately narrow:

* GENERIC chains only. A delegation artifact carries protocol envelopes (AP2 mandates, TAP
  signatures, x402 payloads) signed by third parties with keys this module does not hold,
  and §2.6 requires a chain with no agentic protocol in play to omit delegation entirely.
  So `append("delegation", ...)` is refused rather than faked.
* One merchant server key signs every artifact wrapper (§4.3 `server_signature`).
* Chain-level fields (§2.7: chain_id, merchant_id, session_id_hash, spec_version) are carried
  inside the hashed `metadata`, as the published vectors do and as the comment-round
  disposition of upstream issue #3 makes normative for v1.0.3-final.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, TypeGuard

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import CanonicalizationError, canonicalize
from .chain import (
    ARTIFACT_TYPES,
    INTERACTION_CHANNELS,
    PERMITTED_ACTORS,
    POST_SEAL_TYPES,
    PRE_SEAL_ORDER,
    SPEC_VERSION,
    TIMESTAMP_RE,
    TRANSACTION_TYPES,
    TYPE_LAYERS,
    VERIFIER_ID,
    compute_hash,
    show,
    sign_hash,
    verify_chain,
)
from .summary import format_minor_units, interaction_channel_of, minor_unit_exponent

__all__ = [
    "ChainBuilder",
    "ExportRefused",
    "ProducerError",
    "export_dispute_bundle",
    "format_minor_units",
    "hmac_ref",
    "idempotency_fallback",
    "minor_unit_exponent",
    "signing_key_id",
]


class ProducerError(ValueError):
    """The requested artifact would not be conformant, so it is not produced."""


class ExportRefused(RuntimeError):
    """§6.2: a bundle whose re-verification fails MUST NOT be exported for submission."""

    def __init__(self, message: str, errors: list[str]) -> None:
        super().__init__(message)
        self.errors = errors


# ---------------------------------------------------------------------------------------------
# References: pseudonyms, idempotency keys, key ids, money
# ---------------------------------------------------------------------------------------------


def hmac_ref(salt: bytes, message: str) -> str:
    """The §2.7 construction: 'sha256:' + lowercase hex of HMAC-SHA256(salt, utf8(message)).

    Used for session_id_hash, consumer_ip_hash, user_agent_hash and the address hashes. §3.5's
    prose sketches addresses as sha256(address + salt); the keyed §2.7 construction is used
    for them too, so every pseudonym in a chain is built the same way. Only equality between
    the cart's and the fulfillment's address hash matters to verification (§3.7), and that
    holds under either construction as long as one is used consistently.
    """
    if not isinstance(salt, bytes) or len(salt) < 16:
        raise ProducerError("HMAC salt must be at least 16 bytes (a per-merchant secret, §2.7)")
    return "sha256:" + hmac.new(salt, message.encode("utf-8"), hashlib.sha256).hexdigest()


def idempotency_fallback(transaction_id: str, artifact_type: str, actor_id: str, ts: str) -> str:
    """§8.4 wall-clock fallback: SHA256(transaction_id:artifact_type:actor_id:floor(ms/60000)).

    §8.4 prefers an event-native identifier (PSP event ID, carrier event ID, jti/nonce) and
    calls this a fallback. The text fixes the input, not the output encoding; lowercase hex
    is used here.
    """
    moment = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    window = int(moment.timestamp() * 1000) // 60000
    material = f"{transaction_id}:{artifact_type}:{actor_id}:{window}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def signing_key_id(public_key: Ed25519PublicKey) -> str:
    """A stable key_id for the §4.3 published key: 'ed25519:' + 16 hex of SHA-256(raw key)."""
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]


# ---------------------------------------------------------------------------------------------
# Payload rules (§3.1-§3.7, §3.10)
# ---------------------------------------------------------------------------------------------

# Fields the section marks "(required)". Conditional requirements are checked separately.
REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "discovery": (
        "platform", "attribution_method", "attribution_confidence", "product_url_cited",
        "captured_at", "idempotency_key",
    ),
    "referral": (
        "referral_event_id", "consumer_ip_hash", "consumer_ip_country", "user_agent_hash",
        "consent_gpc", "consent_cookie", "captured_at", "idempotency_key",
    ),
    "intent": (
        "intent_id", "product_id", "product_name", "quantity", "unit_price", "currency",
        "price_displayed_at", "captured_at", "idempotency_key",
    ),
    "policy": (
        "decision_id", "policy_engine_vendor", "policy_version", "outcome", "escalated",
        "risk_score", "rules_triggered", "evaluated_at", "captured_at", "idempotency_key",
    ),
    "cart": (
        "cart_id", "confirmed", "items", "subtotal", "shipping", "tax", "discounts", "total",
        "currency", "shipping_address_hash", "billing_address_hash", "payment_method_token",
        "cart_confirmed_at", "captured_at", "idempotency_key",
    ),
    "authorization": (
        "psp", "charge_id", "payment_method_token", "payment_method_type", "result", "amount",
        "currency", "authorized_at", "settlement_rail", "captured_at", "idempotency_key",
    ),
    "fulfillment": (
        "fulfillment_id", "platform_order_id", "carrier", "tracking_number", "status",
        "delivery_address_hash", "delivery_address_match", "captured_at", "idempotency_key",
    ),
    "refund": (
        "refund_id", "charge_ref", "amount", "currency", "reason", "processed_at",
        "refund_method", "captured_at", "idempotency_key",
    ),
}  # fmt: skip

# §3.6: the card-representment set. MUST be present when settlement_rail is 'card' (null where
# the PSP omits a value, "rather than missing"); MUST be null, not omitted, on non-card rails.
CARD_FIELDS: tuple[str, ...] = (
    "network_transaction_id", "card_brand", "card_last4", "card_funding", "card_country",
    "avs_result", "cvv_result", "three_ds_result", "three_ds_version", "fraud_score",
    "fraud_engine",
)  # fmt: skip
CARD_NON_NULL: tuple[str, ...] = (
    "network_transaction_id", "card_brand", "card_last4", "avs_result", "cvv_result",
    "three_ds_result",
)  # fmt: skip

ENUMS: dict[tuple[str, str], frozenset[str]] = {
    ("discovery", "platform"): frozenset({"chatgpt", "gemini", "perplexity", "copilot", "meta"}),
    ("discovery", "attribution_method"): frozenset(
        {"url_params", "merchant_tracked_link", "referrer_header", "behavioral_heuristic"}
    ),
    ("discovery", "attribution_confidence"): frozenset({"high", "medium", "low"}),
    ("referral", "consent_cookie"): frozenset({"granted", "denied", "unset"}),
    ("policy", "outcome"): frozenset({"approved", "blocked", "escalated"}),
    ("authorization", "payment_method_type"): frozenset(
        {
            "card",
            "apple_pay",
            "google_pay",
            "klarna",
            "affirm",
            "afterpay",
            "ach",
            "sepa",
            "wallet_other",
        }  # fmt: skip
    ),
    ("authorization", "result"): frozenset({"approved", "declined", "review"}),
    ("authorization", "settlement_rail"): frozenset(
        {"card", "stablecoin", "account", "real_time_rails"}
    ),
    ("authorization", "card_brand"): frozenset(
        {"visa", "mastercard", "amex", "discover", "jcb", "unionpay"}
    ),
    ("authorization", "card_funding"): frozenset({"credit", "debit", "prepaid", "unknown"}),
    ("authorization", "avs_result"): frozenset({"Y", "A", "N", "U", "R", "S", "Z", "W"}),
    ("authorization", "cvv_result"): frozenset({"M", "N", "U", "P", "S"}),
    ("authorization", "three_ds_result"): frozenset(
        {
            "authenticated",
            "attempted",
            "frictionless",
            "failed",
            "not_supported",
            "not_applicable",
        }  # fmt: skip
    ),
    ("fulfillment", "status"): frozenset(
        {"pending", "in_transit", "delivered", "failed", "returned"}
    ),
    ("refund", "reason"): frozenset(
        {"customer_request", "dispute_resolution", "goodwill", "error_correction", "other"}
    ),
}

# §3.1: attribution_confidence is deterministic by attribution_method.
_CONFIDENCE_BY_METHOD = {
    "url_params": "high",
    "merchant_tracked_link": "high",
    "referrer_header": "medium",
    "behavioral_heuristic": "low",
}

# Payload fields that hold ISO 8601 UTC instants and must parse as such.
_INSTANT_FIELDS = (
    "captured_at", "price_displayed_at", "evaluated_at", "cart_confirmed_at", "authorized_at",
    "shipped_at", "delivered_at", "processed_at",
)  # fmt: skip

_HASH_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_FORBIDDEN_KEYS = ("session_token", "pan", "card_number", "cvv", "cvc", "track_data")
# A run of 13-19 digits, optionally grouped by single spaces or hyphens, as a PAN is printed.
_PAN_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")


def _is_int(value: Any) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _walk_strings(value: Any, path: str) -> Iterator[tuple[str, str]]:
    """Every string, and every integer as its decimal text: §8.3 scans the serialized payload."""
    if isinstance(value, str):
        yield path, value
    elif _is_int(value):
        yield path, str(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _walk_strings(item, f"{path}.{key}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from _walk_strings(item, f"{path}[{i}]")


def _walk_keys(value: Any, path: str) -> Iterator[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield f"{path}.{key}", key
            yield from _walk_keys(item, f"{path}.{key}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from _walk_keys(item, f"{path}[{i}]")


def _parse_instant(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo is not None else None


def scan_for_secrets(payload: dict[str, Any], label: str, *, luhn: bool = True) -> list[str]:
    """§2.7 / §3.6 / §8.3: no PAN, CVV, track data or session token in a payload.

    Secret field names are refused in every payload (§2.7). The Luhn gate is the §8.3
    reference rule: every 13-19 digit run, optionally grouped by single spaces or hyphens,
    over strings and integers alike. §3.6 and §8.3 scope that gate to authorization payloads,
    and so does `check_payload`: a 15-digit FedEx tracking number passes Luhn one time in ten,
    and refusing a tenth of real deliveries is not a safety margin.
    """
    problems = []
    for path, key in _walk_keys(payload, label):
        if isinstance(key, str) and key.lower() in _FORBIDDEN_KEYS:
            problems.append(f"{path}: field name {show(key)} is a forbidden secret (§2.7, §3.6)")
    if not luhn:
        return problems
    for path, text in _walk_strings(payload, label):
        for match in _PAN_CANDIDATE.finditer(text):
            digits = re.sub(r"[ -]", "", match.group())
            if 13 <= len(digits) <= 19 and _luhn_ok(digits):
                problems.append(
                    f"{path}: contains a Luhn-valid {len(digits)}-digit sequence, i.e. a PAN "
                    "pattern; MUST be rejected at ingestion (§3.6, §8.3)"
                )
    return problems


def check_payload(artifact_type: str, payload: Any) -> list[str]:
    """Every per-artifact payload rule this module enforces. Empty list means conformant."""
    if not isinstance(payload, dict):
        return [f"{artifact_type} payload must be an object"]
    problems: list[str] = []
    label = f"{artifact_type}.payload"
    for name in REQUIRED_FIELDS.get(artifact_type, ()):
        if name not in payload:
            problems.append(f"{label}.{name} is required (§3)")
    for (kind, name), allowed in ENUMS.items():
        if kind == artifact_type and payload.get(name) is not None:
            if not (isinstance(payload[name], str) and payload[name] in allowed):
                problems.append(
                    f"{label}.{name}={show(payload[name])} is not one of {sorted(allowed)}"
                )
    for name in _INSTANT_FIELDS:
        if name in payload and payload[name] is not None and _parse_instant(payload[name]) is None:
            problems.append(f"{label}.{name}={show(payload[name])} is not an ISO 8601 UTC instant")
    for name in ("idempotency_key",):
        if name in payload and (not isinstance(payload[name], str) or not payload[name]):
            problems.append(f"{label}.{name} must be a non-empty string (§2.7, §8.4)")
    problems += scan_for_secrets(payload, label, luhn=artifact_type == "authorization")

    check = _TYPE_CHECKS.get(artifact_type)
    if check is not None:
        problems += check(payload, label)
    return problems


def _check_discovery(p: dict[str, Any], label: str) -> list[str]:
    method, confidence = p.get("attribution_method"), p.get("attribution_confidence")
    expected = _CONFIDENCE_BY_METHOD.get(method) if isinstance(method, str) else None
    if expected is not None and confidence != expected:
        return [
            f"{label}.attribution_confidence must be {show(expected)} for attribution_method "
            f"{show(method)} (§3.1: deterministic by method)"
        ]
    return []


def _check_referral(p: dict[str, Any], label: str) -> list[str]:
    out = []
    for name in ("consumer_ip_hash", "user_agent_hash"):
        if name in p and not (isinstance(p[name], str) and _HASH_REF_RE.match(p[name])):
            out.append(f"{label}.{name} must be a 'sha256:...' HMAC per §2.7")
    country = p.get("consumer_ip_country")
    if country is not None and not (
        isinstance(country, str) and re.fullmatch(r"[A-Z]{2}", country)
    ):
        out.append(f"{label}.consumer_ip_country must be ISO 3166-1 alpha-2")
    if "consent_gpc" in p and not isinstance(p["consent_gpc"], bool):
        out.append(f"{label}.consent_gpc must be a boolean (§3.2)")
    return out


def _check_intent(p: dict[str, Any], label: str) -> list[str]:
    out = []
    quantity = p.get("quantity")
    if "quantity" in p and not (_is_int(quantity) and quantity >= 1):
        out.append(f"{label}.quantity must be an integer >= 1 (§3.3)")
    if "unit_price" in p and not (_is_int(p["unit_price"]) and p["unit_price"] >= 0):
        out.append(f"{label}.unit_price must be non-negative integer minor units (§3.3)")
    return out


def _check_policy(p: dict[str, Any], label: str) -> list[str]:
    out = []
    score = p.get("risk_score")
    if "risk_score" in p and not (_is_int(score) and 0 <= score <= 100):
        out.append(f"{label}.risk_score must be an integer 0-100 (§3.4)")
    if "rules_triggered" in p and not isinstance(p["rules_triggered"], list):
        out.append(f"{label}.rules_triggered must be an array, possibly empty (§3.4)")
    if "escalated" in p and not isinstance(p["escalated"], bool):
        out.append(f"{label}.escalated must be a boolean (§3.4)")
    if p.get("outcome") in ("blocked", "escalated") and not p.get("reason"):
        out.append(f"{label}.reason is required when outcome is {show(p['outcome'])} (§3.4)")
    return out


def _check_cart(p: dict[str, Any], label: str) -> list[str]:
    out = []
    if "confirmed" in p and p["confirmed"] is not True:
        out.append(f"{label}.confirmed MUST be true (§3.5)")
    money = ("subtotal", "shipping", "tax", "discounts", "total")
    bad = [k for k in money if k in p and not _is_int(p[k])]
    if bad:
        out.append(f"{label} fields {bad} must be integer minor units (§3.5)")
    elif all(k in p for k in money):
        if p["discounts"] < 0:
            out.append(f"{label}.discounts must be non-negative (§3.5)")
        if p["subtotal"] + p["shipping"] + p["tax"] - p["discounts"] != p["total"]:
            out.append(f"{label}: subtotal + shipping + tax - discounts != total (§3.5 MUST-1)")
    items = p.get("items")
    if "items" in p:
        if not isinstance(items, list) or not items:
            out.append(f"{label}.items must be a non-empty array (§3.5)")
        else:
            line_total = 0
            for i, item in enumerate(items):
                if not isinstance(item, dict):
                    out.append(f"{label}.items[{i}] must be an object")
                    continue
                for key in ("product_id", "product_name", "quantity", "unit_price"):
                    if key not in item:
                        out.append(f"{label}.items[{i}].{key} is required (§3.5)")
                q, u = item.get("quantity"), item.get("unit_price")
                if not (_is_int(q) and q >= 1) or not (_is_int(u) and u >= 0):
                    out.append(f"{label}.items[{i}] quantity/unit_price must be integers (§3.5)")
                else:
                    line_total += q * u
            # Stricter than the text, which never states it: a subtotal that is not the sum of
            # its lines is a cart a reviewer cannot reconcile, so it is not produced.
            if not out and _is_int(p.get("subtotal")) and line_total != p["subtotal"]:
                out.append(f"{label}.subtotal {p['subtotal']} != sum of lines {line_total}")
    for name in ("shipping_address_hash", "billing_address_hash"):
        if name in p and not (isinstance(p[name], str) and _HASH_REF_RE.match(p[name])):
            out.append(f"{label}.{name} must be 'sha256:...' (addresses are hashed, §3.5)")
    return out


def _check_authorization(p: dict[str, Any], label: str) -> list[str]:
    out = []
    if "amount" in p and not _is_int(p["amount"]):
        out.append(f"{label}.amount must be integer minor units (§3.6)")
    if p.get("result") == "approved" and not p.get("auth_code"):
        out.append(f"{label}.auth_code is required when result is 'approved' (§3.6)")
    rail = p.get("settlement_rail")
    if rail == "card":
        missing = [f for f in CARD_FIELDS if f not in p]
        if missing:
            out.append(
                f"{label} card rail: {missing} must be present, null where the PSP omits them "
                "(§3.6 representment set)"
            )
        empty = [f for f in CARD_NON_NULL if f in p and p[f] is None]
        if empty:
            out.append(f"{label} card rail: {empty} cannot be null for a card authorization (§3.6)")
        if p.get("three_ds_result") not in (None, "not_applicable") and not p.get(
            "three_ds_version"
        ):
            out.append(f"{label}.three_ds_version is required when 3DS applied (§3.6)")
        last4 = p.get("card_last4")
        if last4 is not None and not (isinstance(last4, str) and re.fullmatch(r"\d{4}", last4)):
            out.append(f"{label}.card_last4 must be exactly four digits (§3.6)")
        if p.get("stablecoin") is not None:
            out.append(f"{label}.stablecoin must be null on the card rail (§3.6)")
        if "stablecoin" not in p:
            out.append(f"{label}.stablecoin must be present (null) on the card rail (§3.6)")
    elif rail is not None:
        not_null = [f for f in CARD_FIELDS if p.get(f) is not None]
        if not_null and rail == "stablecoin":
            out.append(f"{label}: card fields {not_null} must be null off the card rail (§3.6)")
        absent = [f for f in CARD_FIELDS if f not in p]
        if absent:
            out.append(f"{label}: {absent} must be set to null, not omitted (§3.6)")
        if rail == "stablecoin" and not isinstance(p.get("stablecoin"), dict):
            out.append(f"{label}.stablecoin object is REQUIRED on the stablecoin rail (§3.6)")
    return out


def _check_fulfillment(p: dict[str, Any], label: str) -> list[str]:
    out = []
    status = p.get("status")
    if status in ("in_transit", "delivered") and not p.get("shipped_at"):
        out.append(f"{label}.shipped_at is required when status is {show(status)} (§3.7)")
    if status == "delivered" and not p.get("delivered_at"):
        out.append(f"{label}.delivered_at is required when status is 'delivered' (§3.7)")
    if "delivery_address_match" in p and not isinstance(p["delivery_address_match"], bool):
        out.append(f"{label}.delivery_address_match must be a boolean (§3.7)")
    shipped, delivered = _parse_instant(p.get("shipped_at")), _parse_instant(p.get("delivered_at"))
    if shipped and delivered and delivered < shipped:
        out.append(f"{label}: delivered_at precedes shipped_at")
    return out


def _check_refund(p: dict[str, Any], label: str) -> list[str]:
    if "amount" in p and not (_is_int(p["amount"]) and p["amount"] > 0):
        return [f"{label}.amount must be positive integer minor units (§3.10)"]
    return []


_TYPE_CHECKS = {
    "discovery": _check_discovery,
    "referral": _check_referral,
    "intent": _check_intent,
    "policy": _check_policy,
    "cart": _check_cart,
    "authorization": _check_authorization,
    "fulfillment": _check_fulfillment,
    "refund": _check_refund,
}


# ---------------------------------------------------------------------------------------------
# The chain builder
# ---------------------------------------------------------------------------------------------


@dataclass
class ChainBuilder:
    """Appends signed artifacts to one transaction chain, refusing anything non-conformant.

    Every append is validated against the artifact's own section and against the chain so far
    (order, seal, cross-artifact invariants) before it is hashed and signed, so a chain this
    builder emits always verifies under `verify_chain`. Appends are idempotent on the payload's
    idempotency_key (§8.4): repeating an identical event returns the existing record; reusing a
    key for different content is refused.
    """

    transaction_type: str
    chain_id: str
    merchant_id: str
    session_id_hash: str
    signing_key: Ed25519PrivateKey = field(repr=False)
    spec_version: str = SPEC_VERSION
    sdk_version: str = VERIFIER_ID
    _records: list[dict[str, Any]] = field(default_factory=list, init=False, repr=False)
    _keys: dict[str, int] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.transaction_type not in TRANSACTION_TYPES:
            raise ProducerError(f"unknown transaction_type {show(self.transaction_type)} (§2.2)")
        if self.spec_version != SPEC_VERSION:
            raise ProducerError(f"this producer emits {SPEC_VERSION} only (§0.1, §2.7)")
        for name in ("chain_id", "merchant_id"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise ProducerError(f"{name} must be a non-empty string (§2.7)")
        if not _HASH_REF_RE.match(self.session_id_hash or ""):
            raise ProducerError("session_id_hash must be 'sha256:...' per the §2.7 HMAC")

    # -- state ---------------------------------------------------------------------------------

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.signing_key.public_key()

    @property
    def records(self) -> list[dict[str, Any]]:
        """A deep copy: callers can mutate it (tamper tests do) without touching the chain."""
        return copy.deepcopy(self._records)

    @property
    def head_hash(self) -> str | None:
        return self._records[-1]["current_hash"] if self._records else None

    @property
    def sealed_bundle_hash(self) -> str | None:
        """§2.5: the authorization artifact's current_hash, once it exists."""
        auth = self._first("authorization")
        return auth["current_hash"] if auth else None

    def _first(self, kind: str) -> dict[str, Any] | None:
        return next((r for r in self._records if r["artifact_type"] == kind), None)

    def _payloads(self, kind: str) -> list[dict[str, Any]]:
        return [r["hash_input"]["payload"] for r in self._records if r["artifact_type"] == kind]

    def metadata(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "merchant_id": self.merchant_id,
            "session_id_hash": self.session_id_hash,
            "spec_version": self.spec_version,
            "protocol": "GENERIC",
            "sdk_version": self.sdk_version,
            "signing_key_id": signing_key_id(self.public_key),
        }

    # -- append --------------------------------------------------------------------------------

    def append(
        self,
        artifact_type: str,
        *,
        actor_type: str,
        actor_id: str,
        payload: dict[str, Any],
        timestamp: str,
        interaction_channel: str | None = None,
    ) -> dict[str, Any]:
        """Validate, hash, sign and append one artifact. Returns a copy of the stored record."""
        if artifact_type == "delegation":
            raise ProducerError(
                "delegation is not produced: its protocol envelopes are signed by third parties "
                "with keys this producer does not hold, and a GENERIC chain MUST omit it (§2.6)"
            )
        if not (isinstance(artifact_type, str) and artifact_type in ARTIFACT_TYPES):
            raise ProducerError(f"unknown artifact_type {show(artifact_type)} (Appendix B)")
        if not isinstance(payload, dict):
            raise ProducerError(f"{artifact_type} payload must be an object")
        payload = copy.deepcopy(payload)

        key = payload.get("idempotency_key")
        if isinstance(key, str) and key in self._keys:
            existing = self._records[self._keys[key]]
            same = (
                existing["artifact_type"] == artifact_type
                and existing["hash_input"]["payload"] == payload
                and existing["hash_input"]["actor_id"] == actor_id
            )
            if same:
                return copy.deepcopy(existing)
            raise ProducerError(
                f"idempotency_key {show(key)} already identifies a different event (§8.4)"
            )

        problems = self._chain_problems(artifact_type, actor_type, actor_id, payload, timestamp)
        problems += check_payload(artifact_type, payload)
        if interaction_channel is not None and not (
            isinstance(interaction_channel, str) and interaction_channel in INTERACTION_CHANNELS
        ):
            problems.append(f"interaction_channel {show(interaction_channel)} is not a §2.4 value")
        # §2.4: "null for non-agent actors (psp, fulfillment_provider, direct_web layers)".
        # Vector (b) reads the parenthetical as the whole list and sets a channel on user
        # artifacts; this producer emits only what both readings accept.
        if interaction_channel is not None and actor_type != "agent":
            problems.append(f"interaction_channel must be null for actor {show(actor_type)} (§2.4)")
        if interaction_channel is not None and self.transaction_type == "direct_web":
            problems.append("interaction_channel must be null in a direct_web chain (§2.4)")
        if problems:
            raise ProducerError(f"{artifact_type} not produced:\n  - " + "\n  - ".join(problems))

        hash_input = {
            "actor_id": actor_id,
            "actor_type": actor_type,
            "artifact_type": artifact_type,
            "interaction_channel": interaction_channel,
            "metadata": self.metadata(),
            "payload": payload,
            "previous_hash": self.head_hash,
            "timestamp": timestamp,
        }
        try:
            current = compute_hash(hash_input)
        except CanonicalizationError as exc:
            raise ProducerError(
                f"{artifact_type} not produced: no §4.1 canonical form: {exc}"
            ) from exc
        record = {
            "sequence_number": len(self._records) + 1,
            "artifact_type": artifact_type,
            "hash_input": hash_input,
            "canonical_json": canonicalize(hash_input).decode("utf-8"),
            "current_hash": current,
            "server_signature": sign_hash(self.signing_key, current),
        }
        self._records.append(record)
        if isinstance(key, str):
            self._keys[key] = len(self._records) - 1
        return copy.deepcopy(record)

    def _chain_problems(
        self,
        artifact_type: str,
        actor_type: str,
        actor_id: str,
        payload: dict[str, Any],
        timestamp: str,
    ) -> list[str]:
        problems: list[str] = []
        if not (
            isinstance(actor_type, str)
            and actor_type in PERMITTED_ACTORS.get(artifact_type, frozenset())
        ):
            problems.append(
                f"actor_type {show(actor_type)} is not permitted for {artifact_type} (§3.8)"
            )
        if not isinstance(actor_id, str) or not actor_id:
            problems.append("actor_id must be a non-empty string")
        if not isinstance(timestamp, str) or not TIMESTAMP_RE.match(timestamp):
            problems.append(
                f"timestamp {show(timestamp)} must be RFC 3339 UTC whole seconds (§4.1)"
            )

        sealed = self.sealed_bundle_hash is not None
        if artifact_type in PRE_SEAL_ORDER:
            if artifact_type not in TYPE_LAYERS[self.transaction_type]:
                problems.append(
                    f"{artifact_type} is not a layer of {self.transaction_type} (§2.2, §3.8)"
                )
            if sealed:
                problems.append(f"{artifact_type} cannot follow the authorization seal (§2.5)")
            present = [
                r["artifact_type"] for r in self._records if r["artifact_type"] in PRE_SEAL_ORDER
            ]
            if present and PRE_SEAL_ORDER.index(artifact_type) <= PRE_SEAL_ORDER.index(present[-1]):
                problems.append(f"{artifact_type} is out of order after {present[-1]} (§3.9.2)")
        elif artifact_type in POST_SEAL_TYPES and not sealed:
            problems.append(f"{artifact_type} is post-seal; no authorization precedes it (§2.5)")

        # Timestamps and captured_at never go backwards (§2.7 MUST for captured_at).
        if self._records:
            last = self._records[-1]["hash_input"]
            if isinstance(timestamp, str) and timestamp < last["timestamp"]:
                problems.append("timestamp precedes the previous artifact's")
            prev_cap = _parse_instant(last["payload"].get("captured_at"))
            cap = _parse_instant(payload.get("captured_at"))
            if prev_cap and cap and cap < prev_cap:
                problems.append(
                    "captured_at decreases; MUST be monotonically non-decreasing (§2.7)"
                )

        problems += self._cross_artifact(artifact_type, payload)
        return problems

    def _cross_artifact(self, artifact_type: str, payload: dict[str, Any]) -> list[str]:
        """Invariants that span artifacts; each names its section or says it is stricter."""
        problems: list[str] = []
        carts = self._payloads("cart")
        cart = carts[0] if carts else None
        auths = self._payloads("authorization")
        auth = auths[0] if auths else None

        if artifact_type == "authorization":
            policies = self._payloads("policy")
            if not policies:
                problems.append("MUST never authorize without a preceding policy artifact (§3.4)")
            elif policies[-1].get("outcome") == "blocked":
                problems.append("the policy outcome is 'blocked'; nothing may be authorized")
            if cart is None:
                problems.append("authorization needs the cart it settles (§3.6 MUST-1)")
            else:
                if payload.get("amount") != cart.get("total"):
                    problems.append("authorization.amount != cart.total (§3.6 MUST-1)")
                if payload.get("currency") != cart.get("currency"):
                    problems.append("authorization.currency != cart.currency (§3.6 MUST-1)")
                # Stricter than the text: the token authorized is the token the cart named.
                if payload.get("payment_method_token") != cart.get("payment_method_token"):
                    problems.append("authorization.payment_method_token != cart's token")
        if artifact_type == "cart":
            intents = self._payloads("intent")
            if intents and intents[-1].get("currency") != payload.get("currency"):
                problems.append("cart.currency differs from the intent's currency")
        if artifact_type == "fulfillment" and cart is not None:
            expected = payload.get("delivery_address_hash") == cart.get("shipping_address_hash")
            if payload.get("delivery_address_match") is not expected:
                problems.append(
                    "delivery_address_match MUST equal (delivery_address_hash == "
                    "cart.shipping_address_hash) (§3.7)"
                )
        if artifact_type == "refund":
            if auth is None or auth.get("result") != "approved":
                problems.append("a refund needs an approved authorization to refund (§3.10)")
            else:
                if payload.get("charge_ref") != auth.get("charge_id"):
                    problems.append("refund.charge_ref must be the §3.6 charge_id (§3.10)")
                if payload.get("currency") != auth.get("currency"):
                    problems.append("refund.currency must match the authorization's")
                refunded = sum(r.get("amount", 0) for r in self._payloads("refund"))
                if _is_int(payload.get("amount")) and refunded + payload["amount"] > auth.get(
                    "amount", 0
                ):
                    problems.append(
                        f"refunds would total {refunded + payload['amount']}, more than the "
                        f"{auth.get('amount')} authorized"
                    )
        return problems


# ---------------------------------------------------------------------------------------------
# Export (§6.1, §6.2)
# ---------------------------------------------------------------------------------------------


def export_dispute_bundle(
    records: list[dict[str, Any]],
    public_key: Ed25519PublicKey,
    *,
    transaction_id: str,
    transaction_type: str,
    status: str,
    merchant_name: str,
    exported_at: str,
    verified_at: str | None = None,
    for_submission: bool = True,
) -> dict[str, Any]:
    """Re-verify the chain in full and export it as a §6.1 DisputeBundle.

    §6.2: the chain is re-verified before export, failures are surfaced in the verification
    object, and a bundle whose verification is not valid is refused when `for_submission`
    (representment-bound) is set. Wrapper values that the chain determines (merchantId,
    sealedBundleHash, totalValue, currency, interactionChannel, createdAt, completedAt,
    evidenceTier) are derived from the chain rather than supplied, so the wrapper cannot
    contradict the evidence it summarizes. `customerHistory` is not produced: it is computed
    across chains and is not hash-chained (§6.1), so this exporter will not assert it.
    """
    ordered = sorted(copy.deepcopy(records), key=lambda r: r["sequence_number"])
    by_type: dict[str, dict[str, Any]] = {}
    for record in ordered:
        by_type.setdefault(record["artifact_type"], record)
    first_meta = ordered[0]["hash_input"].get("metadata") or {}
    merchant_id = first_meta.get("merchant_id")
    auth = by_type.get("authorization")
    sealed = auth["current_hash"] if auth else None

    result = verify_chain(
        ordered,
        public_key,
        transaction_type=transaction_type,
        sealed_bundle_hash=sealed,
        expected_merchant_id=merchant_id,
        verified_at=verified_at,
    )
    if for_submission and not result.valid:
        raise ExportRefused(
            "re-verification failed; §6.2 forbids exporting this bundle for submission",
            result.errors,
        )

    cart = by_type.get("cart")
    cart_payload = cart["hash_input"]["payload"] if cart else {}
    currency = cart_payload.get("currency")
    total = cart_payload.get("total")
    delivered = [
        r for r in ordered
        if r["artifact_type"] == "fulfillment"
        and r["hash_input"]["payload"].get("status") == "delivered"
    ]  # fmt: skip

    return {
        "transaction": {
            "id": transaction_id,
            "transactionType": transaction_type,
            "status": status,
            "interactionChannel": interaction_channel_of(ordered),
            "createdAt": ordered[0]["hash_input"]["timestamp"],
            "completedAt": delivered[-1]["hash_input"]["timestamp"] if delivered else None,
            "sealedBundleHash": sealed,
        },
        "verification": {
            "valid": result.valid,
            "hashChainIntact": result.hash_chain_intact,
            "signaturesValid": result.signatures_valid,
            "chainComplete": result.chain_complete,
            "artifactsVerified": result.artifacts_verified,
            "verifiedAt": result.verified_at,
            "verificationMode": "full",
            "errors": list(result.errors),
            "specVersion": result.spec_version,
            "evidenceTier": result.evidence_tier,
            "protocolEnvelopesVerified": list(result.protocol_envelopes_verified),
            "cartPaymentBindingVerified": result.cart_payment_binding_verified,
        },
        "artifacts": ordered,
        "merchantContext": {
            "merchantId": merchant_id,
            "merchantName": merchant_name,
            "totalValue": format_minor_units(total, currency) if _is_int(total) else None,
            "currency": currency,
        },
        "evidenceTier": result.evidence_tier,
        "protocolEnvelopesVerified": list(result.protocol_envelopes_verified),
        "customerHistory": None,
        "exportedAt": exported_at,
    }
