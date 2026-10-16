"""Values a DisputeBundle wrapper restates from its chain, derived one way for both halves.

The exporter (`produce.export_dispute_bundle`) derives these to write the §6.1 wrapper, and
the verifier (`bundle.verify_bundle`) derives them again to check it. Keeping the derivation in
one place means the two can never disagree about what a correct wrapper says.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any, TypeGuard

# ISO 4217 minor-unit exponents for the currencies this package will format or check. A
# currency outside the table is never guessed: the exporter leaves totalValue null (§6.1 allows
# it) and the verifier says it could not check, rather than assuming two decimal places.
MINOR_UNITS: dict[str, int] = {
    "USD": 2, "EUR": 2, "GBP": 2, "CAD": 2, "AUD": 2, "NZD": 2, "CHF": 2, "SEK": 2, "NOK": 2,
    "DKK": 2, "PLN": 2, "CZK": 2, "HUF": 2, "SGD": 2, "HKD": 2, "CNY": 2, "INR": 2, "BRL": 2,
    "MXN": 2, "ZAR": 2, "AED": 2, "SAR": 2, "ILS": 2, "TRY": 2, "THB": 2, "MYR": 2, "PHP": 2,
    "IDR": 2, "JPY": 0, "KRW": 0, "VND": 0, "CLP": 0, "ISK": 0, "UGX": 0, "XOF": 0, "XAF": 0,
    "BHD": 3, "KWD": 3, "JOD": 3, "OMR": 3, "TND": 3,
}  # fmt: skip


def _is_int(value: Any) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def minor_unit_exponent(currency: Any) -> int | None:
    return MINOR_UNITS.get(currency) if isinstance(currency, str) else None


def format_minor_units(amount: Any, currency: Any) -> str | None:
    """5500 USD -> '55.00'; 5500 JPY -> '5500'. None when the exponent is unknown."""
    exponent = minor_unit_exponent(currency)
    if exponent is None or not _is_int(amount):
        return None
    if exponent == 0:
        return str(amount)
    return f"{Decimal(amount).scaleb(-exponent):.{exponent}f}"


def major_to_minor(value: Any, currency: Any) -> int | None:
    """'55.00' USD -> 5500. None when the value is not an exact decimal string in that currency.

    Exactness matters: '55.001' USD is not 5500 or 5501, it is a wrapper that does not describe
    a real charge, and it is reported as such rather than rounded into agreement.
    """
    exponent = minor_unit_exponent(currency)
    if exponent is None or not isinstance(value, str):
        return None
    try:
        amount = Decimal(value)
    except InvalidOperation:
        return None
    if not amount.is_finite():
        return None
    scaled = amount.scaleb(exponent)
    if scaled != scaled.to_integral_value():
        return None
    return int(scaled)


def interaction_channel_of(records: list[Any]) -> str | None:
    """The transaction-level channel implied by the channels its artifacts carry (§2.4)."""
    seen: set[str] = set()
    for record in records:
        hash_input = record.get("hash_input") if isinstance(record, dict) else None
        source = hash_input if isinstance(hash_input, dict) else record
        channel = source.get("interaction_channel") if isinstance(source, dict) else None
        if isinstance(channel, str):
            seen.add(channel)
    if not seen:
        return None
    if seen == {"voice"}:
        return "voice"
    if seen == {"text_chat"}:
        return "text_chat"
    return "voice_and_text"
