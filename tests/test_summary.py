import pytest

from aep_verify.summary import (
    format_minor_units,
    interaction_channel_of,
    major_to_minor,
    minor_unit_exponent,
)


@pytest.mark.parametrize(
    "amount, currency, expected",
    [
        (5500, "USD", "55.00"),
        (5, "USD", "0.05"),
        (0, "EUR", "0.00"),
        (5500, "JPY", "5500"),
        (5500, "BHD", "5.500"),
        (-5, "USD", "-0.05"),
        (5500, "XYZ", None),  # never guess an exponent
        (5500, None, None),
        (True, "USD", None),  # bool is not an amount
        (55.0, "USD", None),  # minor units are integers
    ],
)
def test_format_minor_units(amount, currency, expected):
    assert format_minor_units(amount, currency) == expected


@pytest.mark.parametrize(
    "value, currency, expected",
    [
        ("55.00", "USD", 5500),
        ("55", "USD", 5500),
        ("55.5", "USD", 5550),
        ("5500", "JPY", 5500),
        ("5.500", "BHD", 5500),
        ("55.001", "USD", None),  # not an exact USD amount: reported, never rounded
        ("55.5", "JPY", None),
        ("NaN", "USD", None),
        ("Infinity", "USD", None),
        ("fifty", "USD", None),
        (55.0, "USD", None),  # §6.1 types totalValue as a string
        ("55.00", "XYZ", None),
    ],
)
def test_major_to_minor(value, currency, expected):
    assert major_to_minor(value, currency) == expected


def test_round_trip_for_every_known_currency():
    from aep_verify.summary import MINOR_UNITS

    for currency in MINOR_UNITS:
        for amount in (0, 1, 99, 5500, 123456789):
            assert major_to_minor(format_minor_units(amount, currency), currency) == amount


def test_minor_unit_exponent_rejects_non_strings():
    assert minor_unit_exponent(["USD"]) is None and minor_unit_exponent("USD") == 2


@pytest.mark.parametrize(
    "channels, expected",
    [
        ([], None),
        ([None, None], None),
        (["voice", None], "voice"),
        (["text_chat", "text_chat"], "text_chat"),
        (["voice", "text_chat"], "voice_and_text"),
        (["voice_and_text"], "voice_and_text"),
    ],
)
def test_interaction_channel_of(channels, expected):
    nested = [{"hash_input": {"interaction_channel": c}} for c in channels]
    flat = [{"interaction_channel": c} for c in channels]
    assert interaction_channel_of(nested) == expected
    assert interaction_channel_of(flat) == expected


def test_interaction_channel_of_ignores_junk():
    assert interaction_channel_of(["x", 3, {"hash_input": "y"}, {"interaction_channel": 7}]) is None
