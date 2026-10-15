"""Ed25519 key helpers (§4.3). Keys are 32 raw bytes, base64 (standard alphabet) at rest."""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class KeyFormatError(ValueError):
    """The key material is not 32 base64-encoded bytes."""


def _decode32(b64: str, what: str) -> bytes:
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise KeyFormatError(f"{what} is not valid base64") from exc
    if len(raw) != 32:
        raise KeyFormatError(f"{what} is {len(raw)} bytes; Ed25519 {what}s are 32")
    return raw


def public_key_from_base64(b64: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(_decode32(b64, "public key"))


def private_key_from_seed_base64(b64: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_decode32(b64, "seed"))


def public_key_to_base64(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def load_public_key(source: str) -> Ed25519PublicKey:
    """Accept a base64 string, or a path to keys.json / a file holding the base64 string."""
    path = Path(source)
    if path.is_file():
        text = path.read_text(encoding="utf-8").strip()
        if text.startswith("{"):
            data = json.loads(text)
            if "public_key_base64" not in data:
                raise KeyFormatError(f"{source} has no public_key_base64 member")
            return public_key_from_base64(data["public_key_base64"])
        return public_key_from_base64(text)
    return public_key_from_base64(source)
