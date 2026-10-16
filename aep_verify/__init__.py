"""aep-verify: an independent verifier, and a conformant producer, for AEP v1.0.3-rc.2 evidence."""

from .bundle import BundleVerification, verify_bundle
from .canonical import CanonicalizationError, canonicalize, parse_json, sha256_of
from .chain import (
    ArtifactRecord,
    ChainFormatError,
    VerificationResult,
    compute_hash,
    expected_artifact_count,
    verify_chain,
)
from .keys import private_key_from_seed_base64, public_key_from_base64
from .produce import ChainBuilder, ExportRefused, ProducerError, export_dispute_bundle

__version__ = "0.2.0"

__all__ = [
    "ArtifactRecord",
    "BundleVerification",
    "CanonicalizationError",
    "ChainBuilder",
    "ChainFormatError",
    "ExportRefused",
    "ProducerError",
    "VerificationResult",
    "__version__",
    "canonicalize",
    "compute_hash",
    "expected_artifact_count",
    "export_dispute_bundle",
    "parse_json",
    "private_key_from_seed_base64",
    "public_key_from_base64",
    "sha256_of",
    "verify_bundle",
    "verify_chain",
]
