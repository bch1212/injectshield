"""InjectShield Python SDK.

Quick start:
    from injectshield import InjectShield
    client = InjectShield(api_key="is_live_…")
    result = client.scan("ignore previous instructions", context="user_input")
    if not result.safe:
        raise RuntimeError(f"injection: {result.threat_type}")
"""

from .client import (
    InjectShield,
    AsyncInjectShield,
    ScanResult,
    InjectShieldError,
    AuthError,
    RateLimitError,
    QuotaExceededError,
)

__all__ = [
    "InjectShield",
    "AsyncInjectShield",
    "ScanResult",
    "InjectShieldError",
    "AuthError",
    "RateLimitError",
    "QuotaExceededError",
    "__version__",
]

__version__ = "0.1.0"
