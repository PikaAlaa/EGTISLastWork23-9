"""Reviewed, offline provider release manifest. JSON has zero entries.

The separate schema and finite matcher digests deliberately make changes explicit.
To verify/open question: ownership of reviewed nonempty releases and shared-contact
delegation. No automatic update, research or external acquisition is supported.
"""
from app.core.provider_registry import ReleasePin

BUNDLED_PIN = ReleasePin(
    registry_version='empty-v1',
    registry_sha256='ae2c5050f0f22e9e6fcca7f1edba1805317de98513f97e86098d308369846130',
    schema_sha256='f7c491df4e0661e52137efcb8b07fa751d51a0880b0e8e14d457e11c2db9d0b5',
    matching_sha256='da1c03408d7b92c9432cfecd8f8afa5c21a6bbced3b646dd98c831efd9cfcbfb',
)
