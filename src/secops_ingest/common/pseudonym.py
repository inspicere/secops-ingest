"""Pseudonymous subject keys.

Cross-source correlation is deferred (spec §1), but the join key it needs cannot
be backfilled: vendor retention caps how far back records can be re-fetched, so
an identifier not captured now is permanently unavailable for the period before
it was. Connectors therefore emit a pseudonym rather than the identity itself.

    subject_key("Alice.Smith@example.com ", salt) -> "9f2b…"   (64 hex chars)

The key is HMAC-SHA256 keyed by the salt, not a hash of the identifier with the
salt appended. sha256(id + salt) is an ad hoc keyed hash whose strength rests
on how the two strings happen to be concatenated; HMAC is the standard keyed
construction, with a security argument behind it, and it says plainly that
the salt is a key. Changing the construction orphans every stored key exactly
as changing the salt does. It changed once, before any connector in this
package emitted a key; it must not change again.

**Pseudonymisation is not anonymisation.** A keyed hash of an email remains
personal data: it is stable, linkable across sources, and re-identifiable by
anyone holding the salt. It stays within the retention and legal-hold questions
in docs/architecture/retention-and-storage.md §2. What it buys is that no
address is stored in the warehouse, so nothing to leak in a dashboard, a
backup, or a seven-year archive.
"""

from __future__ import annotations

import hashlib
import hmac
import re

#: Minimum salt length. A short salt is brute-forceable against a known user
#: list: the identifier space is small and enumerable, so the salt is the only
#: thing preventing a dictionary attack over every employee address.
MIN_SALT_LENGTH = 32

_WHITESPACE = re.compile(r"\s+")


class SaltTooShort(ValueError):
    """The configured salt is too short to resist enumeration."""


def normalise(identifier: str) -> str:
    """Canonicalise an identifier so the same person hashes identically.

    The join is only as good as this: an address lowercased in one connector
    and not another produces two different keys for one person, and the
    correlation silently returns nothing rather than failing.
    """
    return _WHITESPACE.sub("", identifier).strip().lower()


def subject_key(identifier: str | None, salt: str) -> str | None:
    """Return a stable pseudonym for `identifier`, or None if absent.

    Args:
        identifier: an email address or UPN. See the module note on directories.
        salt: stable for the life of the platform. **Changing it invalidates
            every historical key** — new data would no longer join to old.
            Treat it like the Metabase encryption key: stored in the secret
            backend, backed up, never regenerated.
    """
    if not identifier or not identifier.strip():
        return None
    if len(salt) < MIN_SALT_LENGTH:
        raise SaltTooShort(
            f"join-key salt must be at least {MIN_SALT_LENGTH} characters; "
            "identifiers are enumerable, so a short salt offers no protection"
        )
    return hmac.new(
        salt.encode("utf-8"), normalise(identifier).encode("utf-8"), hashlib.sha256
    ).hexdigest()
