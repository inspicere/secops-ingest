"""A secret value that cannot be printed by accident.

The provider contract in base.py forbids logging a value or putting one in an
exception message. That is a rule people follow until they are debugging, at
which point `print(creds)` is the obvious move. This type makes the obvious
move safe.

It also registers itself for redaction on construction. Before this, every
connector called register_secret() by hand -- sources/_cortex.py:99,
sources/wazuh.py:85, sources/defectdojo.py:135 -- which works until someone
writes a pack and does not know the convention exists. Registration belongs at
the boundary where a value is resolved, not at each of its call sites.
"""

from __future__ import annotations

from typing import NoReturn

from ..redaction import register_secret

#: Shown instead of the value. Deliberately not the redaction placeholder:
#: this one marks "a Secret object was formatted", which is a code smell worth
#: seeing in a log, whereas redaction.PLACEHOLDER marks "a leaked value was
#: scrubbed", which is a near-miss worth distinguishing from it.
MASK = "<secret>"


class Secret:
    """A string value that hides itself unless explicitly revealed."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError(f"Secret requires a str, got {type(value).__name__}")
        self._value = value
        # Registration is best-effort by design: redaction.register_secret
        # ignores values under MIN_LENGTH because a 3-character secret would
        # match unrelated text everywhere and make logs unreadable.
        register_secret(value)

    def reveal(self) -> str:
        """Return the underlying value. The only way to get at it."""
        return self._value

    def __len__(self) -> int:
        # Exposed on purpose: verifying a credential landed by comparing
        # lengths rather than values is the house pattern.
        return len(self._value)

    def __str__(self) -> str:
        return MASK

    def __repr__(self) -> str:
        return f"Secret({MASK}, len={len(self._value)})"

    def __format__(self, format_spec: str) -> str:
        # Without this, f"{s:>20}" would raise TypeError from object.__format__
        # (it accepts only an empty spec there). With it, the spec applies to
        # the mask, so the padding works and the value stays hidden.
        return format(MASK, format_spec)

    def __reduce__(self) -> NoReturn:
        # pickle serialises __slots__ state, which would write the plaintext to
        # whatever receives the bytes. Refuse instead. The message names the
        # reason, never the value.
        raise TypeError(
            "Secret cannot be pickled: a pickle is written to disk or sent to "
            "another process, and either would expose the value"
        )

    def __copy__(self) -> Secret:
        # copy.copy would otherwise fall back to __reduce__ and hit the refusal
        # above. Copying stays in-process, so it is safe to allow.
        return Secret(self._value)

    def __deepcopy__(self, memo: dict[int, object]) -> Secret:
        # Same reasoning as __copy__: deepcopy falls back to __reduce__ too.
        # The value is a str, so there is nothing further to copy.
        return Secret(self._value)

    def __eq__(self, other: object) -> bool:
        # Only against another Secret. Comparing to a bare str is almost
        # always a sign that a value escaped the wrapper somewhere.
        if not isinstance(other, Secret):
            return NotImplemented
        return self._value == other._value

    def __hash__(self) -> int:
        return hash(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)
