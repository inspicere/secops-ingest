# tests/secrets/test_secret_type.py
from __future__ import annotations

import logging

import pytest

from secops_ingest import redaction
from secops_ingest.secrets import Secret
from secops_ingest.secrets.base import SecretProvider


@pytest.fixture(autouse=True)
def _clear_registry():
    redaction._REGISTRY.clear()
    yield
    redaction._REGISTRY.clear()


def test_str_and_repr_never_contain_the_value():
    s = Secret("hunter2-correct-horse")
    assert "hunter2" not in str(s)
    assert "hunter2" not in repr(s)
    assert "Secret(" in repr(s)


def test_reveal_returns_the_value():
    assert Secret("hunter2-correct-horse").reveal() == "hunter2-correct-horse"


def test_construction_registers_for_redaction():
    Secret("hunter2-correct-horse")
    assert redaction.scrub("token=hunter2-correct-horse") == f"token={redaction.PLACEHOLDER}"


def test_short_values_are_still_wrapped_even_though_redaction_skips_them():
    # redaction.MIN_LENGTH is 8: shorter values would match too much unrelated
    # text. The wrapper must still hide them from repr.
    s = Secret("abc")
    assert "abc" not in repr(s)
    assert s.reveal() == "abc"


def test_formatting_and_interpolation_do_not_leak():
    s = Secret("hunter2-correct-horse")
    assert "hunter2" not in f"{s}"
    assert "hunter2" not in "{}".format(s)
    assert "hunter2" not in "%s" % (s,)


def test_equality_compares_values_but_only_against_secret():
    assert Secret("a-long-enough-value") == Secret("a-long-enough-value")
    assert Secret("a-long-enough-value") != Secret("another-long-value")
    assert Secret("a-long-enough-value") != "a-long-enough-value"


def test_len_is_the_value_length():
    # Length is deliberately exposed: verification compares lengths, never
    # values. See the warehouse rotation in phase-5b.
    assert len(Secret("12345678")) == 8


def test_logging_a_secret_object_does_not_leak(caplog):
    s = Secret("hunter2-correct-horse")
    with caplog.at_level(logging.INFO):
        logging.getLogger("t").info("using %s", s)
    assert "hunter2" not in caplog.text


def test_provider_get_secret_wraps_and_get_still_returns_str():
    class Fake(SecretProvider):
        def _fetch(self, name: str) -> str:
            return "resolved-value-long"

    p = Fake()
    assert p.get("thing") == "resolved-value-long"
    wrapped = p.get_secret("thing")
    assert isinstance(wrapped, Secret)
    assert wrapped.reveal() == "resolved-value-long"
    assert "resolved-value-long" not in repr(wrapped)
