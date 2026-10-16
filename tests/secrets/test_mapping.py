# tests/secrets/test_mapping.py
from __future__ import annotations

import pytest

from secops_ingest.secrets.mapping import (
    InvalidMap,
    Posture,
    load_map,
)

GOOD = {
    "posture": "assured",
    "providers": {
        "vault": {"kind": "vault_agent", "config": {"socket": "/run/vault-agent/agent.sock"}},
        "delinea": {
            "kind": "delinea",
            "config": {"base_url": "https://pam.example.com"},
            "credential": "delinea.bootstrap",
        },
    },
    "entries": {
        "xdr_ro.api_key": {"provider": "vault", "path": "secops/xdr_ro", "field": "api_key"},
        "delinea.bootstrap": {"provider": "vault", "path": "metabase/delinea", "field": "secret"},
        "phisher.token": {"provider": "delinea", "secret": "4821", "field": "password"},
    },
}


def test_loads_a_valid_map():
    m = load_map(GOOD)
    assert m.posture is Posture.ASSURED
    assert set(m.providers) == {"vault", "delinea"}
    assert m.entries["phisher.token"].provider == "delinea"
    assert m.entries["phisher.token"].locator == {"secret": "4821", "field": "password"}


def test_vault_is_root_and_delinea_is_brokered():
    m = load_map(GOOD)
    assert m.providers["vault"].credential is None
    assert m.providers["delinea"].credential == "delinea.bootstrap"
    assert m.roots() == {"vault"}


def test_resolution_order_puts_roots_first():
    # A brokered provider cannot be constructed until the entry holding its
    # credential is resolvable, so the order matters to the caller.
    assert load_map(GOOD).resolution_order() == ["vault", "delinea"]


def test_entry_naming_an_unknown_provider_is_rejected():
    doc = {**GOOD, "entries": {"a.b": {"provider": "nope", "path": "x", "field": "y"}}}
    with pytest.raises(InvalidMap, match="unknown provider 'nope'"):
        load_map(doc)


def test_provider_credential_naming_a_missing_entry_is_rejected():
    doc = {
        "posture": "assured",
        "providers": {"d": {"kind": "delinea", "config": {}, "credential": "not.there"}},
        "entries": {},
    }
    with pytest.raises(InvalidMap, match="credential 'not.there'"):
        load_map(doc)


def test_a_cycle_is_rejected():
    doc = {
        "posture": "assured",
        "providers": {
            "a": {"kind": "vault_agent", "config": {}, "credential": "b.cred"},
            "b": {"kind": "delinea", "config": {}, "credential": "a.cred"},
        },
        "entries": {
            "a.cred": {"provider": "b", "secret": "1", "field": "f"},
            "b.cred": {"provider": "a", "path": "p", "field": "f"},
        },
    }
    with pytest.raises(InvalidMap, match="cycle"):
        load_map(doc)


def test_a_map_with_no_root_is_rejected():
    doc = {
        "posture": "assured",
        "providers": {"a": {"kind": "delinea", "config": {}, "credential": "a.self"}},
        "entries": {"a.self": {"provider": "a", "secret": "1", "field": "f"}},
    }
    with pytest.raises(InvalidMap, match="no root provider"):
        load_map(doc)


def test_assured_posture_rejects_a_file_provider():
    doc = {
        "posture": "assured",
        "providers": {"f": {"kind": "file", "config": {"directory": "/etc/x"}}},
        "entries": {"a.b": {"provider": "f", "name": "a.b"}},
    }
    with pytest.raises(InvalidMap, match="posture 'assured' forbids provider kind 'file'"):
        load_map(doc)


def test_dev_posture_permits_a_file_provider():
    doc = {
        "posture": "dev",
        "providers": {"f": {"kind": "file", "config": {"directory": "/etc/x"}}},
        "entries": {"a.b": {"provider": "f", "name": "a.b"}},
    }
    assert load_map(doc).posture is Posture.DEV


def test_invalid_secret_name_is_rejected():
    doc = {**GOOD, "entries": {"../etc/passwd": {"provider": "vault", "path": "p", "field": "f"}}}
    with pytest.raises(InvalidMap, match="invalid secret name"):
        load_map(doc)


def test_unknown_posture_is_rejected():
    with pytest.raises(InvalidMap, match="unknown posture 'yolo'"):
        load_map({**GOOD, "posture": "yolo"})


def test_non_mapping_document_is_rejected():
    with pytest.raises(InvalidMap, match="must be a mapping"):
        load_map(["not", "a", "dict"])


def test_missing_posture_is_rejected_rather_than_defaulted():
    doc = {k: v for k, v in GOOD.items() if k != "posture"}
    with pytest.raises(InvalidMap, match="posture is required"):
        load_map(doc)


def _one_provider(posture, kind):
    return {
        "posture": posture,
        "providers": {"p": {"kind": kind, "config": {}}},
        "entries": {"a.b": {"provider": "p", "name": "a.b"}},
    }


def test_assured_posture_rejects_a_registered_non_pam_kind():
    # "env" is registered, and is not a PAM kind. An allowlist refuses it, and
    # would equally refuse any third-party file-reading plugin.
    with pytest.raises(InvalidMap, match="posture 'assured' forbids provider kind 'env'"):
        load_map(_one_provider("assured", "env"))


def test_assured_posture_compares_kinds_lowercased():
    with pytest.raises(InvalidMap, match="posture 'assured' forbids provider kind 'File'"):
        load_map(_one_provider("assured", "File"))
    # A mixed-case PAM kind passes the allowlist but is not a registered
    # backend name, so it is still refused -- at load, not at resolution.
    with pytest.raises(InvalidMap, match="unregistered kind 'Vault_Agent'"):
        load_map(_one_provider("assured", "Vault_Agent"))


def test_an_unregistered_kind_is_rejected_at_load():
    with pytest.raises(InvalidMap, match="unregistered kind 'vualt_agent'"):
        load_map(_one_provider("dev", "vualt_agent"))


def test_kind_checking_can_be_left_to_an_injected_factory():
    assert load_map(_one_provider("dev", "anything"), check_kinds=False).posture is Posture.DEV


def test_a_typod_top_level_key_is_rejected_not_loaded_empty():
    doc = {"posture": "assured", "provider": GOOD["providers"], "entry": GOOD["entries"]}
    with pytest.raises(InvalidMap, match="unknown top-level key.*'entry'.*'provider'"):
        load_map(doc)


def test_a_typod_provider_spec_key_is_rejected():
    doc = {**GOOD, "providers": {"vault": {"kind": "vault_agent", "credentail": "x"}}}
    with pytest.raises(InvalidMap, match="provider 'vault' has unknown key.*'credentail'"):
        load_map(doc)


def test_entry_locators_still_accept_arbitrary_keys():
    doc = {
        **GOOD,
        "entries": {
            **GOOD["entries"],
            "a.b": {"provider": "vault", "path": "p", "field": "f", "anything": "goes"},
        },
    }
    assert load_map(doc).entries["a.b"].locator["anything"] == "goes"
