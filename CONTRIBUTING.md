# Contributing

## Development

```bash
git clone git@github.com:inspicere/secops-ingest.git
cd secops-ingest
pip install -e ".[dev]"
pytest
```

The package uses a `src/` layout with `pythonpath = ["src"]` in the pytest config, so the tests
import without a build step.

## Before opening a pull request

```bash
ruff check src tests
mypy src
pytest -q
```

CI runs exactly these, plus a check that core still imports with **no** optional dependency
installed. That last one is the one people trip over: if you add a top-level import of an
optional package anywhere in the core path, a default install stops working and the project's
central claim stops being true.

## Tests

- No live API calls. Ever. Tests must pass on a machine with no credentials and no network.
- Fixtures must be synthetic or thoroughly sanitised — no tenant identifiers, hostnames, real
  addresses, or personal data. Use `example.com`; it is reserved for this.
- A regression test should be seen to fail before it is trusted. Revert the fix, watch it go red,
  restore. A test that has never failed is not yet evidence of anything.

## Adding a secret backend

Prefer shipping it as your own package with an entry point — see the README. That way your
dependency never enters anyone else's install, and you do not need this project to accept a
change in order to release yours.

A backend belongs *here* only if it depends on nothing outside the standard library.

## Adding a connector

Connectors live in `secops_ingest/sources/` and follow the contract shown in the README, with
`example.py` as the worked reference. Two requirements beyond the interface:

- **Base URLs, regions, and tenant identifiers come from configuration, never constants.** A
  connector with a hardcoded endpoint is usable by exactly one organisation.
- **Pick the watermark deliberately** and say in a comment why that field and not another. If
  the vendor mutates records after creation, a creation-time watermark will silently skip every
  update.

## Commit messages

Explain why, not what — the diff already says what. If you found a trap worth remembering,
the commit message is a good place for it; the next person to touch that code will run
`git log` on it long before they read any docs.
