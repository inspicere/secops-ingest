from __future__ import annotations

import re

from secops_ingest.schema import control_sql

# One match per declaration: from the column name through its terminating comma,
# so a NOT NULL on a continuation line still falls inside the match.
_DECLARATION = re.compile(r"^\s*posture\s+text[^,]*,", re.M)


def test_both_run_tables_carry_a_posture_column():
    sql = control_sql()
    assert len(_DECLARATION.findall(sql)) == 2
    assert "posture       text" in sql


def test_posture_is_nullable_so_existing_rows_remain_valid():
    # Adding NOT NULL would require a default and rewrite every historical
    # row with a value that was never true of it.
    for declaration in _DECLARATION.findall(control_sql()):
        assert "NOT NULL" not in declaration
