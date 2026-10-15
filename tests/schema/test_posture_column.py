from __future__ import annotations

import re

from secops_ingest.schema import control_sql


def test_both_run_tables_carry_a_posture_column():
    sql = control_sql()
    assert len(re.findall(r"^\s*posture\s+text", sql, re.M)) == 2
    assert "posture       text" in sql or "posture text" in sql


def test_posture_is_nullable_so_existing_rows_remain_valid():
    # Adding NOT NULL would require a default and rewrite every historical
    # row with a value that was never true of it.
    sql = control_sql()
    for line in sql.splitlines():
        if "posture" in line:
            assert "NOT NULL" not in line
