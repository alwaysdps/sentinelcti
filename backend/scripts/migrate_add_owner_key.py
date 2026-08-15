"""Add the `owner_key` column for anonymous per-browser workspaces.

Written as an explicit, idempotent migration rather than left to `create_all`,
which only ever CREATEs — it never ALTERs an existing table, so on a deployed
database the column would simply never appear and every query would fail on a
missing column.

    python -m scripts.migrate_add_owner_key            # show what would change
    python -m scripts.migrate_add_owner_key --apply    # apply it

Existing rows are left with owner_key = NULL, which is deliberate:

  * seeded demo rows (`is_demo`) stay visible to everyone, so a first-time
    visitor still lands on a populated dashboard;
  * every other pre-existing row becomes owned by nobody and therefore visible
    to nobody. That is the correct outcome — those rows were created before
    workspaces existed, under a model where everything was public, so there is
    no honest workspace to assign them to. It also quietly retires the test
    artefacts left in the table during development, without deleting anything.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import inspect, text  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.database.session import engine, is_postgres  # noqa: E402

TABLE = "analyses"
COLUMN = "owner_key"
INDEX = "ix_analyses_owner_key"


def column_exists() -> bool:
    return any(c["name"] == COLUMN for c in inspect(engine).get_columns(TABLE))


def index_exists() -> bool:
    return any(i["name"] == INDEX for i in inspect(engine).get_indexes(TABLE))


def main(apply: bool) -> int:
    print(f"Database : {settings.database_url.split('@')[-1] if '@' in settings.database_url else settings.database_url}")

    if TABLE not in inspect(engine).get_table_names():
        print(f"[fail] Table '{TABLE}' does not exist. Run: python -m scripts.check_db --create")
        return 1

    has_column, has_index = column_exists(), index_exists()
    print(f"  {COLUMN} column : {'present' if has_column else 'MISSING'}")
    print(f"  {INDEX} : {'present' if has_index else 'MISSING'}")

    if has_column and has_index:
        print("\n[ ok ] Already migrated. Nothing to do.")
        return 0

    if not apply:
        print("\nRe-run with --apply to make these changes.")
        return 0

    # Nullable with no default: every existing row stays unowned, which is what
    # keeps this migration non-destructive and instant even on a large table.
    statements: list[str] = []
    if not has_column:
        varchar = "VARCHAR(64)" if is_postgres(settings.database_url) else "VARCHAR(64)"
        statements.append(f"ALTER TABLE {TABLE} ADD COLUMN {COLUMN} {varchar}")
    if not has_index:
        statements.append(f"CREATE INDEX {INDEX} ON {TABLE} ({COLUMN})")

    with engine.begin() as conn:
        for statement in statements:
            print(f"  -> {statement}")
            conn.execute(text(statement))

    if not (column_exists() and index_exists()):
        print("\n[fail] Verification failed after applying.")
        return 1

    with engine.connect() as conn:
        total = conn.execute(text(f"SELECT count(*) FROM {TABLE}")).scalar_one()
        demo = conn.execute(text(f"SELECT count(*) FROM {TABLE} WHERE is_demo")).scalar_one()

    print(f"\n[ ok ] Migrated. {total} rows: {demo} shared demo, {total - demo} now unowned.")
    print("       Demo rows stay visible to every visitor; the rest are retired.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Apply the migration.")
    raise SystemExit(main(parser.parse_args().apply))
