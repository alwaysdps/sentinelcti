"""Delete seeded demo analyses from the configured database.

WHY THIS EXISTS
---------------
Demo rows belong to no workspace, which is what made them shareable back when
a first-time visitor was shown a populated dashboard. Nothing is shared any
more (see `services/query_service.visible_to`), so they are invisible to every
caller -- and there is deliberately no API route that can delete them, because
an endpoint able to remove rows nobody owns is an endpoint able to empty the
database for everyone.

That leaves them stranded: stored, unreachable, and counted by nothing. This
script is the supported way to clear them out.

It is also the only tool here that deletes data it was not handed a key for, so
it is built to be hard to misfire:

  * it reports before it deletes, and does nothing without `--yes`;
  * the WHERE clause is `is_demo IS TRUE` and nothing else, so a row belonging
    to a real visitor cannot be caught by it even accidentally;
  * it prints the database it is about to touch, with the password redacted,
    because "which database am I pointed at" is the question you want answered
    *before* the delete rather than after.

Usage:
    python -m scripts.purge_demo               # report only
    python -m scripts.purge_demo --yes         # actually delete

Against a remote database, point DATABASE_URL at it for the one command:
    DATABASE_URL=postgresql+psycopg://... python -m scripts.purge_demo --yes
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import delete, func, select  # noqa: E402

from app.database.session import SessionLocal, backend_name  # noqa: E402
from app.models.analysis import Analysis  # noqa: E402

from scripts.check_db import redacted_url  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Delete seeded demo analyses.")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Perform the deletion. Without it, this only reports what would go.",
    )
    args = parser.parse_args()

    print(f"Backend : {backend_name()}")
    print(f"URL     : {redacted_url()}\n")

    db = SessionLocal()
    try:
        total = db.execute(select(func.count()).select_from(Analysis)).scalar_one()
        demo = db.execute(
            select(func.count()).select_from(Analysis).where(Analysis.is_demo.is_(True))
        ).scalar_one()

        print(f"Total analyses stored : {total}")
        print(f"Flagged is_demo       : {demo}")
        print(f"Belonging to visitors : {total - demo}  (never touched by this script)\n")

        if not demo:
            print("[ ok ] No demo rows to remove.")
            return 0

        sample = db.execute(
            select(Analysis.reference, Analysis.indicator_display)
            .where(Analysis.is_demo.is_(True))
            .order_by(Analysis.id)
            .limit(5)
        ).all()
        print("Sample of what would go:")
        for reference, indicator in sample:
            print(f"  {reference}  {indicator[:60]}")
        if demo > len(sample):
            print(f"  ... and {demo - len(sample)} more")

        if not args.yes:
            print(f"\n[dry run] {demo} rows would be deleted. Re-run with --yes to do it.")
            return 0

        removed = db.execute(delete(Analysis).where(Analysis.is_demo.is_(True))).rowcount
        db.commit()

        remaining = db.execute(select(func.count()).select_from(Analysis)).scalar_one()
        print(f"\n[ ok ] Deleted {removed} demo analyses.")
        print(f"       {remaining} analyses remain, all belonging to real workspaces.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
