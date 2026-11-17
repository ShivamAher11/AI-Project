"""Persist structured Stage 1 function summaries and link AI runs to functions.

Adds:
- functions.ai_summary_json: nullable JSONB holding a validated Stage 1
  function summary (schema_version 1.0). Kept readable alongside the legacy
  functions.ai_summary text column during the transition.
- ai_runs.function_id: nullable FK to functions.id, indexed, so a function
  summary run can be associated with exactly one function. Null for
  analysis-level runs.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql

revision = "0006_ai_function_summary"
down_revision = "0005_ai_pipeline_report"
branch_labels = None
depends_on = None


def _table_columns(table: str) -> set[str]:
    bind = op.get_bind()
    inspector = inspect(bind)
    return {column["name"] for column in inspector.get_columns(table)}


def _indexes(table: str) -> set[str]:
    bind = op.get_bind()
    inspector = inspect(bind)
    return {index["name"] for index in inspector.get_indexes(table)}


def upgrade() -> None:
    columns = _table_columns("functions")
    if "ai_summary_json" not in columns:
        op.add_column(
            "functions",
            sa.Column("ai_summary_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        )

    ai_run_columns = _table_columns("ai_runs")
    if "function_id" not in ai_run_columns:
        op.add_column(
            "ai_runs",
            sa.Column("function_id", sa.Text(), nullable=True),
        )
        op.create_foreign_key(
            "fk_ai_runs_function_id",
            "ai_runs",
            "functions",
            ["function_id"],
            ["id"],
            ondelete="CASCADE",
        )

    indexes = _indexes("ai_runs")
    if "ix_ai_runs_function_id" not in indexes:
        op.create_index(
            "ix_ai_runs_function_id",
            "ai_runs",
            ["function_id"],
            unique=False,
        )


def downgrade() -> None:
    indexes = _indexes("ai_runs")
    if "ix_ai_runs_function_id" in indexes:
        op.drop_index("ix_ai_runs_function_id", table_name="ai_runs")

    ai_run_columns = _table_columns("ai_runs")
    if "function_id" in ai_run_columns:
        # Drop the FK constraint if present (name follows the create_foreign_key
        # convention above); be resilient to databases created before this migration.
        bind = op.get_bind()
        inspector = inspect(bind)
        for fk in inspector.get_foreign_keys("ai_runs"):
            if fk["referred_table"] == "functions" and "function_id" in (fk.get("constrained_columns") or []):
                op.drop_constraint(fk["name"], "ai_runs", type_="foreignkey")
                break
        op.drop_column("ai_runs", "function_id")

    columns = _table_columns("functions")
    if "ai_summary_json" in columns:
        op.drop_column("functions", "ai_summary_json")
