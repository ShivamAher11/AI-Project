"""Persist deterministic rule score and breakdown.

Revision ID: 0004_rule_scoring
Revises: 0003_fixture_call_graph

This migration is intentionally idempotent because 0001_initial builds its
schema from the currently imported SQLAlchemy models. On some databases that
means these columns already exist before this revision is reached.
"""

from alembic import op
from sqlalchemy import inspect
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0004_rule_scoring"
down_revision = "0003_fixture_call_graph"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = inspect(op.get_bind())
    existing_columns = {column["name"] for column in inspector.get_columns("analyses")}

    columns_to_add = (
        ("risk_score", sa.Column("risk_score", sa.Integer(), nullable=True)),
        ("risk_rating", sa.Column("risk_rating", sa.String(), nullable=True)),
        (
            "scoring_breakdown",
            sa.Column("scoring_breakdown", postgresql.JSONB(), nullable=True),
        ),
        (
            "scoring_input_hash",
            sa.Column("scoring_input_hash", sa.String(length=64), nullable=True),
        ),
    )

    for column_name, column in columns_to_add:
        if column_name not in existing_columns:
            op.add_column("analyses", column)
            existing_columns.add(column_name)


def downgrade() -> None:
    existing_columns = {
        column["name"] for column in inspect(op.get_bind()).get_columns("analyses")
    }

    # Drop in reverse dependency/order, checking first so downgrade is resilient
    # to databases whose schema was originally created from current ORM metadata.
    for column_name in (
        "scoring_breakdown",
        "scoring_input_hash",
        "risk_rating",
        "risk_score",
    ):
        if column_name in existing_columns:
            op.drop_column("analyses", column_name)
