"""Persist deterministic rule score and breakdown.

Revision ID: 0004_rule_scoring
Revises: 0003_fixture_call_graph
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
    columns = {column["name"] for column in inspect(op.get_bind()).get_columns("analyses")}
    additions = (
        ("risk_score", sa.Column("risk_score", sa.Integer(), nullable=True)),
        ("risk_rating", sa.Column("risk_rating", sa.String(), nullable=True)),
        ("scoring_breakdown", sa.Column("scoring_breakdown", postgresql.JSONB(), nullable=True)),
        ("scoring_input_hash", sa.Column("scoring_input_hash", sa.String(length=64), nullable=True)),
    )
    for name, column in additions:
        if name not in columns:
            op.add_column("analyses", column)


def downgrade() -> None:
    columns = {column["name"] for column in inspect(op.get_bind()).get_columns("analyses")}
    for name in ("scoring_breakdown", "scoring_input_hash", "risk_rating", "risk_score"):
        if name in columns:
            op.drop_column("analyses", name)
