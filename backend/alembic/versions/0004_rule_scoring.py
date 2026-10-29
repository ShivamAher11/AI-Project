"""Persist deterministic rule score and breakdown.

Revision ID: 0004_rule_scoring
Revises: 0003_fixture_call_graph
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0004_rule_scoring"
down_revision = "0003_fixture_call_graph"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("analyses", sa.Column("risk_score", sa.Integer(), nullable=True))
    op.add_column("analyses", sa.Column("risk_rating", sa.String(), nullable=True))
    op.add_column("analyses", sa.Column("scoring_breakdown", postgresql.JSONB(), nullable=True))
    op.add_column("analyses", sa.Column("scoring_input_hash", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("analyses", "scoring_breakdown")
    op.drop_column("analyses", "scoring_input_hash")
    op.drop_column("analyses", "risk_rating")
    op.drop_column("analyses", "risk_score")
