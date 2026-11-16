"""Persist the evidence-grounded pipeline AI report.

Revision ID: 0005_ai_pipeline_report
Revises: 0004_rule_scoring

The initial migration builds tables from current ORM metadata, so this
revision is idempotent for fresh databases and upgrades existing databases.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql

revision = "0005_ai_pipeline_report"
down_revision = "0004_rule_scoring"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {
        column["name"] for column in inspect(op.get_bind()).get_columns("analyses")
    }
    if "ai_report" not in columns:
        op.add_column(
            "analyses", sa.Column("ai_report", postgresql.JSONB(), nullable=True)
        )


def downgrade() -> None:
    columns = {
        column["name"] for column in inspect(op.get_bind()).get_columns("analyses")
    }
    if "ai_report" in columns:
        op.drop_column("analyses", "ai_report")
