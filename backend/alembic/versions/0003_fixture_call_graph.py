"""Persist fixture/real source marker and PageRank centrality.

Revision ID: 0003_fixture_call_graph
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "0003_fixture_call_graph"
down_revision = "0002_pe_static_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = inspect(op.get_bind())
    if "ghidra_source" not in {column["name"] for column in inspector.get_columns("analyses")}:
        op.add_column("analyses", sa.Column("ghidra_source", sa.String(), nullable=False, server_default="none"))
    if "centrality" not in {column["name"] for column in inspect(op.get_bind()).get_columns("functions")}:
        op.add_column("functions", sa.Column("centrality", sa.Float(), nullable=False, server_default="0"))


def downgrade() -> None:
    inspector = inspect(op.get_bind())
    if "centrality" in {column["name"] for column in inspector.get_columns("functions")}:
        op.drop_column("functions", "centrality")
    if "ghidra_source" in {column["name"] for column in inspector.get_columns("analyses")}:
        op.drop_column("analyses", "ghidra_source")
