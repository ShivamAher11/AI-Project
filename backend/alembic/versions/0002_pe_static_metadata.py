"""Persist PE endian, extension warning, and export symbols.

Revision ID: 0002_pe_static_metadata
"""

import sqlalchemy as sa
from sqlalchemy import inspect
from alembic import op


revision = "0002_pe_static_metadata"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = inspect(op.get_bind())
    analysis_columns = {column["name"] for column in inspector.get_columns("analyses")}
    if "endian" not in analysis_columns:
        op.add_column("analyses", sa.Column("endian", sa.String(length=2), nullable=False, server_default="le"))
    if "extension_mismatch" not in analysis_columns:
        op.add_column("analyses", sa.Column("extension_mismatch", sa.Boolean(), nullable=False, server_default=sa.false()))
    if "strings_truncated" not in analysis_columns:
        op.add_column("analyses", sa.Column("strings_truncated", sa.Boolean(), nullable=False, server_default=sa.false()))
    if "possible_packing" not in analysis_columns:
        op.add_column("analyses", sa.Column("possible_packing", sa.Boolean(), nullable=False, server_default=sa.false()))
    if not inspector.has_table("export_symbols"):
        op.create_table(
            "export_symbols",
            sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
            sa.Column("analysis_id", sa.UUID(), nullable=False),
            sa.Column("name", sa.Text(), nullable=False),
            sa.Column("address", sa.Text(), nullable=True),
            sa.Column("ordinal", sa.Integer(), nullable=True),
            sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
    indexes = {index["name"] for index in inspect(op.get_bind()).get_indexes("export_symbols")}
    if "ix_export_symbols_analysis_name" not in indexes:
        op.create_index("ix_export_symbols_analysis_name", "export_symbols", ["analysis_id", "name"])


def downgrade() -> None:
    inspector = inspect(op.get_bind())
    if inspector.has_table("export_symbols"):
        indexes = {index["name"] for index in inspector.get_indexes("export_symbols")}
        if "ix_export_symbols_analysis_name" in indexes:
            op.drop_index("ix_export_symbols_analysis_name", table_name="export_symbols")
        op.drop_table("export_symbols")
    analysis_columns = {column["name"] for column in inspect(op.get_bind()).get_columns("analyses")}
    if "extension_mismatch" in analysis_columns:
        op.drop_column("analyses", "extension_mismatch")
    if "endian" in analysis_columns:
        op.drop_column("analyses", "endian")
    if "strings_truncated" in analysis_columns:
        op.drop_column("analyses", "strings_truncated")
    if "possible_packing" in analysis_columns:
        op.drop_column("analyses", "possible_packing")
