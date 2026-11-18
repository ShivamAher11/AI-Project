"""Allow the generic format on analyses to accept arbitrary regular files.

Changes:
- Update ck_analyses_format check constraint from ('pe', 'elf') to
  ('pe', 'elf', 'generic') so unknown-magic uploads can be stored.
"""

from __future__ import annotations

from alembic import op

revision = "0007_allow_generic_format"
down_revision = "0006_ai_function_summary"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("ck_analyses_format", "analyses", type_="check")
    op.create_check_constraint(
        "ck_analyses_format",
        "analyses",
        "format IN ('pe', 'elf', 'generic')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_analyses_format", "analyses", type_="check")
    op.create_check_constraint(
        "ck_analyses_format",
        "analyses",
        "format IN ('pe', 'elf')",
    )
