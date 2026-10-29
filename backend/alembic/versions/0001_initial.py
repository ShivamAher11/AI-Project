"""Create the initial normalized-analysis PostgreSQL schema.

Revision ID: 0001_initial
"""

from alembic import op

from app.db import Base
import app.models  # noqa: F401 — register mapped tables before create_all

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
