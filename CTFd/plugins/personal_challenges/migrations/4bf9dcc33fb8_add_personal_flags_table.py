"""add_personal_flags_table

Revision ID: 4bf9dcc33fb8
Revises: None
Create Date: 2024-11-09 09:11:03.277734

"""
#THIS

# revision identifiers, used by Alembic.
import sqlalchemy as sa
from alembic import op

revision = "4bf9dcc33fb8"
down_revision = None
branch_labels = None
depends_on = None

def upgrade(op=None):
    # op.create_table(
    #     "personal_flags",
    #     #sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    #     sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    #     sa.Column("variable", sa.String(length=128), nullable=False),
    #     sa.Column("contents", sa.String(length=128), nullable=False),
    # )

    op.create_table(
        "personal_flags",
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("variable", sa.String(length=128), nullable=False),
        sa.Column("contents", sa.String(length=128), nullable=False),
        sa.PrimaryKeyConstraint("user_id", "variable")
    )


def downgrade(op=None):
    op.drop_table("personal_flags")

