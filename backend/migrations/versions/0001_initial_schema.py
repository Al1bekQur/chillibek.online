"""initial schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-10-13
"""
from alembic import op
import sqlalchemy as sa


revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "menu_items",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("weight", sa.String(length=50), nullable=True),
        sa.Column("price", sa.Integer(), nullable=False),
        sa.Column("image_url", sa.Text(), nullable=True),
        sa.CheckConstraint("price > 0", name="ck_menu_items_price_positive"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "staff",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("username", sa.String(length=80), nullable=False),
        sa.Column("password", sa.Text(), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.CheckConstraint("role IN ('admin', 'waiter', 'chef')", name="ck_staff_role"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )
    op.create_table(
        "orders",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("table_number", sa.String(length=2), nullable=True),
        sa.Column("items_json", sa.Text(), nullable=False),
        sa.Column("total_price", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), server_default="pending", nullable=False),
        sa.Column("created_at", sa.String(length=32), nullable=True),
        sa.Column("approved_at", sa.String(length=32), nullable=True),
        sa.Column("ready_at", sa.String(length=32), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'cooking', 'ready', 'completed')",
            name="ck_orders_status",
        ),
        sa.CheckConstraint("total_price >= 0", name="ck_orders_total_price_nonnegative"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("orders")
    op.drop_table("staff")
    op.drop_table("menu_items")
