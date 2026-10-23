"""Persistent mandatory login admission state; no restaurant data migration."""
from alembic import op
import sqlalchemy as sa

revision = '0002_login_attempts'
down_revision = '0001_initial_schema'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('login_attempts',
        sa.Column('identity', sa.String(64), primary_key=True),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('level', sa.Integer(), nullable=False),
        sa.Column('reset_at', sa.Float(), nullable=False),
        sa.Column('locked_until', sa.Float(), nullable=False))


def downgrade():
    op.drop_table('login_attempts')
