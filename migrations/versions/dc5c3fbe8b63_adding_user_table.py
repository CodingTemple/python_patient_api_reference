"""Adding user table

Revision ID: dc5c3fbe8b63
Revises: 8dc731fb734e
Create Date: 2020-11-01 11:55:37.760633

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'dc5c3fbe8b63'
down_revision = '8dc731fb734e'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.String(length=200), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('password', sa.String(length=256), nullable=False),
    sa.Column('date_created', sa.DateTime(), nullable=False),
    sa.Column('token', sa.String(length=256), nullable=True),
    sa.Column('token_refreshed', sa.Boolean(), nullable=True),
    sa.Column('date_refreshed', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('user')
    # ### end Alembic commands ###
