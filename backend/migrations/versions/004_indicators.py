"""Indicator store tables (design core-v1 §7.2). No data step: feed projection is a runtime job.

Tables are defined explicitly here, not from live models. A table that already
exists is accepted only when it has every expected column.
"""
from alembic import op
import sqlalchemy as sa

revision = '004_indicators'; down_revision = '003_feed_observations'; branch_labels = None; depends_on = None


def _ensure_table(name, *elements, indexes=()):
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    expected = {e.name for e in elements if isinstance(e, sa.Column)}
    if name in inspector.get_table_names():
        existing = {c['name'] for c in inspector.get_columns(name)}
        if not expected <= existing:
            raise RuntimeError(f'{name}_exists_with_unexpected_columns')
        return
    op.create_table(name, *elements)
    for index_name, columns, unique in indexes:
        op.create_index(index_name, name, columns, unique=unique)


def upgrade():
    _ensure_table(
        'indicators',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('type', sa.String(16), nullable=False),
        sa.Column('value_hash', sa.String(64), nullable=False),
        sa.Column('value', sa.Text, nullable=True),
        sa.Column('hash_algo', sa.String(16), nullable=True),
        sa.Column('registered_domain', sa.String(255), nullable=True),
        sa.Column('registered_domain_hash', sa.String(64), nullable=True),
        sa.Column('first_seen', sa.DateTime, nullable=False),
        sa.Column('last_seen', sa.DateTime, nullable=False),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint('type', 'value_hash', name='uq_indicators_type_value_hash'),
        indexes=[('ix_indicators_registered_domain', ['registered_domain'], False),
                 ('ix_indicators_registered_domain_hash', ['registered_domain_hash'], False)])
    _ensure_table(
        'indicator_sightings',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('indicator_id', sa.Integer, sa.ForeignKey('indicators.id', ondelete='CASCADE'), nullable=False),
        sa.Column('source_kind', sa.String(16), nullable=False),
        sa.Column('source_name', sa.String(50), nullable=False),
        sa.Column('first_seen', sa.DateTime, nullable=False),
        sa.Column('last_seen', sa.DateTime, nullable=False),
        sa.Column('active', sa.Boolean, nullable=False),
        sa.Column('ref', sa.String(200), nullable=True),
        sa.UniqueConstraint('indicator_id', 'source_kind', 'source_name', name='uq_indicator_sightings_source'),
        indexes=[('ix_indicator_sightings_indicator_id', ['indicator_id'], False)])
    _ensure_table(
        'correlation_stoplist',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('type', sa.String(16), nullable=False),
        sa.Column('value_hash', sa.String(64), nullable=False),
        sa.Column('value', sa.Text, nullable=True),
        sa.Column('reason', sa.String(50), nullable=False),
        sa.Column('brand', sa.String(255), nullable=True),
        sa.Column('seeded', sa.Boolean, nullable=False),
        sa.UniqueConstraint('type', 'value_hash', name='uq_correlation_stoplist_type_value_hash'))


def downgrade():
    # The projection is rebuildable from the feed tables; analyst stoplist rows are lost.
    op.drop_table('indicator_sightings')
    op.drop_table('correlation_stoplist')
    op.drop_table('indicators')
