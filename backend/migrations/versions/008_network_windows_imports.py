"""network.windows import records (design network-windows-v1 §6.7, §7; step 11). Counts and digests only."""
from alembic import op
import sqlalchemy as sa

revision = '008_network_windows_imports'; down_revision = '007_malware_scans'; branch_labels = None; depends_on = None
TABLE = 'network_windows_imports'
COLUMNS = ['id', 'started_at', 'finished_at', 'engine_version', 'manifest_sha256', 'lists_lock_sha256', 'span_first',
           'span_last', 'files', 'counts', 'coverage', 'findings_by_kind']


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if TABLE in inspector.get_table_names():
        if not set(COLUMNS) <= {c['name'] for c in inspector.get_columns(TABLE)}:
            raise RuntimeError('network_windows_imports_exists_with_unexpected_columns')
        return
    op.create_table(
        TABLE,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('started_at', sa.DateTime, nullable=False),
        sa.Column('finished_at', sa.DateTime, nullable=True),
        sa.Column('engine_version', sa.String(200), nullable=False),
        sa.Column('manifest_sha256', sa.String(64), nullable=True),
        sa.Column('lists_lock_sha256', sa.String(64), nullable=True),
        sa.Column('span_first', sa.DateTime, nullable=True),
        sa.Column('span_last', sa.DateTime, nullable=True),
        sa.Column('files', sa.JSON, nullable=False),
        sa.Column('counts', sa.JSON, nullable=False),
        sa.Column('coverage', sa.JSON, nullable=False),
        sa.Column('findings_by_kind', sa.JSON, nullable=False))
    op.create_index('ix_network_windows_imports_started_at', TABLE, ['started_at'])


def downgrade():
    op.drop_index('ix_network_windows_imports_started_at', table_name=TABLE)
    op.drop_table(TABLE)
