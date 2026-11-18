"""ATT&CK technique catalogue table (design core-v1 §7.2). Loading happens in scripts/initialize.py."""
from alembic import op
import sqlalchemy as sa

revision = '006_attack_catalogue'; down_revision = '005_findings_incidents'; branch_labels = None; depends_on = None
COLUMNS = ['technique_id', 'matrix', 'attack_version', 'name', 'tactics', 'platforms', 'stix_id', 'url']


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if 'attack_techniques' in inspector.get_table_names():
        if not set(COLUMNS) <= {c['name'] for c in inspector.get_columns('attack_techniques')}:
            raise RuntimeError('attack_techniques_exists_with_unexpected_columns')
        return
    op.create_table(
        'attack_techniques',
        sa.Column('technique_id', sa.String(16), primary_key=True),
        sa.Column('matrix', sa.String(16), primary_key=True),
        sa.Column('attack_version', sa.String(16), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('tactics', sa.JSON, nullable=False),
        sa.Column('platforms', sa.JSON, nullable=False),
        sa.Column('stix_id', sa.String(100), nullable=False),
        sa.Column('url', sa.String(255), nullable=True))


def downgrade():
    op.drop_table('attack_techniques')
