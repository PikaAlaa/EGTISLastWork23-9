"""Stored device of each finding (design core-v2 §3.2, step 7b).

`finding_devices.device_ref` always holds the server-wrapped `srv:<32 hex>` ref; no endpoint
`hmac:` ref is stored. The table is defined explicitly here, not from live models. Downgrade
drops it; attributions can be rebuilt only for findings whose details keep the ref
(data/scripts/rewrap_device_refs.py), because no secret may be needed by a migration.
"""
from alembic import op
import sqlalchemy as sa

revision = '009_finding_devices'; down_revision = '008_network_windows_imports'; branch_labels = None; depends_on = None
TABLE = 'finding_devices'
COLUMNS = ['finding_id', 'device_ref', 'attributed_by']
INDEX = 'ix_finding_devices_device_ref'


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if TABLE in inspector.get_table_names():
        if not set(COLUMNS) <= {c['name'] for c in inspector.get_columns(TABLE)}:
            raise RuntimeError('finding_devices_exists_with_unexpected_columns')
        return
    op.create_table(
        TABLE,
        sa.Column('finding_id', sa.String(36), sa.ForeignKey('findings.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('device_ref', sa.String(37), nullable=False),
        sa.Column('attributed_by', sa.String(32), nullable=False))
    op.create_index(INDEX, TABLE, ['device_ref'])


def downgrade():
    op.drop_index(INDEX, table_name=TABLE)
    op.drop_table(TABLE)
