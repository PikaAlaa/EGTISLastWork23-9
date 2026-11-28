"""LAN agent devices, one-use pairing invitations and received batches (design windows-agent-lan-v1 §7.1, step 1).

Adds `devices`, `device_pairing_tokens` and `agent_batches` only; no existing table is altered. Tables are
defined explicitly here, not from live models. `devices.device_ref` holds only the server-wrapped `srv:<32 hex>`
ref; secrets are stored only as SHA-256 digests. Re-running on a database that already has the tables with the
expected columns does nothing; unexpected columns are refused. Downgrade drops the three tables.
"""
from alembic import op
import sqlalchemy as sa

revision = '010_agent_devices'; down_revision = '009_finding_devices'; branch_labels = None; depends_on = None
COLUMNS = {
    'devices': ['id', 'device_ref', 'display_label', 'token_hash', 'agent_instance_id', 'status', 'agent_version',
                'engine_versions', 'last_coverage', 'notice_version_ack', 'paired_at', 'last_seen_at', 'revoked_at',
                'revoked_reason'],
    'device_pairing_tokens': ['id', 'code_hash', 'display_label', 'created_at', 'expires_at', 'used_at',
                              'failed_attempts', 'device_id'],
    'agent_batches': ['id', 'batch_id', 'device_id', 'sent_at', 'received_at', 'agent_version', 'engine_versions',
                      'coverage', 'accepted_findings', 'duplicate_findings'],
}


def upgrade():
    inspector = sa.inspect(op.get_bind())
    existing = set(inspector.get_table_names())
    for table, columns in COLUMNS.items():
        if table in existing and not set(columns) <= {c['name'] for c in inspector.get_columns(table)}:
            raise RuntimeError(f'{table}_exists_with_unexpected_columns')
    if 'devices' not in existing:
        op.create_table(
            'devices',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('device_ref', sa.String(37), nullable=False),
            sa.Column('display_label', sa.String(64), nullable=True),
            sa.Column('token_hash', sa.String(64), nullable=True),
            sa.Column('agent_instance_id', sa.String(36), nullable=False),
            sa.Column('status', sa.String(16), nullable=False),
            sa.Column('agent_version', sa.String(64), nullable=False),
            sa.Column('engine_versions', sa.JSON, nullable=False),
            sa.Column('last_coverage', sa.JSON, nullable=False),
            sa.Column('notice_version_ack', sa.String(32), nullable=False),
            sa.Column('paired_at', sa.DateTime, nullable=False),
            sa.Column('last_seen_at', sa.DateTime, nullable=False),
            sa.Column('revoked_at', sa.DateTime, nullable=True),
            sa.Column('revoked_reason', sa.String(100), nullable=True),
            sa.UniqueConstraint('device_ref', name='uq_devices_device_ref'))
        op.create_index('ix_devices_token_hash', 'devices', ['token_hash'], unique=True)
    if 'device_pairing_tokens' not in existing:
        op.create_table(
            'device_pairing_tokens',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('code_hash', sa.String(64), nullable=False),
            sa.Column('display_label', sa.String(64), nullable=True),
            sa.Column('created_at', sa.DateTime, nullable=False),
            sa.Column('expires_at', sa.DateTime, nullable=False),
            sa.Column('used_at', sa.DateTime, nullable=True),
            sa.Column('failed_attempts', sa.Integer, nullable=False),
            sa.Column('device_id', sa.Integer, sa.ForeignKey('devices.id'), nullable=True),
            sa.UniqueConstraint('code_hash', name='uq_device_pairing_tokens_code_hash'))
    if 'agent_batches' not in existing:
        op.create_table(
            'agent_batches',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('batch_id', sa.String(36), nullable=False),
            sa.Column('device_id', sa.Integer, sa.ForeignKey('devices.id'), nullable=False),
            sa.Column('sent_at', sa.DateTime, nullable=False),
            sa.Column('received_at', sa.DateTime, nullable=False),
            sa.Column('agent_version', sa.String(64), nullable=False),
            sa.Column('engine_versions', sa.JSON, nullable=False),
            sa.Column('coverage', sa.JSON, nullable=False),
            sa.Column('accepted_findings', sa.Integer, nullable=False),
            sa.Column('duplicate_findings', sa.Integer, nullable=False),
            sa.UniqueConstraint('device_id', 'batch_id', name='uq_agent_batches_device_batch'))
        op.create_index('ix_agent_batches_received_at', 'agent_batches', ['received_at'])


def downgrade():
    op.drop_index('ix_agent_batches_received_at', table_name='agent_batches')
    op.drop_table('agent_batches')
    op.drop_table('device_pairing_tokens')
    op.drop_index('ix_devices_token_hash', table_name='devices')
    op.drop_table('devices')
