"""Findings, incidents and campaigns tables (design core-v1 §7.2).

Tables are defined explicitly here, not from live models. Downgrade loses analyst
notes, so it refuses while incident_events has rows unless
ETIS_ALLOW_DESTRUCTIVE_DOWNGRADE=1.
"""
import os

from alembic import op
import sqlalchemy as sa

revision = '005_findings_incidents'; down_revision = '004_indicators'; branch_labels = None; depends_on = None
TABLES = ['campaigns', 'incidents', 'findings', 'finding_indicators', 'finding_attack',
          'incident_indicators', 'incident_links', 'incident_events']


def _ensure_table(name, *elements, indexes=()):
    inspector = sa.inspect(op.get_bind())
    expected = {e.name for e in elements if isinstance(e, sa.Column)}
    if name in inspector.get_table_names():
        existing = {c['name'] for c in inspector.get_columns(name)}
        if not expected <= existing:
            raise RuntimeError(f'{name}_exists_with_unexpected_columns')
        return
    op.create_table(name, *elements)
    for index_name, columns in indexes:
        op.create_index(index_name, name, columns)


def upgrade():
    _ensure_table(
        'campaigns',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now(), nullable=False),
        sa.Column('status', sa.String(16), nullable=False))
    _ensure_table(
        'incidents',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('domain', sa.String(16), nullable=False),
        sa.Column('severity', sa.String(16), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('resolution', sa.String(32), nullable=True),
        sa.Column('campaign_id', sa.Integer, sa.ForeignKey('campaigns.id', ondelete='SET NULL'), nullable=True),
        sa.Column('reopened_from', sa.Integer, sa.ForeignKey('incidents.id', ondelete='SET NULL'), nullable=True),
        sa.Column('opened_at', sa.DateTime, nullable=False),
        sa.Column('last_activity_at', sa.DateTime, nullable=False),
        sa.Column('resolved_at', sa.DateTime, nullable=True),
        indexes=[('ix_incidents_status', ['status']), ('ix_incidents_last_activity_at', ['last_activity_at'])])
    _ensure_table(
        'findings',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('schema_version', sa.String(16), nullable=False),
        sa.Column('engine_name', sa.String(100), nullable=False),
        sa.Column('engine_version', sa.String(200), nullable=False),
        sa.Column('domain', sa.String(16), nullable=False),
        sa.Column('kind', sa.String(100), nullable=False),
        sa.Column('severity', sa.String(16), nullable=False),
        sa.Column('confidence', sa.String(16), nullable=False),
        sa.Column('evidence', sa.JSON, nullable=False),
        sa.Column('observed_at', sa.DateTime, nullable=False),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('source_kind', sa.String(16), nullable=False),
        sa.Column('source_ref', sa.String(200), nullable=False),
        sa.Column('scan_request_id', sa.Integer, sa.ForeignKey('scan_requests.id', ondelete='CASCADE'), nullable=True),
        sa.Column('incident_id', sa.Integer, sa.ForeignKey('incidents.id', ondelete='SET NULL'), nullable=True),
        indexes=[('ix_findings_severity', ['severity']), ('ix_findings_observed_at', ['observed_at']),
                 ('ix_findings_scan_request_id', ['scan_request_id']), ('ix_findings_incident_id', ['incident_id'])])
    _ensure_table(
        'finding_indicators',
        sa.Column('finding_id', sa.String(36), sa.ForeignKey('findings.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('indicator_id', sa.Integer, sa.ForeignKey('indicators.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('role', sa.String(100), primary_key=True))
    _ensure_table(
        'finding_attack',
        sa.Column('finding_id', sa.String(36), sa.ForeignKey('findings.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('technique_id', sa.String(16), primary_key=True),
        sa.Column('matrix', sa.String(16), primary_key=True),
        sa.Column('attack_version', sa.String(16), nullable=False),
        sa.Column('basis', sa.String(100), nullable=False))
    _ensure_table(
        'incident_indicators',
        sa.Column('incident_id', sa.Integer, sa.ForeignKey('incidents.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('indicator_id', sa.Integer, sa.ForeignKey('indicators.id', ondelete='CASCADE'), primary_key=True))
    _ensure_table(
        'incident_links',
        sa.Column('incident_id', sa.Integer, sa.ForeignKey('incidents.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('related_incident_id', sa.Integer, sa.ForeignKey('incidents.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('relation', sa.String(16), primary_key=True))
    _ensure_table(
        'incident_events',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('incident_id', sa.Integer, sa.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('actor', sa.String(64), nullable=False),
        sa.Column('from_status', sa.String(16), nullable=True),
        sa.Column('to_status', sa.String(16), nullable=True),
        sa.Column('action', sa.String(32), nullable=False),
        sa.Column('note', sa.Text, nullable=True),
        sa.Column('at', sa.DateTime, nullable=False),
        indexes=[('ix_incident_events_incident_id', ['incident_id'])])


def downgrade():
    bind = op.get_bind()
    events = bind.execute(sa.text('SELECT COUNT(*) FROM incident_events')).scalar()
    if events and os.getenv('ETIS_ALLOW_DESTRUCTIVE_DOWNGRADE') != '1':
        raise RuntimeError('incident_events_not_empty: analyst notes would be lost; '
                           'set ETIS_ALLOW_DESTRUCTIVE_DOWNGRADE=1 to proceed')
    for table in reversed(TABLES):
        op.drop_table(table)
