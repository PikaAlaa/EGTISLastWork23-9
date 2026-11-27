"""Baseline schema, compatible with the September repository's scan tables."""
from alembic import op
import sqlalchemy as sa
from app.core.database import Base
import app.models
revision='001_baseline';down_revision=None;branch_labels=None;depends_on=None
# Core v1 tables are created only by their own migrations (004+). Creating them here from
# live models would, on PostgreSQL, reference scan_requests before this baseline creates it.
CORE_V1_TABLES={'indicators','indicator_sightings','correlation_stoplist','findings','finding_indicators',
    'finding_attack','incidents','incident_indicators','incident_links','incident_events','campaigns','attack_techniques',
    # Core v2 (docs/design/core-v2.md section 3.2): created only by 009_finding_devices, after findings.
    'finding_devices'}
def upgrade():
    bind=op.get_bind()
    for table in Base.metadata.sorted_tables:
        if table.name not in {'scan_requests','scan_results','feed_snapshots','feed_observations'}|CORE_V1_TABLES:table.create(bind,checkfirst=True)
    existing=sa.inspect(bind).get_table_names()
    if 'scan_requests' not in existing:
        op.create_table('scan_requests',sa.Column('id',sa.Integer,primary_key=True),
            sa.Column('url_value',sa.Text),sa.Column('text_value',sa.Text),
            sa.Column('submitted_at',sa.DateTime,server_default=sa.func.now(),nullable=False))
        op.create_index('ix_scan_requests_submitted_at','scan_requests',['submitted_at'])
    if 'scan_results' not in existing:
        op.create_table('scan_results',sa.Column('id',sa.Integer,primary_key=True),
            sa.Column('scan_request_id',sa.Integer,sa.ForeignKey('scan_requests.id'),unique=True,nullable=False),
            sa.Column('rule_based_score',sa.Float,nullable=False),sa.Column('blacklist_score',sa.Float),
            sa.Column('lstm_score',sa.Float),sa.Column('final_score',sa.Float,nullable=False),
            sa.Column('verdict',sa.String(10),nullable=False),sa.Column('engine_breakdown',sa.JSON,nullable=False),
            sa.Column('computed_at',sa.DateTime,server_default=sa.func.now(),nullable=False))
def downgrade():raise RuntimeError('Baseline downgrade is unsupported; restore an operator-managed backup.')
