"""Hash submissions, remove raw input and old snippets, add incomplete outcomes and feed versions."""
import hashlib
from alembic import op
import sqlalchemy as sa
from app.models.snapshot import FeedSnapshot
revision='002_private_scans';down_revision='001_baseline';branch_labels=None;depends_on=None
def upgrade():
    bind=op.get_bind()
    with op.batch_alter_table('scan_requests') as batch:
        batch.add_column(sa.Column('url_hash',sa.String(64)))
        batch.add_column(sa.Column('text_hash',sa.String(64)))
        batch.add_column(sa.Column('input_type',sa.String(16),server_default='unknown',nullable=False))
    # Do not print values or preserve the old engine breakdown: it contains matched input snippets.
    rows=bind.execute(sa.text('SELECT id,url_value,text_value FROM scan_requests')).mappings()
    for row in rows:
        digest=lambda v:hashlib.sha256(v.encode()).hexdigest() if v else None
        kind='both' if row['url_value'] and row['text_value'] else 'url' if row['url_value'] else 'text'
        bind.execute(sa.text('UPDATE scan_requests SET url_hash=:u,text_hash=:t,input_type=:k WHERE id=:id'),
                     dict(u=digest(row['url_value']),t=digest(row['text_value']),k=kind,id=row['id']))
    table=sa.table('scan_results',sa.column('engine_breakdown',sa.JSON))
    bind.execute(table.update().values(engine_breakdown={'policy':'legacy-redacted','reason':'legacy_result'}))
    with op.batch_alter_table('scan_requests') as batch:
        batch.drop_column('url_value');batch.drop_column('text_value')
    with op.batch_alter_table('scan_results') as batch:
        batch.alter_column('verdict',existing_type=sa.String(10),type_=sa.String(16))
        batch.add_column(sa.Column('analysis_complete',sa.Boolean,server_default=sa.true(),nullable=False))
    FeedSnapshot.__table__.create(bind,checkfirst=True)
def downgrade():raise RuntimeError('Privacy migration is irreversible; raw submissions cannot be reconstructed.')
