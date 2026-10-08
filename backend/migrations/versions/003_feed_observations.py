"""Track source-specific observations for expiry and rollback."""
from alembic import op
import sqlalchemy as sa
from app.models.feed_observation import FeedObservation
revision='003_feed_observations';down_revision='002_private_scans';branch_labels=None;depends_on=None
def upgrade():
    bind=op.get_bind();FeedObservation.__table__.create(bind,checkfirst=True)
    # Baseline-created table is empty; existing runtime rows inherit their actual observation dates.
    bind.execute(sa.text('INSERT INTO feed_observations (url_hash,source,last_seen) '
        'SELECT b.url_hash,b.source,b.last_seen FROM blacklist_entries b WHERE NOT EXISTS '
        '(SELECT 1 FROM feed_observations f WHERE f.url_hash=b.url_hash AND f.source=b.source)'))
def downgrade():op.drop_table('feed_observations')
