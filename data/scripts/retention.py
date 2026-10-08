import sys
from pathlib import Path
from datetime import datetime,timedelta
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'backend'))
from app.core.database import SessionLocal
from app.core.settings import settings
from app.models import ScanRequest
def delete_expired(db,days=None):
    cutoff=datetime.now()-timedelta(days=settings.retention_days if days is None else days)
    rows=db.query(ScanRequest).filter(ScanRequest.submitted_at<cutoff).all()
    for row in rows:db.delete(row)
    db.commit();return len(rows)
if __name__=='__main__':
    with SessionLocal() as db:print({'deleted':delete_expired(db)})
