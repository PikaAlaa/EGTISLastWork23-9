"""Database configuration. Submitted values are never logged."""
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from app.core.settings import settings, PROJECT_ROOT

(PROJECT_ROOT / 'var').mkdir(exist_ok=True)
engine = create_engine(settings.database_url, hide_parameters=True, pool_pre_ping=True,
                       connect_args={'check_same_thread': False} if settings.database_url.startswith('sqlite') else {'connect_timeout': 3})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
class Base(DeclarativeBase):
    pass
def get_db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
