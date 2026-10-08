import os
os.environ['ETIS_RATE_LIMIT']='10000/minute'
os.environ['DATABASE_URL']='sqlite://'
os.environ['ETIS_API_KEY']=''
os.environ['ETIS_REQUIRED_FEEDS']=''
import pytest
from datetime import date
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.core.database import Base,get_db_session
import app.models
from app.models import BlacklistEntry
from app.core.url_utils import parse_url,url_hash

@pytest.fixture
def db():
    engine=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool,hide_parameters=True)
    Base.metadata.create_all(engine)
    session=sessionmaker(bind=engine,expire_on_commit=False)()
    for url in ['https://known-phish.example/login','https://docs.google.com/document/d/phish','https://second-phish.example/login']:
        session.add(BlacklistEntry(url=url,url_hash=url_hash(url),domain=parse_url(url).host,source='manual',first_seen=date.today(),last_seen=date.today(),reputation_score=90.0))
    session.commit()
    yield session
    session.close();engine.dispose()

@pytest.fixture
def client(db):
    from fastapi.testclient import TestClient
    from app.main import app
    app.dependency_overrides[get_db_session]=lambda:db
    with TestClient(app,raise_server_exceptions=False) as client:yield client
    app.dependency_overrides.clear()
