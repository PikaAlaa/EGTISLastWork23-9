"""Independent source observations prevent one feed's expiry from deleting another's evidence."""
from datetime import date
from sqlalchemy import String,Date
from sqlalchemy.orm import Mapped,mapped_column
from app.core.database import Base

class FeedObservation(Base):
    __tablename__='feed_observations'
    url_hash: Mapped[str]=mapped_column(String(64),primary_key=True)
    source: Mapped[str]=mapped_column(String(50),primary_key=True)
    last_seen: Mapped[date]=mapped_column(Date,index=True)
