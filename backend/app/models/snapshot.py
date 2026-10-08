from datetime import datetime
from sqlalchemy import DateTime, String, JSON, Boolean, Integer, func
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base

class FeedSnapshot(Base):
    __tablename__ = 'feed_snapshots'
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(50), index=True)
    version: Mapped[str] = mapped_column(String(64), unique=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    row_count: Mapped[int] = mapped_column(Integer)
    accepted: Mapped[bool] = mapped_column(Boolean, default=True)
    payload: Mapped[list] = mapped_column(JSON)
