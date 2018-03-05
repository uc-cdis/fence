"""
Models relating to logging
"""
from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import DateTime
from sqlalchemy import text

from fence.models._base import Base


class EventLog(Base):
    __tablename__ = 'event_log'

    id = Column(Integer, primary_key=True)
    action = Column(String)
    timestamp = Column(DateTime(timezone=True), nullable=False, server_default=text('now()'))
    target = Column(String)
    target_type = Column(String)
    description = Column(String)
