from sqlalchemy import Column, Integer, String, ForeignKey, Date, Boolean, Time
from sqlalchemy.dialects.postgresql import TIMESTAMP, JSONB

from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)


class Note(Base):
    __tablename__ = "notes"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    date = Column(Date, nullable=False)
    is_headache = Column(Boolean, nullable=False)
    headache_time = Column(Time)
    intensity = Column(Integer)
    medicine = Column(JSONB)




class UserQuestions(Base):
    __tablename__ = "user_questions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    second_question = Column(Boolean, nullable=False)
    third_question = Column(Boolean, nullable=False)
    fourth_question = Column(Boolean, nullable=False)