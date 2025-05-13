import dataclasses

from sqlalchemy import Column, Integer, String, ForeignKey, Date, Boolean, Time, DateTime, ARRAY
from sqlalchemy.dialects.postgresql import TIMESTAMP, JSONB

from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    is_verified = Column(Boolean, nullable=False)


class UserVerification(Base):
    __tablename__ = "user_verification"

    email = Column(String, ForeignKey("users.email"), unique=True, nullable=False, primary_key=True)
    code = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False)
    attempts = Column(Integer, nullable=False, default=0)


class Note(Base):
    __tablename__ = "notes"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    date = Column(Date, nullable=False)
    is_headache = Column(Boolean, nullable=False)
    headache_time = Column(Time)
    duration = Column(String)
    headache_type = Column(ARRAY(String))
    area = Column(ARRAY(String))
    intensity = Column(Integer)
    triggers = Column(ARRAY(String))
    symptoms = Column(ARRAY(String))
    medicine = Column(JSONB)
    pressure_morning_up = Column(Integer)
    pressure_morning_down = Column(Integer)
    pressure_evening_up = Column(Integer)
    pressure_evening_down = Column(Integer)
    comment = Column(String)


class UserQuestions(Base):
    __tablename__ = "user_questions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    time_question = Column(Boolean, nullable=False)
    duration_question = Column(Boolean, nullable=False)
    intensity_question = Column(Boolean, nullable=False)
    pain_type_question = Column(Boolean, nullable=False)
    area_question = Column(Boolean, nullable=False)
    triggers_question = Column(Boolean, nullable=False)
    medicine_question = Column(Boolean, nullable=False)
    symptoms_question = Column(Boolean, nullable=False)
    pressure_question = Column(Boolean, nullable=False)
    comment_question = Column(Boolean, nullable=False)


class RefreshToken(Base):
    __tablename__ = "tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True)  # Сам токен
    token_hash = Column(String)  # Хеш токена (опционально)
    user_id = Column(Integer, index=True)  # Связь с пользователем
    expires_at = Column(DateTime)
    revoked = Column(Boolean, default=False)
