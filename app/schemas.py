from typing import Any, List, Optional
from pydantic import BaseModel, EmailStr, Json
from datetime import date, datetime, time, timedelta


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserAuth(BaseModel):
    username: EmailStr
    password: str

class Medicine(BaseModel):
    name: str
    weight: int

class PasswordReset(BaseModel):
    email: EmailStr
    password: str
    code: str


class NoteCreate(BaseModel):
    date: date
    is_headache: bool
    headache_time: Optional[time] = None
    duration: Optional[str] = None
    intensity: Optional[int] = None
    headache_type: Optional[List[str]] = None
    triggers: Optional[List[str]] = None
    area: Optional[List[str]] = None
    symptoms: Optional[List[str]] = None
    medicine: Optional[List[Medicine]] = None
    pressure_morning_up: Optional[int] = None
    pressure_morning_down: Optional[int] = None
    pressure_evening_up: Optional[int] = None
    pressure_evening_down: Optional[int] = None
    comment: Optional[str] = None


class NoteResponse(NoteCreate):
    id: int
    user_id: int

class StatisticsCreate(BaseModel):
    date_start: date
    date_end: date

class ReportCreate(StatisticsCreate):
    format: int
    send_to_mail: bool


class UserResponse(BaseModel):
    id: int
    name: str
    email: str

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenData(BaseModel):
    email: str | None = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class QuestionsData(BaseModel):
    time_question: bool
    duration_question: bool
    intensity_question: bool
    pain_type_question: bool
    area_question: bool
    triggers_question: bool
    medicine_question: bool
    symptoms_question: bool
    pressure_question: bool
    comment_question: bool

class QuestionsResponse(QuestionsData):
    id: int
    user_id: int



