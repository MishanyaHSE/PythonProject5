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

class NoteResponse(BaseModel):
    id: int
    user_id: int
    date: date
    is_headache: bool
    headache_time: Optional[time] = None
    intensity: Optional[int] = None
    medicine: Optional[List[Medicine]] = None


class NoteCreate(BaseModel):
    date: date
    is_headache: bool
    headache_time: time
    intensity: int
    medicine: List[Medicine]

class UserResponse(BaseModel):
    id: int
    name: str
    email: str

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str | None = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class QuestionsResponse(BaseModel):
    id: int
    user_id: int
    second_question: bool
    third_question: bool
    fourth_question: bool


class QuestionsData(BaseModel):
    second_question: bool
    third_question: bool
    fourth_question: bool
