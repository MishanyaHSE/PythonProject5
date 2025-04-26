from calendar import month

from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy import extract, and_

from .models import User, Note, UserQuestions
from .database import get_db, Base, engine
from .schemas import UserCreate, UserResponse, Token, TokenData, UserLogin, UserAuth, NoteCreate, NoteResponse, QuestionsResponse, QuestionsData
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import logging

# Секретный ключ для JWT
SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], default="bcrypt")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)




app = FastAPI()


# Создаем таблицы при старте (в продакшене используйте Alembic)
@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


    # Функция для верификации пароля
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


# Функция для хеширования пароля
def get_password_hash(password):
    return pwd_context.hash(password)


# Эндпоинт для создания пользователя
@app.post("/register", response_model=UserResponse)
async def create_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    logger.info(str(user))
    try:
        # Проверка существующего пользователя
        existing_user = (await db.execute(select(User).where(User.email == user.email))).scalar_one_or_none()
        if existing_user:
            # Пример использования в коде
            logger.info(f"User with same password found")
            raise HTTPException(status_code=400, detail="Email already registered")

        # Создаем пользователя с ВСЕМИ полями
        new_user = User(
            name=user.name,
            email=str(user.email),
            password=get_password_hash(user.password) # Хешируем пароль
        )
        logger.info(f"User: {new_user.name}, {new_user.email}, {new_user.password}")


        db.add(new_user)
        logger.info(f"Added new user")
        await db.commit()
        await db.refresh(new_user)
        new_user_questions = UserQuestions(user_id=new_user.id, second_question=True, third_question=True,
                                           fourth_question=True)
        db.add(new_user_questions)
        logger.info(f"Added user questions")
        await db.commit()
        await db.refresh(new_user_questions)
        return new_user
    except Exception as e:
        await db.rollback()
        logger.info(str(user))
        raise HTTPException(status_code=500, detail="Error creating user")


# Эндпоинт для получения токена
@app.post("/login", response_model=Token)
async def login_for_access_token(form_data: UserAuth , db: AsyncSession = Depends(get_db)):
    user = (await db.execute(select(User).where(User.email == form_data.username))).scalar_one_or_none()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


# Функция для создания JWT
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Эндпоинт для получения текущего пользователя
async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = (await db.execute(select(User).where(User.email == token_data.email))).scalar_one_or_none()
    if user is None:
        raise credentials_exception
    return user

# Эндпоинт для получения пользователя по ID (защищенный JWT)
@app.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.get("/users/notes/{date}/", response_model=list[NoteResponse])
async def read_users_notes(date: datetime, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    query = (
        select(Note)
        .where(
            and_(
                Note.user_id == current_user.id,
                extract('month', Note.date) == date.month,
                extract('year', Note.date) == date.year
            )
        )
        .order_by(Note.date)
    )
    result = await db.execute(query)
    return result.scalars().all()

@app.get("/users/notes/one/{date}/", response_model=list[NoteResponse])
async def read_users_notes(date: datetime, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    query = (
        select(Note)
        .where(
            and_(
                Note.user_id == current_user.id,
                extract('month', Note.date) == date.month,
                extract('year', Note.date) == date.year,
                extract('day', Note.date) == date.day
            )
        )
    )
    result = await db.execute(query)
    return result.scalars().all()


@app.post("/users/notes", response_model=NoteResponse)
async def write_users_notes(note: NoteCreate, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    # db_note = Note(is_headache=note.is_headache, date=note.date, headache_time=note.headache_time,
    # intensity=note.intensity, medicine=note.medicine, user_id=current_user.id)
    db_note = Note(user_id=current_user.id, **note.model_dump())
    db.add(db_note)
    await db.commit()
    await db.refresh(db_note)
    return db_note




@app.get("/users/{user_id}/", response_model=UserResponse)
async def read_user(user_id: int, db: AsyncSession = Depends(get_db)):
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user



# Эндпоинты для получения и изменения списков вопросов

@app.get("/users/questions", response_model=QuestionsResponse)
async def read_users_questions(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    questions =  (await db.execute(select(UserQuestions).where(UserQuestions.user_id == current_user.id))).scalar_one_or_none()
    return questions


@app.put("/users/questions", response_model=QuestionsResponse)
async def update_questions(questions_data: QuestionsData, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    questions = (await db.execute(select(UserQuestions).where(UserQuestions.user_id == current_user.id))).scalar_one_or_none()
    questions.second_question = questions_data.second_question
    questions.third_question = questions_data.third_question
    questions.fourth_question = questions_data.fourth_question
    await db.commit()
    await db.refresh(questions)
    return questions
