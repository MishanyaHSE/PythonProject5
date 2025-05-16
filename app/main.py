import io
import os

from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy import extract, and_, func, column
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import StreamingResponse

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import logging
import secrets
import smtplib
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import csv
import pandas as pd
import numpy as np

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from app.models import User, Note, UserQuestions, RefreshToken, UserVerification
from app.database import get_db, Base, engine
from app.schemas import UserCreate, UserResponse, Token, TokenData, UserAuth, NoteCreate, NoteResponse, QuestionsResponse, \
    QuestionsData, ReportCreate, StatisticsCreate, PasswordReset

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_MINUTES = 30 * 6000
SMTP_CONFIG = {
    "host": os.getenv("SMTP_HOST", "smtp.gmail.com"),
    "port": int(os.getenv("SMTP_PORT", 587)),
    "user": os.getenv("SMTP_USER", "your-email@gmail.com"),
    "password": os.getenv("SMTP_PASSWORD", "your-app-password")
}

pwd_context = CryptContext(schemes=["bcrypt"], default="bcrypt")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=origins,
    allow_headers=origins,
)


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


# Эндпоинт для создания пользователя
@app.post("/register", response_model=UserResponse)
async def create_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    try:
        existing_user = (await db.execute(select(User).where(User.email == user.email))).scalar_one_or_none()
        if existing_user and existing_user.is_verified:
            raise HTTPException(status_code=400, detail="Email already registered")
        elif existing_user and not existing_user.is_verified:
            await db.delete(
                (await db.execute(select(UserQuestions).where(UserQuestions.user_id == existing_user.id)))
                .scalar_one_or_none())
            await db.commit()
            await db.delete((await db.execute(select(UserVerification).where(UserVerification.email == existing_user.email)))
                            .scalar_one_or_none())
            await db.commit()
            await db.delete(existing_user)
            await db.commit()

        new_user = User(
            name=user.name,
            email=str(user.email),
            password=get_password_hash(user.password),  # Хешируем пароль
            is_verified=False
        )
        db.add(new_user)
        logger.info(f"Added new user")
        await db.commit()
        await db.refresh(new_user)
        user_verification = generate_verification_code(new_user.email)
        db.add(user_verification)
        await db.commit()
        await db.refresh(user_verification)
        send_verification_code(new_user.email, user_verification.code)
        new_user_questions = UserQuestions(user_id=new_user.id, time_question=True, duration_question=True,
                                           intensity_question=True, pain_type_question=True, area_question=True,
                                           triggers_question=True, medicine_question=True, symptoms_question=True,
                                           pressure_question=True, comment_question=True)
        db.add(new_user_questions)
        logger.info(f"Added user questions")
        await db.commit()
        await db.refresh(new_user_questions)
        return new_user
    except Exception as e:
        await db.rollback()
        logger.info(str(user))
        logger.info(str(e))
        raise HTTPException(status_code=500, detail="Error creating user")


@app.post("/register/{email}/{code}/")
async def verify_code(email: str, code: str, db: AsyncSession = Depends(get_db)):
    logger.info(f"Email: {email} ")
    is_valid = await validate_verification_code(code, email, db)
    if is_valid:
        user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
        user.is_verified = True
        await db.commit()
        await db.refresh(user)
        return {'message': 'Verification code is valid'}
    else:
        raise HTTPException(status_code=400, detail="Code is invalid or has been expired")


def send_verification_code(email, code):
    msg = EmailMessage()
    msg["Subject"] = "Код подтверждения"
    msg["From"] = SMTP_CONFIG["user"]
    msg["To"] = email
    msg.set_content(f"Ваш код подтверждения: {code}")
    try:
        with smtplib.SMTP(SMTP_CONFIG["host"], SMTP_CONFIG["port"]) as server:
            server.starttls()
            server.login(SMTP_CONFIG["user"], SMTP_CONFIG["password"])
            server.send_message(msg)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Email sending failed: {str(e)}")





async def validate_verification_code(code, email, db):
    existing_user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if existing_user is None:
        logger.info(f"User not found")
        return False
    user_verification = (
        await db.execute(select(UserVerification).where(UserVerification.email == email))).scalar_one_or_none()
    if user_verification is None:
        logger.info(f"Verification code not found")
        return False
    if user_verification.code != code:
        logger.info(f"Email verification code mismatch")
        if user_verification.attempts == 2:
            await db.delete(user_verification)
            await db.delete(existing_user)
        user_verification.attempts += 1
        return False
    else:
        if user_verification.created_at > datetime.now() + timedelta(minutes=15):
            logger.info(f"Email verification code expired")
            await db.delete(user_verification)
            return False
        else:
            return True


def generate_verification_code(email):
    code = str(secrets.randbelow(999999)).zfill(6)
    date = datetime.now()
    user_reg = UserVerification(email=email, code=code, created_at=date)
    return user_reg


# Эндпоинт для получения токена
@app.post("/login", response_model=Token)
async def login_for_access_token(form_data: UserAuth, db: AsyncSession = Depends(get_db)):
    user = (await db.execute(select(User).where(User.email == form_data.username))).scalar_one_or_none()
    if not user or not verify_password(form_data.password, user.password) or not user.is_verified:
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_delta = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    access_token, refresh_token = await create_access_token(user.id, data={"sub": user.email},
                                                            expires_delta=access_token_expires,
                                                            refresh_delta=refresh_token_delta)
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    db_token = RefreshToken(
        token=refresh_token,
        user_id=user.id,
        expires_at=datetime.utcnow() + refresh_token_delta,
        revoked=False
    )
    db.add(db_token)
    await db.commit()
    await db.refresh(db_token)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@app.post("/login/refresh", response_model=Token)
async def refresh_token(refreshtoken: str = Depends(oauth2_scheme), user: User = Depends(get_current_user),
                        db: AsyncSession = Depends(get_db)):
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_delta = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    if is_valid_refresh_token(refreshtoken):
        new_token, refresh_token = await create_access_token(user.id, data={"sub": user.email},
                                                             expires_delta=access_token_expires,
                                                             refresh_delta=refresh_token_delta)
        db_token = RefreshToken(
            token=refresh_token,
            user_id=user.id,
            expires_at=datetime.utcnow() + access_token_expires,
            revoked=False
        )
        db.add(db_token)
        await db.commit()
        await db.refresh(db_token)
        return {"access_token": new_token, "refresh_token": refresh_token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=401, detail="Could not validate credentials")


async def is_valid_refresh_token(token, db: AsyncSession = Depends(get_db)):
    query = (
        select(RefreshToken)
        .where(
            RefreshToken.token == token
        )
    )
    db_token = await db.execute(query).scalar_one_or_none()
    if not db_token:
        return False
    if db_token.revoked:
        return False
    if datetime.utcnow() > db_token.expires_at:
        return False
    return True


# Функция для создания JWT
async def create_access_token(user_id: int, data: dict, expires_delta: timedelta | None = None,
                              refresh_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    refresh = datetime.utcnow() + refresh_delta
    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    to_encode.update({'exp': refresh})
    refresh_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt, refresh_jwt


# Эндпоинт для получения текущего пользователя по JWT.
@app.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


@app.get("/users/notes/{date}/", response_model=list[NoteResponse])
async def read_users_notes(date: datetime, current_user: User = Depends(get_current_user),
                           db: AsyncSession = Depends(get_db)):
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


@app.get("/users/notes/one/{date}/", response_model=NoteCreate)
async def get_one_note(date: datetime, current_user: User = Depends(get_current_user),
                       db: AsyncSession = Depends(get_db)):
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
    if result.scalars().first():
        return result.scalars().one_or_none()
    else:
        raise HTTPException(status_code=404, detail="Note not found")


@app.post("/users/notes", response_model=NoteResponse)
async def write_users_notes(note: NoteCreate, current_user: User = Depends(get_current_user),
                            db: AsyncSession = Depends(get_db)):

    db_note = Note(user_id=current_user.id, **note.model_dump())
    db.add(db_note)
    await db.commit()
    await db.refresh(db_note)
    return db_note


@app.post("/users/forgot-password/{email}")
async def forgot_password(email: str, db: AsyncSession = Depends(get_db)):
    try:
        logger.info(email)
        existing_user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
        logger.info('HERE')
        if existing_user and existing_user.is_verified:
            existing_code = (await db.execute(select(UserVerification).where(UserVerification.email == email))).scalar_one_or_none()
            logger.info('HERE2')

            await db.delete(existing_code)
            await db.commit()
            user_verification = generate_verification_code(email)
            db.add(user_verification)
            await db.commit()
            await db.refresh(user_verification)
            send_verification_code(email, user_verification.code)
            return

        elif existing_user and not existing_user.is_verified or not existing_user:
            logger.info('HERE3')
            raise HTTPException(status_code=400, detail="Email not registered")
    except:
        raise HTTPException(status_code=400, detail="Email not registered")


@app.patch("/users/reset-password")
async def reset_password(reset_data: PasswordReset, db: AsyncSession = Depends(get_db)):
    if validate_verification_code(reset_data.code, reset_data.email, db):
        user = (await db.execute(select(User).where(User.email == reset_data.email))).scalar_one_or_none()
        user.password = get_password_hash(reset_data.password)
        await db.commit()
        await db.refresh(user)
    else:
        raise HTTPException(status_code=404, detail="Code not found or has expired")


@app.get("/users/{user_id}/", response_model=UserResponse)
async def read_user(user_id: int, db: AsyncSession = Depends(get_db)):
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.delete("/users/notes/one/{date}/")
async def delete_note_by_date(date: datetime, current_user: User = Depends(get_current_user),
                              db: AsyncSession = Depends(get_db)):
    note = await db.execute(
        select(Note)
        .where(
            and_(
                Note.user_id == current_user.id,
                extract('day', Note.date) == date.day,
                extract('month', Note.date) == date.month,
                extract('year', Note.date) == date.year
            )
        )
    )
    note = note.scalar_one_or_none()

    if not note:
        raise HTTPException(
            status_code=404,
            detail="Note not found for this date"
        )
    await db.delete(note)
    await db.commit()

    return {"message": "Note successfully deleted"}


# Эндпоинты для получения и изменения списков вопросов
@app.get("/users/questions", response_model=QuestionsResponse)
async def read_users_questions(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    questions = (
        await db.execute(select(UserQuestions).where(UserQuestions.user_id == current_user.id))).scalar_one_or_none()
    return questions


@app.put("/users/questions", response_model=QuestionsResponse)
async def update_questions(questions_data: QuestionsData, current_user: User = Depends(get_current_user),
                           db: AsyncSession = Depends(get_db)):
    questions = (
        await db.execute(select(UserQuestions).where(UserQuestions.user_id == current_user.id))).scalar_one_or_none()
    questions.time_question = questions_data.time_question
    questions.duration_question = questions_data.duration_question
    questions.intensity_question = questions_data.intensity_question
    questions.pain_type_question = questions_data.pain_type_question
    questions.area_question = questions_data.area_question
    questions.triggers_question = questions_data.triggers_question
    questions.medicine_question = questions_data.medicine_question
    questions.symptoms_question = questions_data.symptoms_question
    questions.pressure_question = questions_data.pressure_question
    questions.comment_question = questions_data.comment_question
    await db.commit()
    await db.refresh(questions)
    return questions

def send_report_to_email(recipient, pdf_buffer, format):
    try:
        msg = MIMEMultipart()
        msg['Subject'] = format.upper() + ' Report'
        msg['From'] = SMTP_CONFIG["user"]
        msg['To'] = recipient

        text = MIMEText("Please find attached the PDF report.")
        msg.attach(text)
        attachment = MIMEApplication(pdf_buffer.read(), _subtype=format)
        attachment.add_header('Content-Disposition', 'attachment', filename='report.' + format)
        msg.attach(attachment)

        with smtplib.SMTP(SMTP_CONFIG["host"], SMTP_CONFIG["port"]) as server:
            server.starttls()
            server.login(SMTP_CONFIG["user"], SMTP_CONFIG["password"])
            server.send_message(msg)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Email sending failed: {str(e)}")


@app.post("/users/report")
async def generate_report(report: ReportCreate, current_user: User = Depends(get_current_user),
                          db: AsyncSession = Depends(get_db)):
    query = (
        select(Note)
        .where(
            and_(
                Note.user_id == current_user.id,
                Note.date >= report.date_start,
                Note.date <= report.date_end
            )
        )
        .order_by(Note.date)
    )
    result = (await db.execute(query)).scalars().all()
    if report.format == 0:
        buffer = create_pdf(result)
        if report.send_to_mail:
            return StreamingResponse(buffer, media_type="application/pdf",
                                     headers={f"Content-Disposition": f'attachment; filename="report.pdf"'})
        else:
            send_report_to_email(current_user.email, buffer, 'pdf')
    else:
        buffer = create_csv(result)
        if report.send_to_mail:
            return StreamingResponse(buffer, media_type="text/csv",
                                     headers={f"Content-Disposition": f'attachment; filename="report.csv"'})
        else:
            send_report_to_email(current_user.email, buffer, 'csv')





def convert_to_native(df_grouped):
    # Переименовываем колонки с MultiIndex
    if isinstance(df_grouped.columns, pd.MultiIndex):
        df_grouped.columns = ['_'.join(col).strip() for col in df_grouped.columns.values]
    return df_grouped.reset_index().applymap(
        lambda x: x.item() if isinstance(x, np.generic) else x
    )


async def create_statistics(date_start, date_end, user_id, db):
    query = (
        select(Note)
        .where(
            and_(
                Note.user_id == user_id,
                Note.date >= date_start,
                Note.date <= date_end
            )
        )
        .order_by(Note.date)
    )
    notes = (await db.execute(query)).scalars().all()
    if len(notes) == 0:
        raise HTTPException(status_code=404, detail="Notes not found")
    result = {}

    data = [note.__dict__ for note in notes]
    df = pd.DataFrame(data)

    total_days = (date_end - date_start).days + 1
    # 1 пункт
    percent = round((len(notes) / total_days * 100))
    result["fill_percentage"] = percent
    # 2 пункт
    pain_days = df[df['is_headache']]
    days_with_pain = len(pain_days)
    days_without_pain = len(notes) - days_with_pain
    result["headache_days"] = {'without_pain': days_without_pain, 'with_pain': days_with_pain}
    # 3 пункт
    df['headache_hour'] = df['headache_time'].apply(lambda x: x.hour if pd.notnull(x) and pd.notnull(x.hour) else None)
    condition = [
        (df['headache_hour'].between(23, 23) | df['headache_hour'].between(0, 5)),
        df['headache_hour'].between(6, 11),
        df['headache_hour'].between(12, 17),
        df['headache_hour'].between(18, 22),
        df['headache_hour'].isna()
    ]
    choices = ['night', 'morning', 'afternoon', 'evening', 'na']
    df['time_category'] = np.select(condition, choices, 'na')
    time_stats = df[df['is_headache']].groupby('time_category').size()
    time_result = {cat: time_stats[cat] for cat in choices if cat in time_stats}
    result['time_stats'] = {
        cat: int(time_stats.get(cat, 0))
        for cat in choices if cat != 'na'
    }
    # 4 пункт
    top_durations = ((df[df['is_headache']]
                      .groupby('duration')
                      .size()
                      .sort_values(ascending=False)
                      .reset_index(name='count'))
                     .to_dict('records'))
    result['top_durations'] = top_durations
    # 5 пункт
    mean_intensity = round(df[df['is_headache']]['intensity'].mean(), 1) if not df[df['is_headache']].empty else 0
    result['mean_intensity'] = mean_intensity
    # 6 пункт
    triggers_series = (
        df[df['is_headache'] & df['triggers'].notnull() & df['triggers'].astype(str).ne('[]')].explode('triggers')[
            'triggers'].dropna().str.strip())
    top_triggers_dict = triggers_series.value_counts().head(3).reset_index(name='count').rename(
        columns={'index': 'trigger'}).to_dict()
    top_triggers = [{'name': top_triggers_dict['triggers'][i], 'count': top_triggers_dict['count'][i]} for i in
                    range(len(top_triggers_dict['count'].keys()))]
    counted_triggers = [i['name'] for i in top_triggers]
    count = 0
    for note in notes:
        if note.triggers is not None:
            for trigger in note.triggers:
                if trigger not in counted_triggers:
                    count += 1
    top_triggers.append({'name': 'Остальные', 'count': count})

    result['top_triggers'] = top_triggers
    return result


@app.post("/users/statistics")
async def get_statistics(statistics_info: StatisticsCreate, current_user: User = Depends(get_current_user),
                         db: AsyncSession = Depends(get_db)):
    return await create_statistics(statistics_info.date_start, statistics_info.date_end, current_user.id, db)


def create_csv(context):
    buffer = io.BytesIO()
    text_buffer = io.StringIO()

    writer = csv.writer(text_buffer)

    # writer.writerow(['Дата'])
    for item in context:
        text = []
        writer.writerow([item.id, item.user_id, item.date, item.medicine])

    buffer.write(text_buffer.getvalue().encode('utf-8'))
    buffer.seek(0)

    return buffer


try:
    pdfmetrics.registerFont(TTFont('DejaVuSans', 'res/DejaVuSans.ttf'))
    pdfmetrics.registerFont(TTFont('DejaVuSans-Bold', 'res/DejaVuSans-Bold.ttf'))
except:
    pdfmetrics.registerFont(TTFont('DejaVuSans', 'arial.ttf'))  # Если есть Arial
    pdfmetrics.registerFont(TTFont('DejaVuSans-Bold', 'arialbd.ttf'))


def create_pdf(content):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y_position = 750
    title_font_size = 14
    date_font_size = 12
    regular_font_size = 10
    line_height = 16

    # Регистрация шрифтов (добавьте в начало функции)
    try:
        pdfmetrics.registerFont(TTFont('DejaVuSans', 'res/DejaVuSans.ttf'))
        pdfmetrics.registerFont(TTFont('DejaVuSans-Bold', 'res/DejaVuSans-Bold.ttf'))
    except:
        pass  # Уже зарегистрированы

    # Заголовок
    if content:
        c.setFont("DejaVuSans-Bold", title_font_size)
        start_date = content[0].date.strftime('%d.%m.%Y')
        end_date = content[-1].date.strftime('%d.%m.%Y')
        header_text = f"Дневник головной боли: {start_date} - {end_date}"
        c.drawString(100, y_position, header_text)
        y_position -= line_height * 2

    for note in content:
        note_lines = prepare_note_content(note)

        # Обрабатываем дату отдельно
        if y_position < 60:
            c.showPage()
            y_position = 750

        c.setFont("DejaVuSans-Bold", date_font_size)
        c.drawString(100, y_position, note_lines[0])  # Дата
        y_position -= line_height

        # Остальные строки
        c.setFont("DejaVuSans", regular_font_size)
        for line in note_lines[1:]:
            if y_position < 40:
                c.showPage()
                y_position = 750
                c.setFont("DejaVuSans", regular_font_size)

            c.drawString(110, y_position, f"•  {line}")  # Добавили маркеры
            y_position -= line_height

        # Разделитель между записями
        y_position -= line_height // 2
        c.line(100, y_position, width - 100, y_position)
        y_position -= line_height

    c.save()
    buffer.seek(0)
    return buffer


def prepare_note_content(note):
    content = []
    content.append(f"Дата: {note.date.strftime('%d.%m.%Y')}")

    if note.is_headache:
        content.append("Головная боль: Да")

        if note.headache_time:
            content.append(f"Начало: {note.headache_time.strftime('%H:%M')}")

        if note.duration:
            content.append(f"Длительность: {note.duration}")

        if note.headache_type:
            content.append(f"Тип: {', '.join(note.headache_type)}")

        if note.area:
            content.append(f"Локализация: {', '.join(note.area)}")

        if note.intensity:
            content.append(f"Интенсивность: {note.intensity}/10")

        if note.triggers:
            content.append(f"Триггеры: {', '.join(note.triggers)}")

        if note.symptoms:
            content.append(f"Симптомы: {', '.join(note.symptoms)}")

        if note.medicine:
            meds = [f"{m.get('name', '')} ({m.get('weight', '')})"
                    for m in note.medicine if m.get('name')]
            if meds:
                content.append(f"Медикаменты: {', '.join(meds)}")

        # Данные давления
        pressure = []
        if note.pressure_morning_up or note.pressure_morning_down:
            pressure.append(f"Утро: {note.pressure_morning_up or '-'}/{note.pressure_morning_down or '-'}")
        if note.pressure_evening_up or note.pressure_evening_down:
            pressure.append(f"Вечер: {note.pressure_evening_up or '-'}/{note.pressure_evening_down or '-'}")
        if pressure:
            content.append("Артериальное давление: " + "; ".join(pressure))

        if note.comment:
            content.append(f"Примечания: {note.comment}")
    else:
        content.append("Головная боль: Нет")

    return content
