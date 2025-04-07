import os

class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://user:pas123@localhost:5432/headache')
    SQLALCHEMY_TRACK_MODIFICATIONS = False