import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg://app:app-local-password@localhost:5432/analysis",
)
def create_engine_from_url(url: str):
    return create_engine(url, pool_pre_ping=True)


def get_engine():
    return create_engine_from_url(DATABASE_URL)
