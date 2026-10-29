import os
from functools import lru_cache

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


@lru_cache(maxsize=1)
def get_engine():
    return create_engine_from_url(DATABASE_URL)


def new_session():
    from sqlalchemy.orm import Session

    return Session(get_engine(), expire_on_commit=False)
