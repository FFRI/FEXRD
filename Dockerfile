FROM python:3.8.8-slim as python-base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    \
    POETRY_VERSION=1.1.5 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_CREATE=false \
    \
    PYSETUP_PATH="/opt/pysetup"

ENV PATH="$POETRY_HOME/bin:$PATH"

FROM python-base as initial
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        curl \
        build-essential \
        git \
        cmake

RUN curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python

WORKDIR $PYSETUP_PATH

FROM initial as development-base
ENV POETRY_NO_INTERACTION=1
COPY poetry.lock pyproject.toml ./

FROM development-base as development
RUN poetry install

WORKDIR /app

FROM development-base as builder-base
RUN poetry install --no-dev

FROM python-base as production
COPY --from=builder-base /usr/local/lib/python3.8/site-packages /usr/local/lib/python3.8/site-packages
COPY ./src /app/
WORKDIR /app
