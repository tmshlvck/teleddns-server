FROM python:3.12-slim
VOLUME /data

ARG POETRY_NO_INTERACTION=1
ARG POETRY_VIRTUALENVS_IN_PROJECT=1
ARG POETRY_VIRTUALENVS_CREATE=1
ARG POETRY_CACHE_DIR=/tmp/poetry_cache

ENV LOG_LEVEL="INFO"
ENV DB_URL="sqlite:////data/teleddns.sqlite"
ENV LISTEN_PORT=8085
ENV ROOT_PATH=""

WORKDIR /app

RUN apt-get update && apt-get install -y python3-poetry

COPY pyproject.toml poetry.lock* README.md alembic.ini ./
COPY alembic/ ./alembic/
COPY src/ ./src/

RUN poetry lock && poetry install --only=main && rm -rf $POETRY_CACHE_DIR

EXPOSE $LISTEN_PORT
CMD ["bash", "-c", "DISABLE_CLI_PARSING=1 poetry run alembic upgrade head; poetry run teleddns_server"]
