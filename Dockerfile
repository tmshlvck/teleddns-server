FROM python:3.12-slim
VOLUME /data

ARG POETRY_NO_INTERACTION=1
ARG POETRY_VIRTUALENVS_IN_PROJECT=0
ARG POETRY_VIRTUALENVS_CREATE=0
ARG POETRY_CACHE_DIR=/tmp/poetry_cache

ENV LOG_LEVEL="INFO"
ENV DB_URL="sqlite:////data/teleddns.sqlite"
ENV LISTEN_PORT=8085
ENV ROOT_PATH="/"

WORKDIR /app

RUN pip install poetry

COPY pyproject.toml poetry.lock* ./
RUN poetry install --only=main && rm -rf $POETRY_CACHE_DIR

COPY src/ ./src/
COPY README.md ./

EXPOSE $LISTEN_PORT
CMD ["poetry", "run", "teleddns_server"]
