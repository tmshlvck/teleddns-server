FROM python:3.12-bookworm
VOLUME /data

ARG POETRY_NO_INTERACTION=1
ARG POETRY_VIRTUALENVS_IN_PROJECT=0
ARG POETRY_VIRTUALENVS_CREATE=0
ARG POETRY_CACHE_DIR=/tmp/poetry_cache

ENV LOG_LEVEL="DEBUG"
#ENV LOG_LEVEL="INFO"
ENV DB_URL="sqlite:////data/teleddns.sqlite"
ENV LISTEN_PORT=8085
ENV ROOT_PATH="/"

WORKDIR /app
RUN pip install poetry
COPY src/ /app
COPY pyproject.toml ./
COPY README.md ./

RUN poetry install && rm -rf $POETRY_CACHE_DIR

EXPOSE $LISTEN_PORT
CMD ["teleddns_server"]
