FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY surfaceaudit/ surfaceaudit/

RUN pip install --no-cache-dir .

ENV SHODAN_API_KEY=""

ENTRYPOINT ["surfaceaudit"]
