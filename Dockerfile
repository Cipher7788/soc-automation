FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml LICENSE ./
COPY config ./config
COPY src ./src
RUN python -m pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 socuser \
    && mkdir -p models reports \
    && chown socuser:socuser models reports

COPY rules ./rules
COPY playbooks ./playbooks
COPY data ./data

USER socuser
CMD ["soc-automation"]
