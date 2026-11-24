FROM python:3.12-slim

ARG INSTALL_DISTRIBUTED=1
WORKDIR /app/dark
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DARK_MAX_PARALLEL=16

RUN groupadd --gid 10001 darkuser \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin darkuser

COPY dark/requirements.txt dark/requirements-distributed.txt /tmp/
RUN if [ "$INSTALL_DISTRIBUTED" = "1" ]; then \
      pip install --no-cache-dir -r /tmp/requirements-distributed.txt; \
    else \
      pip install --no-cache-dir -r /tmp/requirements.txt; \
    fi

COPY --chown=darkuser:darkuser . /app
USER darkuser

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')"
CMD ["python3", "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"]
